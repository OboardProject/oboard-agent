package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/OboardProject/oboard-agent/internal/logging"
	"github.com/OboardProject/oboard-agent/internal/model"
)

const logMaintenanceInterval = 30 * time.Second
const managedLogOutputLimit = 320 << 10

type managedLog struct {
	Service  string
	Path     string
	MaxBytes int64
	Backups  int
}

type LogFileState struct {
	Service   string `json:"service"`
	Path      string `json:"path"`
	SizeBytes int64  `json:"size_bytes"`
	MaxBytes  int64  `json:"max_size_bytes"`
	Backups   int    `json:"backups"`
	Rotated   bool   `json:"rotated"`
	Cleared   bool   `json:"cleared"`
	Error     string `json:"error,omitempty"`
}

type logFileState = LogFileState

func (r *Runner) managedLogs() []managedLog {
	cfg := r.Config()
	coreService := strings.TrimSpace(r.coreService())
	if coreService == "" {
		coreService = "oboard-sb"
	}
	agentMax, agentBackups := applyLogTotalBudget(int64(cfg.LogMaxMB)<<20, cfg.LogBackups, agentLogTotalBudgetBytes)
	coreMax, coreBackups := applyLogTotalBudget(int64(cfg.CoreLogMaxMB)<<20, cfg.CoreLogBackups, coreLogTotalBudgetBytes)
	return []managedLog{
		{Service: "agent", Path: r.serviceLogPath("oboard-agent"), MaxBytes: agentMax, Backups: agentBackups},
		{Service: "core", Path: r.serviceLogPath(coreService), MaxBytes: coreMax, Backups: coreBackups},
	}
}

func (r *Runner) serviceLogPath(service string) string {
	dir := strings.TrimSpace(r.logDir)
	if dir == "" {
		dir = "/var/log"
	}
	return filepath.Join(dir, service+".log")
}

func (r *Runner) logPolicySummary() map[string]any {
	cfg := r.Config()
	summary := map[string]any{
		"level":            logging.CurrentLevel().String(),
		"configured_level": cfg.LogLevel,
	}
	if cfg.LogLevelExpiresAt != "" {
		summary["level_expires_at"] = cfg.LogLevelExpiresAt
	}
	for _, policy := range r.managedLogs() {
		summary[policy.Service] = map[string]any{
			"max_mb":   policy.MaxBytes >> 20,
			"backups":  policy.Backups,
			"path":     policy.Path,
			"budget_b": logTotalBudgetFor(policy.Service),
		}
	}
	return summary
}

func logTotalBudgetFor(service string) int64 {
	if service == "core" {
		return coreLogTotalBudgetBytes
	}
	return agentLogTotalBudgetBytes
}

func (r *Runner) startLogMaintenance(ctx context.Context) {
	r.enforceLogLimits(false)
	r.enforceEmergencyDiskCleanup()
	go func() {
		interval := r.logMaintenanceInterval()
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		// Light statfs pressure check runs less frequently than log rotation.
		pressureTicker := time.NewTicker(60 * time.Second)
		defer pressureTicker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				// A verbose level that has outlived its deadline is retired
				// here, before the sweep, so the tightened cadence and the
				// level itself relax together.
				r.refreshLogLevel()
				// Refresh cadence from the current storage profile and level.
				// The base interval stays a local: writing the Runner field
				// here would race the configuration-update path that owns it.
				base := r.logMaintenanceEvery
				if cur := r.storageProfile(); cur != "" {
					base = logMaintenanceIntervalForProfile(cur)
				}
				if next := verboseAwareInterval(base); next != interval {
					interval = next
					ticker.Reset(interval)
				}
				r.enforceLogLimits(false)
			case <-pressureTicker.C:
				if r.storageDiskInfo().Pressure == "critical" {
					r.enforceEmergencyDiskCleanup()
				}
				// Periodic stale temp cleanup (24h TTL)
				cleanStalePrivateUpdateTemps()
				_ = r.cleanStaleCandidateFiles()
			}
		}
	}()
}

func (r *Runner) enforceLogLimits(force bool) []LogFileState {
	r.logMu.Lock()
	defer r.logMu.Unlock()
	items := make([]LogFileState, 0, 2)
	for _, policy := range r.managedLogs() {
		state := logFileState{Service: policy.Service, Path: policy.Path, MaxBytes: policy.MaxBytes, Backups: policy.Backups}
		if err := pruneLogBackups(policy.Path, policy.Backups); err != nil {
			state.Error = err.Error()
			items = append(items, state)
			continue
		}
		info, err := os.Stat(policy.Path)
		if err != nil {
			if !errors.Is(err, os.ErrNotExist) {
				state.Error = err.Error()
			}
			items = append(items, state)
			continue
		}
		state.SizeBytes = info.Size()
		if info.Size() > policy.MaxBytes || (force && info.Size() > 0) {
			if err := rotateLogFile(policy); err != nil {
				state.Error = err.Error()
			} else {
				state.Rotated = true
				state.SizeBytes = 0
				logging.Infof("log rotated service=%s path=%s max_bytes=%d backups=%d", policy.Service, policy.Path, policy.MaxBytes, policy.Backups)
			}
		}
		items = append(items, state)
	}
	return items
}

func rotateLogFile(policy managedLog) error {
	if policy.MaxBytes <= 0 {
		return errors.New("invalid maximum log size")
	}
	if policy.Backups < 0 || policy.Backups > 20 {
		return errors.New("invalid log backup count")
	}
	if err := pruneLogBackups(policy.Path, policy.Backups); err != nil {
		return err
	}
	file, err := os.OpenFile(policy.Path, os.O_RDWR, 0)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return err
	}
	if info.Size() == 0 {
		return nil
	}
	if policy.Backups > 0 {
		if err := shiftLogBackups(policy.Path, policy.Backups); err != nil {
			return err
		}
		start := int64(0)
		if info.Size() > policy.MaxBytes {
			start = info.Size() - policy.MaxBytes
		}
		if _, err := file.Seek(start, io.SeekStart); err != nil {
			return err
		}
		tmp := fmt.Sprintf("%s.1.tmp-%d", policy.Path, os.Getpid())
		// #nosec G304 -- tmp is derived from a locally configured, allowlisted log path.
		backup, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
		if err != nil {
			return err
		}
		_, copyErr := io.Copy(backup, file)
		syncErr := backup.Sync()
		closeErr := backup.Close()
		if copyErr != nil {
			_ = os.Remove(tmp)
			return copyErr
		}
		if syncErr != nil {
			_ = os.Remove(tmp)
			return syncErr
		}
		if closeErr != nil {
			_ = os.Remove(tmp)
			return closeErr
		}
		if err := os.Rename(tmp, policy.Path+".1"); err != nil {
			_ = os.Remove(tmp)
			return err
		}
	}
	if err := file.Truncate(0); err != nil {
		return err
	}
	_, err = file.Seek(0, io.SeekStart)
	return err
}

func shiftLogBackups(path string, backups int) error {
	if backups == 0 {
		return nil
	}
	if err := os.Remove(fmt.Sprintf("%s.%d", path, backups)); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	for index := backups - 1; index >= 1; index-- {
		from := fmt.Sprintf("%s.%d", path, index)
		to := fmt.Sprintf("%s.%d", path, index+1)
		if err := os.Rename(from, to); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	return nil
}

func pruneLogBackups(path string, backups int) error {
	if backups < 0 || backups > 20 {
		return errors.New("invalid log backup count")
	}
	for index := backups + 1; index <= 20; index++ {
		if err := os.Remove(fmt.Sprintf("%s.%d", path, index)); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	temps, err := filepath.Glob(path + ".*.tmp-*")
	if err != nil {
		return err
	}
	for _, temp := range temps {
		if err := os.Remove(temp); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	return nil
}

func (r *Runner) enforceLogLimitsForMaintenance() []LogFileState { return r.enforceLogLimits(false) }

func (r *Runner) manageLogs(payloadJSON string) (map[string]any, error) {
	var payload model.ManageLogsTaskPayload
	if err := json.Unmarshal([]byte(payloadJSON), &payload); err != nil {
		return map[string]any{"message": "log operation rejected"}, err
	}
	payload.Action = strings.ToLower(strings.TrimSpace(payload.Action))
	payload.Services = strings.ToLower(strings.TrimSpace(payload.Services))
	if payload.Services == "" {
		payload.Services = "all"
	}
	if payload.Action != "rotate" && payload.Action != "clear" {
		return map[string]any{"message": "log operation rejected"}, errors.New("action must be rotate or clear")
	}
	if payload.Services != "all" && payload.Services != "agent" && payload.Services != "core" {
		return map[string]any{"message": "log operation rejected"}, errors.New("services must be all, agent, or core")
	}
	r.logMu.Lock()
	defer r.logMu.Unlock()
	states := make([]LogFileState, 0, 2)
	var failures []string
	for _, policy := range r.managedLogs() {
		if payload.Services != "all" && payload.Services != policy.Service {
			continue
		}
		state := logFileState{Service: policy.Service, Path: policy.Path, MaxBytes: policy.MaxBytes, Backups: policy.Backups}
		var err error
		if payload.Action == "rotate" {
			err = rotateLogFile(policy)
			state.Rotated = err == nil
		} else {
			err = clearLogFile(policy.Path, policy.Backups)
			state.Cleared = err == nil
		}
		if err != nil {
			state.Error = err.Error()
			failures = append(failures, policy.Service+": "+err.Error())
		} else {
			logging.Infof("log %s service=%s path=%s", payload.Action, policy.Service, policy.Path)
		}
		states = append(states, state)
	}
	result := map[string]any{"message": "log operation completed", "action": payload.Action, "services": payload.Services, "files": states}
	if len(failures) > 0 {
		return result, errors.New(strings.Join(failures, "; "))
	}
	return result, nil
}

func clearLogFile(path string, _ int) error {
	// #nosec G304 -- path is selected from the Agent's local log policy, not arbitrary task input.
	file, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err == nil {
		if truncateErr := file.Truncate(0); truncateErr != nil {
			_ = file.Close()
			return truncateErr
		}
		if closeErr := file.Close(); closeErr != nil {
			return closeErr
		}
	}
	return pruneLogBackups(path, 0)
}

func readManagedLogTail(path string, backups, lines int) map[string]any {
	lines = normalizedLogLines(lines)
	item := map[string]any{"path": path, "tail_lines": lines, "backups": backups}
	if strings.TrimSpace(path) == "" {
		item["ok"] = false
		item["error"] = "empty path"
		return item
	}
	if backups < 0 {
		backups = 0
	}
	if backups > 20 {
		backups = 20
	}
	remaining := managedLogOutputLimit
	parts := make([]string, 0, backups+1)
	files := make([]map[string]any, 0, backups+1)
	truncated := false
	for index := 0; index <= backups && remaining > 0; index++ {
		candidate := path
		if index > 0 {
			candidate = fmt.Sprintf("%s.%d", path, index)
		}
		info, err := os.Stat(candidate)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				continue
			}
			item["ok"] = false
			item["error"] = err.Error()
			return item
		}
		content, fileTruncated, err := readTailContent(candidate, remaining)
		if err != nil {
			item["ok"] = false
			item["error"] = err.Error()
			return item
		}
		remaining -= len(content)
		truncated = truncated || fileTruncated
		files = append(files, map[string]any{"path": candidate, "size_bytes": info.Size()})
		content = strings.TrimRight(content, "\r\n")
		if strings.TrimSpace(content) != "" {
			parts = append([]string{content}, parts...)
		}
	}
	if len(files) == 0 {
		item["ok"] = false
		item["error"] = os.ErrNotExist.Error()
		return item
	}
	if remaining == 0 {
		truncated = true
	}
	item["ok"] = true
	item["truncated"] = truncated
	item["files"] = files
	item["content"] = scrubDiagnosticOutput(lastLines(strings.Join(parts, "\n"), lines))
	return item
}
