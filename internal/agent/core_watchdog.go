package agent

import (
	"context"
	"encoding/json"
	"log"
	"os"
	"path/filepath"
	"time"
)

const (
	coreWatchdogInterval    = 5 * time.Second
	coreWatchdogStableReset = 2 * time.Minute
)

type coreWatchdogStatus struct {
	Service        string    `json:"service"`
	State          string    `json:"state"`
	RestartCount   int       `json:"restart_count"`
	Consecutive    int       `json:"consecutive_restarts"`
	LastCheckedAt  time.Time `json:"last_checked_at"`
	LastRestartAt  time.Time `json:"last_restart_at,omitempty"`
	NextAttemptAt  time.Time `json:"next_attempt_at,omitempty"`
	StableSince    time.Time `json:"stable_since,omitempty"`
	LastError      string    `json:"last_error,omitempty"`
	ConfigPath     string    `json:"config_path"`
	RecoveryAction string    `json:"recovery_action,omitempty"`
}

func coreWatchdogBackoff(consecutive int) time.Duration {
	switch {
	case consecutive <= 1:
		return 0
	case consecutive == 2:
		return 5 * time.Second
	case consecutive == 3:
		return 15 * time.Second
	case consecutive == 4:
		return 30 * time.Second
	default:
		return 2 * time.Minute
	}
}

func (r *Runner) startCoreWatchdog(ctx context.Context) {
	ticker := time.NewTicker(coreWatchdogInterval)
	defer ticker.Stop()
	status := coreWatchdogStatus{Service: r.coreService(), ConfigPath: filepath.Join(r.stateDir(), "sing-box.json")}
	r.runCoreWatchdogCheck(ctx, &status, time.Now().UTC())
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-ticker.C:
			r.runCoreWatchdogCheck(ctx, &status, now.UTC())
		}
	}
}

func (r *Runner) runCoreWatchdogCheck(ctx context.Context, status *coreWatchdogStatus, now time.Time) {
	if ctx.Err() != nil || !r.managedRestartEnabled() {
		return
	}
	status.LastCheckedAt = now
	if info, err := os.Stat(status.ConfigPath); err != nil || info.Size() == 0 {
		status.State = "waiting_for_config"
		status.LastError = ""
		r.writeCoreWatchdogStatus(*status)
		return
	}

	r.coreLifecycleMu.Lock()
	defer r.coreLifecycleMu.Unlock()
	if err := r.coreServiceActive(); err == nil {
		wasRunning := status.State == "running"
		status.State = "running"
		status.LastError = ""
		if status.StableSince.IsZero() {
			status.StableSince = now
		}
		if now.Sub(status.StableSince) >= coreWatchdogStableReset {
			status.Consecutive = 0
			status.NextAttemptAt = time.Time{}
		}
		if !wasRunning {
			_ = r.configureCoreClock(ctx)
		}
		r.writeCoreWatchdogStatus(*status)
		return
	}
	status.StableSince = time.Time{}
	if !status.NextAttemptAt.IsZero() && now.Before(status.NextAttemptAt) {
		status.State = "backoff"
		r.writeCoreWatchdogStatus(*status)
		return
	}

	status.Consecutive++
	if err := validateSingBox(r.coreBinary(), status.ConfigPath, r.commandTimeout()); err != nil {
		status.State = "invalid_config"
		status.LastError = err.Error()
		status.NextAttemptAt = now.Add(2 * time.Minute)
		log.Printf("core watchdog: refusing to restart %s with invalid config: %v", status.Service, err)
		r.writeCoreWatchdogStatus(*status)
		return
	}
	status.State = "restarting"
	status.RecoveryAction = "managed_restart"
	status.LastRestartAt = now
	status.RestartCount++
	r.writeCoreWatchdogStatus(*status)
	log.Printf("core watchdog: %s is stopped; starting automatic recovery", status.Service)
	if err := r.restartCore(); err != nil {
		status.State = "restart_failed"
		status.LastError = err.Error()
		status.NextAttemptAt = now.Add(coreWatchdogBackoff(status.Consecutive + 1))
		log.Printf("core watchdog: restart %s failed: %v", status.Service, err)
		r.writeCoreWatchdogStatus(*status)
		return
	}
	if err := r.waitCoreServiceStable(3 * time.Second); err != nil {
		status.State = "crashed_after_restart"
		status.LastError = err.Error()
		status.NextAttemptAt = now.Add(coreWatchdogBackoff(status.Consecutive + 1))
		log.Printf("core watchdog: %s did not remain running after restart: %v", status.Service, err)
		r.writeCoreWatchdogStatus(*status)
		return
	}
	status.State = "recovered"
	status.LastError = ""
	status.StableSince = time.Now().UTC()
	_ = r.configureCoreClock(ctx)
	status.NextAttemptAt = now.Add(coreWatchdogBackoff(status.Consecutive + 1))
	log.Printf("core watchdog: %s recovered successfully", status.Service)
	r.writeCoreWatchdogStatus(*status)
}

func (r *Runner) writeCoreWatchdogStatus(status coreWatchdogStatus) {
	data, err := json.MarshalIndent(status, "", "  ")
	if err != nil {
		return
	}
	_ = atomicWriteFile(filepath.Join(r.stateDir(), "core-watchdog.json"), data, 0o600)
}
