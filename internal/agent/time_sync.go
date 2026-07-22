package agent

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/OboardProject/oboard-agent/internal/model"
)

type timeSyncState struct {
	LastRun   time.Time `json:"last_run"`
	LastOK    bool      `json:"last_ok"`
	LastError string    `json:"last_error"`
}

func (r *Runner) maybeRunPeriodicTimeSync(ctx context.Context) error {
	cfg := r.Config()
	interval := time.Duration(cfg.TimeSyncIntervalSeconds) * time.Second
	if interval <= 0 || strings.TrimSpace(cfg.TimeSyncCommand) == "none" {
		return nil
	}
	now := time.Now()
	r.mu.Lock()
	if !r.lastTimeSyncCheck.IsZero() && now.Sub(r.lastTimeSyncCheck) < time.Minute {
		r.mu.Unlock()
		return nil
	}
	r.lastTimeSyncCheck = now
	r.mu.Unlock()
	state := r.loadTimeSyncState()
	if !state.LastRun.IsZero() && time.Since(state.LastRun) < interval {
		return nil
	}
	_, err := r.runTimeSyncTask(ctx, model.TimeSyncPlan{Mode: "periodic", IntervalSeconds: int(interval.Seconds()), Servers: defaultTimeServers()})
	return err
}

func (r *Runner) runTimeSyncTask(ctx context.Context, plan model.TimeSyncPlan) (map[string]any, error) {
	_ = ctx
	if plan.IntervalSeconds <= 0 {
		plan.IntervalSeconds = r.Config().TimeSyncIntervalSeconds
	}
	if len(plan.Servers) == 0 {
		plan.Servers = defaultTimeServers()
	}
	state := r.loadTimeSyncState()
	result := map[string]any{"message": "time sync skipped", "mode": plan.Mode, "interval_seconds": plan.IntervalSeconds, "servers": plan.Servers}
	if plan.Mode == "first_apply" && !state.LastRun.IsZero() {
		result["skipped"] = true
		result["reason"] = "first_apply already completed on this agent"
		return result, nil
	}
	if plan.Mode == "periodic" && plan.IntervalSeconds > 0 && !state.LastRun.IsZero() && time.Since(state.LastRun) < time.Duration(plan.IntervalSeconds)*time.Second {
		result["skipped"] = true
		result["reason"] = "time sync interval has not elapsed"
		return result, nil
	}
	cmdName, args, err := r.timeSyncCommand(plan.Servers)
	if err != nil {
		state.LastRun = time.Now().UTC()
		state.LastOK = false
		state.LastError = err.Error()
		if saveErr := r.saveTimeSyncState(state); saveErr != nil {
			result["state_error"] = saveErr.Error()
		}
		return result, err
	}
	if cmdName == "none" {
		result["skipped"] = true
		result["reason"] = "time_sync_command is none"
		return result, nil
	}
	err = runCommand(r.commandTimeout(), cmdName, args...)
	state.LastRun = time.Now().UTC()
	state.LastOK = err == nil
	state.LastError = ""
	if err != nil {
		state.LastError = err.Error()
	}
	result["command"] = strings.Join(append([]string{cmdName}, args...), " ")
	result["executed_at"] = state.LastRun
	if saveErr := r.saveTimeSyncState(state); saveErr != nil {
		result["state_error"] = saveErr.Error()
		if err == nil {
			return result, saveErr
		}
	}
	if err != nil {
		result["message"] = "time sync failed"
		return result, err
	}
	result["message"] = "time sync completed"
	result["skipped"] = false
	return result, nil
}

func (r *Runner) timeSyncCommand(servers []string) (string, []string, error) {
	command := strings.TrimSpace(r.Config().TimeSyncCommand)
	switch command {
	case "", "auto":
		return autoTimeSyncCommand(servers)
	case "none":
		return "none", nil, nil
	case "chrony":
		return "chronyc", []string{"-a", "makestep"}, nil
	case "systemd-timesyncd":
		return "timedatectl", []string{"set-ntp", "true"}, nil
	default:
		return "", nil, errors.New("time_sync_command is not an allowed managed preset")
	}
}

func autoTimeSyncCommand(servers []string) (string, []string, error) {
	server := "pool.ntp.org"
	if len(servers) > 0 && strings.TrimSpace(servers[0]) != "" {
		server = strings.TrimSpace(servers[0])
	}
	switch runtime.GOOS {
	case "linux":
		if _, err := exec.LookPath("chronyc"); err == nil {
			return "chronyc", []string{"-a", "makestep"}, nil
		}
		if _, err := exec.LookPath("ntpdate"); err == nil {
			return "ntpdate", []string{"-u", server}, nil
		}
		if _, err := exec.LookPath("sntp"); err == nil {
			return "sntp", []string{"-sS", server}, nil
		}
		if _, err := exec.LookPath("timedatectl"); err == nil {
			return "timedatectl", []string{"set-ntp", "true"}, nil
		}
	case "darwin":
		if _, err := exec.LookPath("sntp"); err == nil {
			return "sntp", []string{"-sS", server}, nil
		}
	case "windows":
		return "w32tm", []string{"/resync"}, nil
	}
	return "", nil, errors.New("no supported time sync command found; set time_sync_command to an allowed preset or none")
}

func defaultTimeServers() []string {
	return []string{"pool.ntp.org", "time.cloudflare.com", "time.google.com"}
}

func (r *Runner) loadTimeSyncState() timeSyncState {
	b, err := os.ReadFile(filepath.Join(r.stateDir(), "time-sync.json"))
	if err != nil {
		return timeSyncState{}
	}
	var state timeSyncState
	_ = json.Unmarshal(b, &state)
	return state
}

func (r *Runner) saveTimeSyncState(state timeSyncState) error {
	stateDir := r.stateDir()
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		return err
	}
	b, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return err
	}
	return atomicWriteFile(filepath.Join(stateDir, "time-sync.json"), b, 0o600)
}
