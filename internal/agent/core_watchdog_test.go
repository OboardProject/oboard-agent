package agent

import (
	"context"
	"path/filepath"
	"testing"
	"time"
)

func TestCoreWatchdogBackoff(t *testing.T) {
	tests := []struct {
		attempt int
		want    time.Duration
	}{{1, 0}, {2, 5 * time.Second}, {3, 15 * time.Second}, {4, 30 * time.Second}, {5, 2 * time.Minute}, {20, 2 * time.Minute}}
	for _, tt := range tests {
		if got := coreWatchdogBackoff(tt.attempt); got != tt.want {
			t.Fatalf("attempt %d backoff = %s, want %s", tt.attempt, got, tt.want)
		}
	}
}

func TestCoreWatchdogRefreshesServiceAfterConfigChange(t *testing.T) {
	runner := New(Config{StateDir: t.TempDir(), CoreService: "oboard-sb", ResourceProfile: "large"})
	status := coreWatchdogStatus{Service: "sing-box", ConfigPath: filepath.Join(runner.stateDir(), "sing-box.json")}
	runner.runCoreWatchdogCheck(context.Background(), &status, time.Now().UTC())
	if status.Service != "oboard-sb" || status.State != "waiting_for_config" {
		t.Fatalf("watchdog status did not follow current core service: %#v", status)
	}
}

// A kernel revived between two checks never looked stopped to the watchdog,
// yet it starts on the host clock and must be given the logical clock again.
func TestCoreWatchdogPushesClockToRespawnedKernel(t *testing.T) {
	dir := t.TempDir()
	writeCoreConfig(t, dir, coreConfigA)
	kernel := newFakeCoreKernel(t, filepath.Join(dir, "sing-box.json"), true)
	r := newRuntimeTestRunner(t, dir, kernel)
	cfg := r.Config()
	cfg.RestartCommand = "systemd-restart"
	r.storeConfig(cfg)
	r.coreServiceActiveCheck = func() error { return nil }
	status := &coreWatchdogStatus{Service: r.coreService(), ConfigPath: r.statePath(singBoxConfigFile)}

	r.runCoreWatchdogCheck(context.Background(), status, time.Now())
	if status.State != coreWatchdogStateRunning || kernel.clockPushCount() != 1 {
		t.Fatalf("first check: state=%q clock pushes=%d", status.State, kernel.clockPushCount())
	}
	r.runCoreWatchdogCheck(context.Background(), status, time.Now())
	if kernel.clockPushCount() != 1 {
		t.Fatalf("an unchanged kernel was pushed the clock again: %d", kernel.clockPushCount())
	}
	kernel.respawn(5151)
	r.runCoreWatchdogCheck(context.Background(), status, time.Now())
	if kernel.clockPushCount() != 2 {
		t.Fatalf("a respawned kernel was not given the logical clock: %d", kernel.clockPushCount())
	}
}
