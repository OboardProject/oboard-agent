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
