package agent

import (
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
