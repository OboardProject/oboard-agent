package agent

import (
	"errors"
	"testing"
	"time"
)

func TestTrafficLeaseRenewalVerdictNamesTheOutage(t *testing.T) {
	now := time.Date(2026, 9, 3, 10, 0, 0, 0, time.UTC)
	recent := now.Add(-time.Minute).Format(time.RFC3339Nano)

	if got := trafficLeaseRenewalVerdict(recent, 0, time.Time{}, now); got != "healthy" {
		t.Fatalf("verdict = %q, want healthy", got)
	}
	if got := trafficLeaseRenewalVerdict("", 0, time.Time{}, now); got != "unknown" {
		t.Fatalf("verdict = %q, want unknown", got)
	}
	if got := trafficLeaseRenewalVerdict(recent, 3, now.Add(-time.Minute), now); got != "degraded" {
		t.Fatalf("verdict = %q, want degraded", got)
	}
	if got := trafficLeaseRenewalVerdict(recent, 200, now.Add(-time.Hour), now); got != "at_risk" {
		t.Fatalf("verdict = %q, want at_risk", got)
	}
}

// A five day old last_success with no failing-since timestamp is the shape the
// state file takes after a restart during a long outage: the verdict must still
// say the leases stopped being renewed rather than fall back to "degraded".
func TestTrafficLeaseRenewalVerdictReportsAStaleCheckpoint(t *testing.T) {
	now := time.Date(2026, 9, 3, 10, 0, 0, 0, time.UTC)
	stale := now.Add(-5 * 24 * time.Hour).Format(time.RFC3339Nano)
	if got := trafficLeaseRenewalVerdict(stale, 1, time.Time{}, now); got != "stale" {
		t.Fatalf("verdict = %q, want stale", got)
	}
}

func TestNoteTrafficReportOutcomeTracksConsecutiveFailures(t *testing.T) {
	runner := &Runner{}
	runner.storeConfig(Config{})
	failure := errors.New("controller returned 403 Forbidden")

	runner.noteTrafficReportOutcome(failure)
	runner.noteTrafficReportOutcome(failure)
	runner.trafficHealthMu.Lock()
	failures := runner.trafficReportFailures
	since := runner.trafficReportFailingSince
	runner.trafficHealthMu.Unlock()
	if failures != 2 {
		t.Fatalf("failures = %d, want 2", failures)
	}
	if since.IsZero() {
		t.Fatal("failing-since was not dated")
	}

	runner.noteTrafficReportOutcome(nil)
	runner.trafficHealthMu.Lock()
	defer runner.trafficHealthMu.Unlock()
	if runner.trafficReportFailures != 0 || !runner.trafficReportFailingSince.IsZero() {
		t.Fatalf("success did not clear the streak: failures=%d since=%v", runner.trafficReportFailures, runner.trafficReportFailingSince)
	}
}

func TestTerminalTrafficRejectionCoversAuthorizationRefusals(t *testing.T) {
	// binding_removed is what a current Controller sends for a user that is no
	// longer bound to the inbound. unauthorized and forbidden are the same
	// situation from a Controller older than that split, which a rolling
	// upgrade can still put in front of this Agent. Resending any of them is
	// what stalled lease renewal for a whole server.
	for _, reason := range []string{"binding_removed", "unauthorized", "forbidden"} {
		if !terminalTrafficRejectionReason(reason) {
			t.Fatalf("%q must be terminal so the Agent stops resending it", reason)
		}
	}
	for _, reason := range []string{"checkpoint_gap", "epoch_conflict", ""} {
		if terminalTrafficRejectionReason(reason) {
			t.Fatalf("%q must stay recoverable", reason)
		}
	}
}
