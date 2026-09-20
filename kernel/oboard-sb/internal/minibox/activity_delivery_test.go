package minibox

import (
	"github.com/OboardProject/oboard-agent/kernel/oboard-sb/internal/activity"
	"github.com/OboardProject/oboard-agent/kernel/oboard-sb/internal/auditwire"
	"net/netip"
	"testing"
	"time"
)

func enableTestActivityDetails(t *RateLimitTracker) {
	t.SetActivityCollection(auditwire.CollectionPolicy{Mode: "standard"})
}
func TestAccountActivityLightAndDiagnosticBoundary(t *testing.T) {
	now := time.Unix(600, 0)
	tracker := NewRateLimitTracker(RuntimeMetadata{})
	tracker.SetConnectionAuditEnabled(true)
	if tracker.auditCollection.Load().Allows(1, now) {
		t.Fatal("default collects detail")
	}
	tracker.SetActivityCollection(auditwire.CollectionPolicy{Mode: "diagnostic", DiagnosticUserIDs: []int64{1}, DiagnosticUntil: now.Add(time.Minute), Revision: 1})
	if !tracker.auditCollection.Load().Allows(1, now) || tracker.auditCollection.Load().Allows(2, now) || tracker.auditCollection.Load().Allows(1, now.Add(time.Minute)) {
		t.Fatal("diagnostic scope/expiry")
	}
	tracker.activity.Record(activity.Bind(2, 3, 0, netip.MustParseAddr("8.8.8.8")), 600, 100, 0)
	if len(tracker.activity.Snapshot(600).Buckets) != 1 {
		t.Fatal("detail policy changed basic activity")
	}
	tracker.SetConnectionAuditEnabled(false)
	if tracker.ReadActivity() != nil {
		t.Fatal("disabled report")
	}
}
