package minibox

import (
	"net/netip"
	"testing"
	"time"

	"github.com/OboardProject/oboard-agent/kernel/oboard-sb/internal/activity"
)

func TestBasicActivityPayloadHooksIgnoreDiagnosticCapacity(t *testing.T) {
	tracker := NewRateLimitTracker(RuntimeMetadata{RateLimits: RuntimeRateLimits{Users: map[string]RuntimeUserLimit{"alice": {UserID: 7, InboundID: 11, Billable: true}}}})
	now := int64(120)
	tracker.now = func() time.Time { return time.Unix(now, 0) }
	tracker.SetConnectionAuditEnabled(true)
	state := tracker.states["user:alice"]
	id := activity.Bind(7, 11, 0, netip.MustParseAddr("198.51.100.1"))
	// Empty diagnostic handles also occur when destination capacity is exhausted.
	tcp := &trackedConn{tracker: tracker, state: state, admitted: true, activityIdentity: id}
	udp := &trackedPacketConn{tracker: tracker, state: state, admitted: true, activityIdentity: id}
	if len(tracker.activity.Snapshot(now).Buckets) != 0 {
		t.Fatal("connection lifetime counted as payload")
	}
	tcp.addTraffic(100, 0)
	now = 135
	udp.addTraffic(0, 200)
	s := tracker.activity.Snapshot(now)
	if len(s.Buckets) != 1 || s.Buckets[0].ActivityBits != 9 || s.Buckets[0].UploadBytes != 100 || s.Buckets[0].DownloadBytes != 200 {
		t.Fatalf("payload hooks: %+v", s)
	}
	tracker.SetConnectionAuditEnabled(false)
	tcp.addTraffic(1, 1)
	if len(tracker.activity.Snapshot(now).Buckets) != 0 {
		t.Fatal("disabled collection")
	}
	counters := state.currentConfig().counters
	if counters.upload.Load() != 101 || counters.download.Load() != 201 {
		t.Fatal("disabling audit altered exact traffic accounting")
	}
}
