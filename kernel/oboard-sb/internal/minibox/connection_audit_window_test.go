package minibox

import (
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	M "github.com/sagernet/sing/common/metadata"
)

type stubClock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *stubClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *stubClock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

func (c *stubClock) set(at time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = at
}

func newAuditWindowTracker(t *testing.T, clock *stubClock) (*RateLimitTracker, *runtimeState, adapter.InboundContext) {
	t.Helper()
	tracker := NewRateLimitTracker(RuntimeMetadata{RateLimits: RuntimeRateLimits{Users: map[string]RuntimeUserLimit{
		"alice": {UserID: 7, InboundID: 11, Billable: true},
	}}})
	tracker.now = clock.Now
	tracker.SetConnectionAuditEnabled(true)
	metadata := adapter.InboundContext{
		Source:      M.Socksaddr{Addr: netip.MustParseAddr("198.51.100.10"), Port: 51000},
		Destination: M.Socksaddr{Fqdn: "example.com", Port: 443},
		Network:     "tcp",
		Outbound:    "direct",
	}
	return tracker, tracker.states["user:alice"], metadata
}

// assertAuditWindowOrdering enforces the ordering Controller validates:
// collection_started_at <= started_at <= payload_first_at <= payload_last_at
// <= ended_at <= collection_ended_at.
func assertAuditWindowOrdering(t *testing.T, drain ConnectionAuditDrain) {
	t.Helper()
	parse := func(label, value string) time.Time {
		t.Helper()
		parsed, err := time.Parse(time.RFC3339Nano, value)
		if err != nil {
			t.Fatalf("%s is not a valid timestamp: %q", label, value)
		}
		return parsed
	}
	collectionStarted := parse("collection_started_at", drain.CollectionStartedAt)
	collectionEnded := parse("collection_ended_at", drain.CollectionEndedAt)
	if collectionEnded.Before(collectionStarted) {
		t.Fatalf("collection_ended_at %s is before collection_started_at %s", drain.CollectionEndedAt, drain.CollectionStartedAt)
	}
	for _, item := range drain.Items {
		started := parse("started_at", item.StartedAt)
		ended := parse("ended_at", item.EndedAt)
		if started.Before(collectionStarted) {
			t.Fatalf("started_at %s is before collection_started_at %s", item.StartedAt, drain.CollectionStartedAt)
		}
		if ended.Before(started) {
			t.Fatalf("ended_at %s is before started_at %s", item.EndedAt, item.StartedAt)
		}
		if ended.After(collectionEnded) {
			t.Fatalf("ended_at %s is after collection_ended_at %s", item.EndedAt, drain.CollectionEndedAt)
		}
		if item.PayloadFirstAt == "" && item.PayloadLastAt == "" {
			continue
		}
		payloadFirst := parse("payload_first_at", item.PayloadFirstAt)
		payloadLast := parse("payload_last_at", item.PayloadLastAt)
		if payloadFirst.Before(started) {
			t.Fatalf("payload_first_at %s is before started_at %s", item.PayloadFirstAt, item.StartedAt)
		}
		if payloadLast.Before(payloadFirst) {
			t.Fatalf("payload_last_at %s is before payload_first_at %s", item.PayloadLastAt, item.PayloadFirstAt)
		}
		if payloadLast.After(ended) {
			t.Fatalf("payload_last_at %s is after ended_at %s", item.PayloadLastAt, item.EndedAt)
		}
	}
}

// A connection that stays open across several reporting windows keeps
// recording payload after each drain reset its window. The window end must
// follow that payload; Controller rejects the whole batch otherwise.
func TestLongLivedConnectionKeepsPayloadInsideAuditWindow(t *testing.T) {
	clock := &stubClock{now: time.Date(2026, 9, 2, 10, 0, 0, 0, time.UTC)}
	tracker, state, metadata := newAuditWindowTracker(t, clock)

	handle := tracker.recordConnectionStart(state, metadata, nil, "tcp")
	if handle == "" {
		t.Fatal("audit did not record the connection")
	}
	for window := 0; window < 3; window++ {
		clock.advance(2 * time.Second)
		tracker.recordConnectionPayload(handle, 1024, 2048)
		clock.advance(time.Second)
		drain := tracker.DrainConnectionAuditSnapshot()
		if len(drain.Items) != 1 {
			t.Fatalf("window %d drained %d items, want 1", window, len(drain.Items))
		}
		assertAuditWindowOrdering(t, drain)
		if drain.Items[0].PayloadLastAt == "" {
			t.Fatalf("window %d lost the payload timestamp: %#v", window, drain.Items[0])
		}
	}
	tracker.recordConnectionEnd(handle)
	assertAuditWindowOrdering(t, tracker.DrainConnectionAuditSnapshot())
}

// Payload recorded immediately after a drain lands in the window that just
// reset, which is the exact case that produced payload_last_at > ended_at.
func TestPayloadAfterDrainAdvancesWindowEnd(t *testing.T) {
	clock := &stubClock{now: time.Date(2026, 9, 2, 10, 0, 0, 0, time.UTC)}
	tracker, state, metadata := newAuditWindowTracker(t, clock)

	handle := tracker.recordConnectionStart(state, metadata, nil, "tcp")
	clock.advance(time.Second)
	tracker.DrainConnectionAuditSnapshot()
	clock.advance(5 * time.Second)
	tracker.recordConnectionPayload(handle, 10, 20)
	drain := tracker.DrainConnectionAuditSnapshot()
	if len(drain.Items) != 1 {
		t.Fatalf("drained %d items, want 1", len(drain.Items))
	}
	assertAuditWindowOrdering(t, drain)
	if drain.Items[0].PayloadLastAt != drain.Items[0].EndedAt && drain.Items[0].EndedAt < drain.Items[0].PayloadLastAt {
		t.Fatalf("window end did not follow the payload: %#v", drain.Items[0])
	}
	tracker.recordConnectionEnd(handle)
}

// The logical clock may step slightly backwards. A drain must still emit a
// window Controller accepts instead of an inverted one.
func TestAuditWindowSurvivesBackwardClockStep(t *testing.T) {
	start := time.Date(2026, 9, 2, 10, 0, 0, 0, time.UTC)
	clock := &stubClock{now: start}
	tracker, state, metadata := newAuditWindowTracker(t, clock)

	handle := tracker.recordConnectionStart(state, metadata, nil, "tcp")
	clock.advance(3 * time.Second)
	tracker.recordConnectionPayload(handle, 64, 64)
	tracker.DrainConnectionAuditSnapshot()

	clock.advance(2 * time.Second)
	tracker.recordConnectionPayload(handle, 64, 64)
	// A time correction pulls the clock back behind the window start.
	clock.set(start.Add(time.Second))
	drain := tracker.DrainConnectionAuditSnapshot()
	assertAuditWindowOrdering(t, drain)
	tracker.recordConnectionEnd(handle)
	assertAuditWindowOrdering(t, tracker.DrainConnectionAuditSnapshot())
}
