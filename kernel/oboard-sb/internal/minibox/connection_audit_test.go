package minibox

import (
	"net/netip"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	M "github.com/sagernet/sing/common/metadata"
)

func TestConnectionAuditDoesNotAllocateUntilEnabled(t *testing.T) {
	tracker := NewRateLimitTracker(RuntimeMetadata{RateLimits: RuntimeRateLimits{Users: map[string]RuntimeUserLimit{
		"alice": {UserID: 7, InboundID: 11, Billable: true},
	}}})
	state := tracker.states["user:alice"]
	metadata := adapter.InboundContext{
		Source:      M.Socksaddr{Addr: netip.MustParseAddr("198.51.100.10"), Port: 51000},
		Destination: M.Socksaddr{Fqdn: "example.com", Port: 443},
		Network:     "tcp",
		Outbound:    "direct",
	}
	if key := tracker.recordConnectionStart(state, metadata, nil, "tcp"); key != "" || tracker.auditBuckets != nil {
		t.Fatalf("disabled audit allocated state: key=%q buckets=%#v", key, tracker.auditBuckets)
	}
	tracker.SetConnectionAuditEnabled(true)
	started := time.Now()
	key := tracker.recordConnectionStart(state, metadata, nil, "tcp")
	if key == "" {
		t.Fatal("enabled audit did not record a connection")
	}
	tracker.recordConnectionEnd(key)
	items := tracker.DrainConnectionAudits()
	if len(items) != 1 || items[0].UserID != 7 || items[0].SourceIP != "198.51.100.10" || items[0].DestinationPort != 443 {
		t.Fatalf("unexpected audit drain: %#v", items)
	}
	if items[0].ClosedCount != 1 || items[0].DurationTotalMS < 0 || items[0].DurationMaxMS < 0 || time.Since(started) < 0 {
		t.Fatalf("connection duration was not retained: %#v", items[0])
	}
	tracker.SetConnectionAuditEnabled(false)
	if tracker.auditBuckets != nil || tracker.auditActiveByIdentity != nil || tracker.ConnectionAuditEnabled() {
		t.Fatalf("disabling audit retained state: enabled=%v buckets=%#v active=%#v", tracker.ConnectionAuditEnabled(), tracker.auditBuckets, tracker.auditActiveByIdentity)
	}
}

func TestConnectionAuditPeakSpansDestinationBuckets(t *testing.T) {
	tracker := NewRateLimitTracker(RuntimeMetadata{RateLimits: RuntimeRateLimits{Users: map[string]RuntimeUserLimit{
		"alice": {UserID: 7, InboundID: 11, Billable: true},
	}}})
	tracker.SetConnectionAuditEnabled(true)
	state := tracker.states["user:alice"]
	metadata := adapter.InboundContext{
		Source:      M.Socksaddr{Addr: netip.MustParseAddr("198.51.100.10"), Port: 51000},
		Destination: M.Socksaddr{Fqdn: "one.example", Port: 443},
		Network:     "tcp",
		Outbound:    "direct",
	}
	first := tracker.recordConnectionStart(state, metadata, nil, "tcp")
	metadata.Destination.Fqdn = "two.example"
	second := tracker.recordConnectionStart(state, metadata, nil, "tcp")
	if first == "" || second == "" || first == second {
		t.Fatalf("expected two audit buckets, got %q and %q", first, second)
	}
	items := tracker.DrainConnectionAudits()
	if len(items) != 2 {
		t.Fatalf("drain items = %d, want 2: %#v", len(items), items)
	}
	peak := int64(0)
	for _, item := range items {
		if item.ActivePeak > peak {
			peak = item.ActivePeak
		}
	}
	if peak != 2 {
		t.Fatalf("cross-destination active peak = %d, want 2: %#v", peak, items)
	}
	tracker.recordConnectionEnd(first)
	tracker.recordConnectionEnd(second)
}

func TestConnectionAuditPeakIsScopedToDevice(t *testing.T) {
	tracker := NewRateLimitTracker(RuntimeMetadata{RateLimits: RuntimeRateLimits{Users: map[string]RuntimeUserLimit{
		"alice-a": {UserID: 7, InboundID: 11, DeviceIDHash: "device-a", CredentialEpoch: 1, Billable: true},
		"alice-b": {UserID: 7, InboundID: 11, DeviceIDHash: "device-b", CredentialEpoch: 1, Billable: true},
	}}})
	tracker.SetConnectionAuditEnabled(true)
	metadata := adapter.InboundContext{Source: M.Socksaddr{Addr: netip.MustParseAddr("198.51.100.10"), Port: 51000}, Destination: M.Socksaddr{Fqdn: "example.com", Port: 443}, Network: "tcp"}
	first := tracker.recordConnectionStart(tracker.states["user:alice-a"], metadata, nil, "tcp")
	metadata.Source = M.Socksaddr{Addr: netip.MustParseAddr("198.51.100.11"), Port: 51001}
	second := tracker.recordConnectionStart(tracker.states["user:alice-b"], metadata, nil, "tcp")
	items := tracker.DrainConnectionAudits()
	if len(items) != 2 {
		t.Fatalf("drain items = %d, want 2: %#v", len(items), items)
	}
	for _, item := range items {
		if item.ActivePeak != 1 {
			t.Fatalf("device %s peak = %d, want 1", item.DeviceIDHash, item.ActivePeak)
		}
	}
	tracker.recordConnectionEnd(first)
	tracker.recordConnectionEnd(second)
}

func TestConnectionAuditOldCloseDoesNotAffectReenabledGeneration(t *testing.T) {
	tracker := NewRateLimitTracker(RuntimeMetadata{RateLimits: RuntimeRateLimits{Users: map[string]RuntimeUserLimit{
		"alice": {UserID: 7, InboundID: 11, Billable: true},
	}}})
	tracker.SetConnectionAuditEnabled(true)
	state := tracker.states["user:alice"]
	metadata := adapter.InboundContext{
		Source:      M.Socksaddr{Addr: netip.MustParseAddr("198.51.100.10"), Port: 51000},
		Destination: M.Socksaddr{Fqdn: "example.com", Port: 443},
		Network:     "tcp",
	}
	oldKey := tracker.recordConnectionStart(state, metadata, nil, "tcp")
	tracker.SetConnectionAuditEnabled(false)
	tracker.SetConnectionAuditEnabled(true)
	newKey := tracker.recordConnectionStart(state, metadata, nil, "tcp")
	if oldKey == newKey {
		t.Fatalf("audit key generation was reused: %q", oldKey)
	}
	tracker.recordConnectionEnd(oldKey)

	items := tracker.DrainConnectionAudits()
	if len(items) != 1 || items[0].ActiveAtEnd != 1 {
		t.Fatalf("old close affected re-enabled audit state: %#v", items)
	}
	tracker.recordConnectionEnd(newKey)
}

func TestConnectionPresenceEmitsAuthenticationPayloadCloseAndRejection(t *testing.T) {
	tracker := NewRateLimitTracker(RuntimeMetadata{RateLimits: RuntimeRateLimits{Users: map[string]RuntimeUserLimit{
		"alice": {UserID: 7, InboundID: 11, DeviceIDHash: "device-a", CredentialEpoch: 2, Billable: true},
	}}})
	tracker.SetConnectionAuditEnabled(true)
	state := tracker.states["user:alice"]
	metadata := adapter.InboundContext{
		Source:      M.Socksaddr{Addr: netip.MustParseAddr("198.51.100.10"), Port: 51000},
		Destination: M.Socksaddr{Fqdn: "example.com", Port: 443},
		Network:     "tcp",
	}
	handle := tracker.recordConnectionStart(state, metadata, nil, "tcp", true)
	tracker.recordConnectionPayload(handle, 128, 256)
	tracker.recordConnectionEnd(handle)
	rejected := tracker.recordConnectionStart(state, metadata, nil, "tcp", false)
	tracker.recordConnectionEnd(rejected)

	drain := tracker.DrainConnectionPresenceEvents()
	if len(drain.Events) != 4 || drain.DroppedCount != 0 {
		t.Fatalf("presence drain = %#v", drain)
	}
	want := []string{"first_authenticated", "first_meaningful_payload", "last_connection_closed", "credential_rejected"}
	for index, event := range drain.Events {
		if event.Event != want[index] || event.UserID != 7 || event.InboundID != 11 || event.DeviceIDHash != "device-a" || event.CredentialEpoch != 2 {
			t.Fatalf("presence event %d = %#v", index, event)
		}
		if index > 0 && event.Sequence <= drain.Events[index-1].Sequence {
			t.Fatalf("presence sequence did not increase: %#v", drain.Events)
		}
	}
	if !drain.Events[1].Meaningful || drain.Events[1].PayloadLastAt == "" || !drain.Events[2].Meaningful || drain.Events[2].ActiveConnections != 0 {
		t.Fatalf("payload or close state was lost: %#v", drain.Events)
	}
	if drain.Events[3].State != "rejected" || drain.Events[3].ActiveConnections != 0 {
		t.Fatalf("rejection state = %#v", drain.Events[3])
	}
}
