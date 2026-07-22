package minibox

import (
	"net/netip"
	"testing"

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
	key := tracker.recordConnectionStart(state, metadata, nil, "tcp")
	if key == "" {
		t.Fatal("enabled audit did not record a connection")
	}
	tracker.recordConnectionEnd(key)
	items := tracker.DrainConnectionAudits()
	if len(items) != 1 || items[0].UserID != 7 || items[0].SourceIP != "198.51.100.10" || items[0].DestinationPort != 443 {
		t.Fatalf("unexpected audit drain: %#v", items)
	}
	tracker.SetConnectionAuditEnabled(false)
	if tracker.auditBuckets != nil || tracker.auditActiveByUser != nil || tracker.ConnectionAuditEnabled() {
		t.Fatalf("disabling audit retained state: enabled=%v buckets=%#v active=%#v", tracker.ConnectionAuditEnabled(), tracker.auditBuckets, tracker.auditActiveByUser)
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
