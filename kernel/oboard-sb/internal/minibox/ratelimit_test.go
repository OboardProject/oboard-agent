package minibox

import (
	"context"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/bufio"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"golang.org/x/time/rate"
)

func TestRateLimitTrackerWrapsKnownUser(t *testing.T) {
	tracker := NewRateLimitTracker(RuntimeMetadata{RateLimits: RuntimeRateLimits{Users: map[string]RuntimeUserLimit{"alice": {SpeedLimitMbps: 20}}}})
	if !tracker.Enabled() {
		t.Fatal("tracker should be enabled")
	}
	if limiter := tracker.LimiterForUser("alice"); limiter == nil || limiter.Limit() != 2_500_000 {
		t.Fatalf("unexpected limiter: %#v", limiter)
	}
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	wrapped := tracker.RoutedConnection(context.Background(), server, adapter.InboundContext{User: "alice"}, nil, nil)
	if _, ok := wrapped.(*trackedConn); !ok {
		t.Fatalf("known user should be wrapped, got %T", wrapped)
	}
	unknown := tracker.RoutedConnection(context.Background(), client, adapter.InboundContext{User: "bob"}, nil, nil)
	if _, ok := unknown.(*trackedConn); ok {
		t.Fatalf("unknown user should not be wrapped")
	}
}

func TestRuntimeLimitersAreDirectional(t *testing.T) {
	state := newRuntimeState("user:alice", "alice", "", RuntimeUserLimit{SpeedLimitMbps: 20})
	config := state.currentConfig()
	if config.readLimiter == nil || config.writeLimiter == nil {
		t.Fatal("both directional limiters should be configured")
	}
	if config.readLimiter == config.writeLimiter {
		t.Fatal("upload and download must not share a token bucket")
	}
	if config.readLimiter.Burst() < rateLimitIOChunk || config.writeLimiter.Burst() < rateLimitIOChunk {
		t.Fatal("directional limiter burst must allow one bounded I/O chunk")
	}
}

func TestRuntimePolicyMigrationPreservesUnreportedCounters(t *testing.T) {
	state := newRuntimeState("user:alice", "alice", "", RuntimeUserLimit{UserID: 7, Billable: true, PeriodKey: "old"})
	state.addTraffic(9, 4)
	state.updatePolicy(RuntimeUserLimit{UserID: 7, Billable: true, PeriodKey: "new", PreviousPeriodKey: "old"})
	item, ok := state.snapshot()
	if !ok || item.PeriodKey != "new" || item.Upload != 9 || item.Download != 4 {
		t.Fatalf("migrated snapshot = %#v ok=%v", item, ok)
	}
}

func TestRateLimitTrackerFallsBackToInbound(t *testing.T) {
	tracker := NewRateLimitTracker(RuntimeMetadata{RateLimits: RuntimeRateLimits{Inbounds: map[string]RuntimeUserLimit{"in-1": {SpeedLimitMbps: 20}}}})
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	wrapped := tracker.RoutedConnection(context.Background(), server, adapter.InboundContext{Inbound: "in-1"}, nil, nil)
	if _, ok := wrapped.(*trackedConn); !ok {
		t.Fatalf("known inbound should be wrapped, got %T", wrapped)
	}
}

func TestRateLimitTrackerCountsBillableUser(t *testing.T) {
	tracker := NewRateLimitTracker(RuntimeMetadata{RateLimits: RuntimeRateLimits{Users: map[string]RuntimeUserLimit{"alice": {UserID: 7, Billable: true, TrafficLimitBytes: 10, PeriodKey: "2026-07"}}}})
	state := tracker.stateForKey("user:alice")
	state.addTraffic(4, 5)
	items := tracker.Snapshot()
	if len(items) != 1 || items[0].UserID != 7 || items[0].Upload != 4 || items[0].Download != 5 {
		t.Fatalf("unexpected snapshot: %#v", items)
	}
	if state.denied() {
		t.Fatal("9 bytes should not exceed 10 byte quota")
	}
	state.addTraffic(1, 0)
	if !state.denied() {
		t.Fatal("10 bytes should reach quota")
	}
}

func TestUnrestrictedBillableConnectionKeepsDirectCopyEligibility(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	accepted := make(chan net.Conn, 1)
	go func() {
		conn, acceptErr := listener.Accept()
		if acceptErr == nil {
			accepted <- conn
		}
	}()
	client, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	server := <-accepted
	defer server.Close()

	tracker := NewRateLimitTracker(RuntimeMetadata{RateLimits: RuntimeRateLimits{Users: map[string]RuntimeUserLimit{
		"alice": {UserID: 7, Billable: true},
	}}})
	wrapped := tracker.RoutedConnection(context.Background(), server, adapter.InboundContext{User: "alice"}, nil, nil)
	counted, ok := wrapped.(*trackedCounterConn)
	if !ok {
		t.Fatalf("unrestricted billable connection = %T, want trackedCounterConn", wrapped)
	}
	reader, readCounters := N.UnwrapCountReader(counted, nil)
	writer, writeCounters := N.UnwrapCountWriter(counted, nil)
	if len(readCounters) != 1 || len(writeCounters) != 1 {
		t.Fatalf("counter callbacks = %d/%d, want 1/1", len(readCounters), len(writeCounters))
	}
	if !N.SyscallAvailableForRead(reader) || !N.SyscallAvailableForWrite(writer) {
		t.Fatalf("unwrapped TCP connection lost direct-copy eligibility: %T / %T", reader, writer)
	}
	readCounters[0](11)
	writeCounters[0](13)
	items := tracker.Snapshot()
	if len(items) != 1 || items[0].Upload != 11 || items[0].Download != 13 {
		t.Fatalf("unexpected direct-copy counters: %#v", items)
	}
}

func TestSpeedLimitedConnectionStaysWrapped(t *testing.T) {
	tracker := NewRateLimitTracker(RuntimeMetadata{RateLimits: RuntimeRateLimits{Users: map[string]RuntimeUserLimit{
		"alice": {UserID: 7, Billable: true, SpeedLimitMbps: 20},
	}}})
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	wrapped := tracker.RoutedConnection(context.Background(), server, adapter.InboundContext{User: "alice"}, nil, nil)
	if _, ok := wrapped.(*trackedCounterConn); ok {
		t.Fatal("speed-limited connection must not bypass the token bucket")
	}
}

func TestTrackedConnWriteHonorsCanceledRateLimitWait(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	state := newRuntimeState("user:alice", "alice", "", RuntimeUserLimit{})
	state.config.Store(&runtimeConfig{writeLimiter: rate.NewLimiter(1, 1), counters: &runtimeCounters{}})
	wrapped := &trackedConn{ExtendedConn: bufio.NewExtendedConn(client), ctx: ctx, state: state, admitted: true}
	readDone := make(chan struct{})
	go func() {
		defer close(readDone)
		_, _ = server.Read(make([]byte, 1))
	}()
	n, err := wrapped.Write([]byte("x"))
	if n != 0 || !errors.Is(err, context.Canceled) {
		t.Fatalf("write result = (%d, %v), want (0, context.Canceled)", n, err)
	}
	if err := client.Close(); err != nil {
		t.Fatal(err)
	}
	<-readDone
}

func TestUpdatePoliciesRefreshesExistingLimitersAndPreservesIdentity(t *testing.T) {
	tracker := NewRateLimitTracker(RuntimeMetadata{RateLimits: RuntimeRateLimits{
		Users: map[string]RuntimeUserLimit{
			"alice": {UserID: 7, Billable: true, SpeedLimitMbps: 10, TrafficLimitBytes: 100},
		},
		Inbounds: map[string]RuntimeUserLimit{
			"in-7": {UserID: 7, InboundID: 7, PathID: 9, Billable: true, SpeedLimitMbps: 10, TrafficLimitBytes: 100},
		},
	}})
	tracker.UpdatePolicies(map[string]RuntimeUserLimit{
		"user:7": {UserID: 7, Billable: true, SpeedLimitMbps: 20, TrafficLimitBytes: 120},
	})
	userState := tracker.stateForKey("user:alice")
	inboundState := tracker.stateForKey("inbound:in-7")
	if limiter := userState.currentLimiter(); limiter == nil || limiter.Limit() != 2_500_000 {
		t.Fatalf("user limiter = %#v, want 20 Mbps", limiter)
	}
	if limiter := inboundState.currentLimiter(); limiter == nil || limiter.Limit() != 2_500_000 {
		t.Fatalf("inbound limiter = %#v, want 20 Mbps", limiter)
	}
	updated := inboundState.loadedPolicy()
	if updated.InboundID != 7 || updated.PathID != 9 {
		t.Fatalf("inbound identity lost after update: %#v", updated)
	}

	tracker.UpdatePolicies(map[string]RuntimeUserLimit{
		"user:7": {UserID: 7, Billable: true, TrafficLimitBytes: 120},
	})
	if userState.currentLimiter() != nil || inboundState.currentLimiter() != nil {
		t.Fatal("removed speed limit should remove both runtime limiters")
	}
}

func TestPolicyUpdatePreservesCountersInSamePeriodAndResetsNextPeriod(t *testing.T) {
	tracker := NewRateLimitTracker(RuntimeMetadata{RateLimits: RuntimeRateLimits{Users: map[string]RuntimeUserLimit{
		"alice": {UserID: 7, Billable: true, PeriodKey: "2026-07", TrafficLimitBytes: 100},
	}}})
	state := tracker.stateForKey("user:alice")
	state.addTraffic(4, 5)
	tracker.UpdatePolicies(map[string]RuntimeUserLimit{
		"user:7": {UserID: 7, Billable: true, PeriodKey: "2026-07", SpeedLimitMbps: 20, TrafficLimitBytes: 200},
	})
	items := tracker.Snapshot()
	if len(items) != 1 || items[0].Upload != 4 || items[0].Download != 5 {
		t.Fatalf("same-period update lost counters: %#v", items)
	}

	tracker.UpdatePolicies(map[string]RuntimeUserLimit{
		"user:7": {UserID: 7, Billable: true, PeriodKey: "2026-08", TrafficLimitBytes: 200},
	})
	if items := tracker.Snapshot(); len(items) != 0 {
		t.Fatalf("new period should start with empty counters: %#v", items)
	}
	state.addTraffic(2, 3)
	items = tracker.Snapshot()
	if len(items) != 1 || items[0].PeriodKey != "2026-08" || items[0].Upload != 2 || items[0].Download != 3 {
		t.Fatalf("unexpected new-period snapshot: %#v", items)
	}
}

func TestAcknowledgedTrafficIsNotAddedToUpdatedBaseline(t *testing.T) {
	tracker := NewRateLimitTracker(RuntimeMetadata{RateLimits: RuntimeRateLimits{Users: map[string]RuntimeUserLimit{
		"alice": {UserID: 7, Billable: true, PeriodKey: "2026-07", TrafficLimitBytes: 12, UsedBaselineBytes: 4},
	}}})
	state := tracker.stateForKey("user:alice")
	state.addTraffic(6, 0)
	tracker.AcknowledgeTraffic(map[string]TrafficCounterAcknowledgement{
		"user:alice": {PeriodKey: "2026-07", Upload: 6},
	})
	tracker.UpdatePolicies(map[string]RuntimeUserLimit{
		"user:7": {UserID: 7, Billable: true, PeriodKey: "2026-07", TrafficLimitBytes: 12, UsedBaselineBytes: 10},
	})
	if state.denied() {
		t.Fatal("accepted local bytes were counted again on top of the Controller baseline")
	}
	state.addTraffic(0, 2)
	if !state.denied() {
		t.Fatal("new unacknowledged traffic did not consume remaining quota")
	}
}

func TestQuotaAggregatesSameUserAcrossRuntimeStates(t *testing.T) {
	policy := RuntimeUserLimit{UserID: 7, Billable: true, PeriodKey: "2026-07", TrafficLimitBytes: 10}
	tracker := NewRateLimitTracker(RuntimeMetadata{RateLimits: RuntimeRateLimits{
		Users:    map[string]RuntimeUserLimit{"alice": policy},
		Inbounds: map[string]RuntimeUserLimit{"path-alice": policy},
	}})
	userState := tracker.stateForKey("user:alice")
	pathState := tracker.stateForKey("inbound:path-alice")
	userState.addTraffic(6, 0)
	pathState.addTraffic(0, 4)
	if !userState.denied() || !pathState.denied() {
		t.Fatal("same user's quota was not aggregated across runtime states")
	}
}

func TestExpiredRuntimePolicyResetsCountersOnlyOnce(t *testing.T) {
	stale := RuntimeUserLimit{UserID: 7, Billable: true, TrafficLimitBytes: 100, PeriodEnd: time.Now().Add(-time.Hour).UTC().Format(time.RFC3339Nano)}
	tracker := NewRateLimitTracker(RuntimeMetadata{RateLimits: RuntimeRateLimits{Users: map[string]RuntimeUserLimit{"alice": stale}}})
	state := tracker.stateForKey("user:alice")
	state.addTraffic(5, 0)
	state.addTraffic(4, 0)
	items := tracker.Snapshot()
	if len(items) != 1 || items[0].Upload != 9 {
		t.Fatalf("traffic after period reset = %#v, want 9 uploaded bytes", items)
	}
}

func TestZeroOfflineLeaseKeepsActiveQuotaRelay(t *testing.T) {
	tracker := NewRateLimitTracker(RuntimeMetadata{RateLimits: RuntimeRateLimits{Users: map[string]RuntimeUserLimit{
		"alice": {UserID: 7, Billable: true, TrafficLimitBytes: 100, UsedBaselineBytes: 4, LeaseEnforced: true, QuotaState: "active", EnforcementMode: "disconnect_and_reject"},
	}}})
	state := tracker.stateForKey("user:alice")
	if state.denied() {
		t.Fatal("active quota with an empty remaining lease must not black-hole the relay")
	}
	client, server := net.Pipe()
	defer client.Close()
	wrapped := tracker.RoutedConnection(context.Background(), server, adapter.InboundContext{User: "alice"}, nil, nil)
	tracked := baseTrackedConn(wrapped)
	if tracked.closed.Load() || tracked.deny() {
		t.Fatal("matching user connection should stay open while global quota remains")
	}
	done := make(chan error, 1)
	go func() {
		buf := make([]byte, 4)
		n, err := wrapped.Read(buf)
		if err != nil {
			done <- err
			return
		}
		if n != 4 || string(buf[:n]) != "ping" {
			done <- errors.New("unexpected payload")
			return
		}
		_, err = wrapped.Write([]byte("pong"))
		done <- err
	}()
	if _, err := client.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 4)
	n, err := client.Read(buf)
	if err != nil || n != 4 || string(buf) != "pong" {
		t.Fatalf("relay copy failed n=%d err=%v payload=%q", n, err, buf)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestZeroOfflineLeaseStillHonorsGlobalQuotaAndExceededState(t *testing.T) {
	exhausted := NewRateLimitTracker(RuntimeMetadata{RateLimits: RuntimeRateLimits{Users: map[string]RuntimeUserLimit{
		"alice": {UserID: 7, Billable: true, TrafficLimitBytes: 10, UsedBaselineBytes: 10, LeaseEnforced: true, QuotaState: "active"},
	}}})
	if !exhausted.stateForKey("user:alice").denied() {
		t.Fatal("empty lease must still deny once the global quota is consumed")
	}
	marked := NewRateLimitTracker(RuntimeMetadata{RateLimits: RuntimeRateLimits{Users: map[string]RuntimeUserLimit{
		"alice": {UserID: 7, Billable: true, TrafficLimitBytes: 100, UsedBaselineBytes: 4, LeaseEnforced: true, QuotaState: "quota_exceeded", EnforcementMode: "disconnect_and_reject"},
	}}})
	if !marked.stateForKey("user:alice").denied() {
		t.Fatal("quota_exceeded must still deny even when the remaining lease is empty")
	}
	limited := NewRateLimitTracker(RuntimeMetadata{RateLimits: RuntimeRateLimits{Users: map[string]RuntimeUserLimit{
		"alice": {UserID: 7, Billable: true, TrafficLimitBytes: 100, UsedBaselineBytes: 4, LeaseBytes: 6, LeaseEnforced: true, QuotaState: "active"},
	}}})
	state := limited.stateForKey("user:alice")
	state.addTraffic(6, 0)
	if !state.denied() {
		t.Fatal("a positive remaining lease must still cap below the global quota")
	}
}

func TestExpiredPolicyRestoresAssignedResetLease(t *testing.T) {
	stale := RuntimeUserLimit{UserID: 7, Billable: true, TrafficLimitBytes: 100, LeaseBytes: 0, ResetLeaseBytes: 25, LeaseEnforced: true, PeriodEnd: time.Now().Add(-time.Hour).UTC().Format(time.RFC3339Nano)}
	tracker := NewRateLimitTracker(RuntimeMetadata{RateLimits: RuntimeRateLimits{Users: map[string]RuntimeUserLimit{"alice": stale}}})
	state := tracker.stateForKey("user:alice")
	state.addTraffic(24, 0)
	if state.denied() {
		t.Fatal("traffic below the restored reset lease should be allowed")
	}
	state.addTraffic(1, 0)
	if !state.denied() {
		t.Fatal("restored reset lease should be enforced")
	}
}

func TestQuotaPolicyDisconnectsExistingConnection(t *testing.T) {
	tracker := NewRateLimitTracker(RuntimeMetadata{RateLimits: RuntimeRateLimits{Users: map[string]RuntimeUserLimit{
		"alice": {UserID: 7, Billable: true, TrafficLimitBytes: 100},
	}}})
	client, server := net.Pipe()
	defer client.Close()
	wrapped := baseTrackedConn(tracker.RoutedConnection(context.Background(), server, adapter.InboundContext{User: "alice"}, nil, nil))
	tracker.UpdatePolicies(map[string]RuntimeUserLimit{
		"user:7": {UserID: 7, Billable: true, TrafficLimitBytes: 100, QuotaState: "quota_exceeded", EnforcementMode: "disconnect"},
	})
	if !wrapped.closed.Load() {
		t.Fatal("disconnect policy should close an existing connection")
	}
}

func TestRejectNewPolicyKeepsExistingConnectionAndRejectsNewOne(t *testing.T) {
	tracker := NewRateLimitTracker(RuntimeMetadata{RateLimits: RuntimeRateLimits{Users: map[string]RuntimeUserLimit{
		"alice": {UserID: 7, Billable: true, TrafficLimitBytes: 100},
	}}})
	client, server := net.Pipe()
	defer client.Close()
	existing := baseTrackedConn(tracker.RoutedConnection(context.Background(), server, adapter.InboundContext{User: "alice"}, nil, nil))
	tracker.UpdatePolicies(map[string]RuntimeUserLimit{
		"user:7": {UserID: 7, Billable: true, TrafficLimitBytes: 100, QuotaState: "quota_exceeded", EnforcementMode: "reject_new"},
	})
	if existing.closed.Load() || existing.deny() {
		t.Fatal("reject_new should preserve an already admitted connection")
	}

	newClient, newServer := net.Pipe()
	defer newClient.Close()
	newConnection := baseTrackedConn(tracker.RoutedConnection(context.Background(), newServer, adapter.InboundContext{User: "alice"}, nil, nil))
	if !newConnection.closed.Load() || !newConnection.deny() {
		t.Fatal("reject_new should close a connection created after quota exhaustion")
	}
	_ = existing.Close()
}

func baseTrackedConn(conn net.Conn) *trackedConn {
	switch typed := conn.(type) {
	case *trackedConn:
		return typed
	case *trackedCounterConn:
		return typed.trackedConn
	default:
		panic("unexpected tracked connection type")
	}
}

func TestTrackedPacketConnCountsConsumedWriteBuffer(t *testing.T) {
	tracker := NewRateLimitTracker(RuntimeMetadata{RateLimits: RuntimeRateLimits{Users: map[string]RuntimeUserLimit{
		"alice": {UserID: 7, Billable: true},
	}}})
	packet := &testPacketConn{readPayload: []byte("up"), consumeWrite: true}
	wrapped := tracker.RoutedPacketConnection(context.Background(), packet, adapter.InboundContext{User: "alice"}, nil, nil).(*trackedPacketConn)
	readBuffer := buf.NewPacket()
	defer readBuffer.Release()
	if _, err := wrapped.ReadPacket(readBuffer); err != nil {
		t.Fatal(err)
	}
	writeBuffer := buf.As([]byte("down"))
	defer writeBuffer.Release()
	if err := wrapped.WritePacket(writeBuffer, M.Socksaddr{}); err != nil {
		t.Fatal(err)
	}
	items := tracker.Snapshot()
	if len(items) != 1 || items[0].Upload != 2 || items[0].Download != 4 {
		t.Fatalf("unexpected packet counters: %#v", items)
	}
}

func TestConcurrentTrafficPolicyUpdatesAndSnapshots(t *testing.T) {
	tracker := NewRateLimitTracker(RuntimeMetadata{RateLimits: RuntimeRateLimits{Users: map[string]RuntimeUserLimit{
		"alice": {UserID: 7, Billable: true, PeriodKey: "2026-07", TrafficLimitBytes: 1 << 30},
	}}})
	state := tracker.stateForKey("user:alice")
	const workers = 8
	const iterations = 2000
	var wg sync.WaitGroup
	for range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range iterations {
				state.addTraffic(1, 1)
			}
		}()
	}
	wg.Add(2)
	go func() {
		defer wg.Done()
		for i := range iterations {
			tracker.UpdatePolicies(map[string]RuntimeUserLimit{
				"user:7": {UserID: 7, Billable: true, PeriodKey: "2026-07", SpeedLimitMbps: 10 + i%2, TrafficLimitBytes: 1 << 30},
			})
		}
	}()
	go func() {
		defer wg.Done()
		for range iterations {
			_ = tracker.Snapshot()
		}
	}()
	wg.Wait()
	items := tracker.Snapshot()
	want := int64(workers * iterations)
	if len(items) != 1 || items[0].Upload != want || items[0].Download != want {
		t.Fatalf("concurrent counters = %#v, want %d bytes in each direction", items, want)
	}
}

func BenchmarkRuntimeStateAddTraffic(b *testing.B) {
	state := newRuntimeState("user:alice", "alice", "", RuntimeUserLimit{UserID: 7, Billable: true})
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			state.addTraffic(1500, 1500)
		}
	})
}

func BenchmarkRuntimeStateQuotaCheck(b *testing.B) {
	state := newRuntimeState("user:alice", "alice", "", RuntimeUserLimit{UserID: 7, Billable: true, TrafficLimitBytes: 1 << 40})
	b.ReportAllocs()
	for b.Loop() {
		_ = state.denied()
	}
}

func BenchmarkRateLimitTrackerSnapshot(b *testing.B) {
	tracker := NewRateLimitTracker(RuntimeMetadata{RateLimits: RuntimeRateLimits{Users: map[string]RuntimeUserLimit{
		"alice": {UserID: 7, Billable: true, PeriodKey: "2026-07"},
	}}})
	tracker.stateForKey("user:alice").addTraffic(1500, 1500)
	b.ReportAllocs()
	for b.Loop() {
		_ = tracker.Snapshot()
	}
}

func BenchmarkRateLimitTrackerPolicyUpdate(b *testing.B) {
	tracker := NewRateLimitTracker(RuntimeMetadata{RateLimits: RuntimeRateLimits{Users: map[string]RuntimeUserLimit{
		"alice": {UserID: 7, Billable: true, PeriodKey: "2026-07"},
	}}})
	b.ReportAllocs()
	for b.Loop() {
		tracker.UpdatePolicies(map[string]RuntimeUserLimit{
			"user:7": {UserID: 7, Billable: true, PeriodKey: "2026-07", SpeedLimitMbps: 20},
		})
	}
}

type testPacketConn struct {
	readPayload  []byte
	consumeWrite bool
	closed       atomic.Bool
}

func (c *testPacketConn) ReadPacket(buffer *buf.Buffer) (M.Socksaddr, error) {
	_, err := buffer.Write(c.readPayload)
	return M.Socksaddr{}, err
}

func (c *testPacketConn) WritePacket(buffer *buf.Buffer, _ M.Socksaddr) error {
	if c.consumeWrite {
		buffer.Reset()
	}
	return nil
}

func (c *testPacketConn) Close() error {
	c.closed.Store(true)
	return nil
}

func (c *testPacketConn) LocalAddr() net.Addr              { return &net.UDPAddr{} }
func (c *testPacketConn) SetDeadline(time.Time) error      { return nil }
func (c *testPacketConn) SetReadDeadline(time.Time) error  { return nil }
func (c *testPacketConn) SetWriteDeadline(time.Time) error { return nil }
