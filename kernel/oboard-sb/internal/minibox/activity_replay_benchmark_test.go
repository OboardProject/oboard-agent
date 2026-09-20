package minibox

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/netip"
	"runtime"
	"sort"
	"testing"
	"time"

	"github.com/OboardProject/oboard-agent/kernel/oboard-sb/internal/activity"
	"github.com/OboardProject/oboard-agent/kernel/oboard-sb/internal/auditwire"
	"github.com/OboardProject/oboard-agent/kernel/oboard-sb/internal/authorization"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing/common/bufio"
	M "github.com/sagernet/sing/common/metadata"
)

// Local pipe exercises real tracked Write I/O and quota counters. It measures
// neither WAN/protocol handshakes nor production throughput or process RSS.
func BenchmarkActivityTrackedTransfer(b *testing.B) {
	for _, mode := range []string{"off", "light", "standard"} {
		b.Run(mode, func(b *testing.B) {
			now := time.Now().UTC()
			tracker := NewRateLimitTracker(RuntimeMetadata{Authorization: &authorization.Lease{Revision: 1, IssuedAt: now.Format(time.RFC3339Nano), Grants: map[string]string{"local-test-grant": now.Add(5 * time.Minute).Format(time.RFC3339Nano)}}, RateLimits: RuntimeRateLimits{Users: map[string]RuntimeUserLimit{"account": {UserID: 7, InboundID: 11, Billable: true, AuthorizationKey: "local-test-grant"}}}})
			tracker.SetConnectionAuditEnabled(mode != "off")
			if mode != "off" {
				tracker.SetActivityCollection(auditwire.CollectionPolicy{Mode: mode, BaseMode: mode})
			}
			state := tracker.states["user:account"]
			metadata := adapter.InboundContext{User: "account", Source: M.SocksaddrFromNetIP(netip.MustParseAddrPort("8.8.8.8:12345")), Destination: M.SocksaddrFromNetIP(netip.MustParseAddrPort("1.1.1.1:443"))}
			auditKey := tracker.recordConnectionStart(state, metadata, nil, "tcp", true)
			left, right := net.Pipe()
			done := make(chan struct{})
			go func() { defer close(done); _, _ = io.Copy(io.Discard, right) }()
			conn := &trackedConn{ExtendedConn: bufio.NewExtendedConn(left), tracker: tracker, state: state, ctx: context.Background(), admitted: true, auditKey: auditKey, activityIdentity: activity.Bind(7, 11, 0, netip.MustParseAddr("8.8.8.8"))}
			defer func() { left.Close(); right.Close(); <-done }()
			payload := make([]byte, 4096)
			latencies := make([]int64, 0, b.N)
			var before, after runtime.MemStats
			runtime.ReadMemStats(&before)
			goroutines := runtime.NumGoroutine()
			b.ReportAllocs()
			b.SetBytes(int64(len(payload)))
			b.ResetTimer()
			started := time.Now()
			for i := 0; i < b.N; i++ {
				at := time.Now()
				n, err := conn.Write(payload)
				if err != nil || n != len(payload) {
					b.Fatalf("write %d %v", n, err)
				}
				latencies = append(latencies, time.Since(at).Nanoseconds())
			}
			elapsed := time.Since(started)
			b.StopTimer()
			runtime.ReadMemStats(&after)
			sort.Slice(latencies, func(i, j int) bool { return latencies[i] < latencies[j] })
			pct := func(p int) int64 {
				if len(latencies) == 0 {
					return 0
				}
				return latencies[(len(latencies)-1)*p/100]
			}
			encoded, _ := json.Marshal(map[string]any{"mode": mode, "scope": "local net.Pipe tracked payload writes; not WAN throughput/RSS", "writes": b.N, "bytes_per_write": len(payload), "elapsed_ns": elapsed.Nanoseconds(), "p50_ns": pct(50), "p95_ns": pct(95), "p99_ns": pct(99), "allocated_bytes": after.TotalAlloc - before.TotalAlloc, "mallocs": after.Mallocs - before.Mallocs, "heap_before": before.HeapAlloc, "heap_after": after.HeapAlloc, "gc_cycles": after.NumGC - before.NumGC, "goroutines_before": goroutines, "goroutines_after": runtime.NumGoroutine()})
			b.Log("ACTIVITY_TRANSFER_JSON " + string(encoded))
		})
	}
}
