package activity

import (
	"net/netip"
	"runtime"
	"testing"
)

var footprintKeep []*Collector

// Heap delta measures 1000 populated collectors and amortizes runtime noise.
// It is not RSS, a per-live-account production promise, or a transfer benchmark.
func BenchmarkBoundedCollectorFootprint(b *testing.B) {
	const accounts = 1000
	footprintKeep = nil
	runtime.GC()
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	footprintKeep = make([]*Collector, accounts)
	for a := range footprintKeep {
		c := new(Collector)
		c.SetEnabled(true)
		for minute := 0; minute < RetainedMinutes; minute++ {
			for source := 0; source < PerAccountCapacity; source++ {
				id := Bind(int64(a+1), 1, 0, netip.AddrFrom4([4]byte{8, 8, byte(source), 1}))
				c.Record(id, int64(600+minute*60), 16384, 16384)
			}
		}
		footprintKeep[a] = c
	}
	runtime.GC()
	runtime.ReadMemStats(&after)
	if after.HeapAlloc >= before.HeapAlloc {
		b.ReportMetric(float64(after.HeapAlloc-before.HeapAlloc)/accounts, "heap-B/account")
	}
	b.ReportMetric(float64(PerAccountCapacity*RetainedMinutes), "source-minute-buckets/account")
	runtime.KeepAlive(footprintKeep)
	footprintKeep = nil
}
