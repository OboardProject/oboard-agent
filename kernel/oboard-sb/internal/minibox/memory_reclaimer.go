package minibox

import (
	"context"
	"log"
	"os"
	"runtime/debug"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
)

type MemoryReclaimerSnapshot struct {
	Enabled          bool   `json:"enabled"`
	ThresholdBytes   uint64 `json:"threshold_bytes,omitempty"`
	LastCurrentBytes uint64 `json:"last_current_bytes,omitempty"`
	LastAfterBytes   uint64 `json:"last_after_bytes,omitempty"`
	ReclaimCount     uint64 `json:"reclaim_count"`
	LastReclaimedAt  string `json:"last_reclaimed_at,omitempty"`
}

type MemoryReclaimer struct {
	enabled        bool
	thresholdBytes uint64
	lastCurrent    atomic.Uint64
	lastAfter      atomic.Uint64
	reclaimCount   atomic.Uint64
	lastReclaimed  atomic.Int64
}

func StartMemoryReclaimer(ctx context.Context, tuning RuntimeTuning) *MemoryReclaimer {
	threshold := memoryReclaimThreshold(tuning)
	reclaimer := &MemoryReclaimer{enabled: threshold > 0, thresholdBytes: threshold}
	if !reclaimer.enabled {
		return reclaimer
	}
	go reclaimer.run(ctx)
	return reclaimer
}

func memoryReclaimThreshold(tuning RuntimeTuning) uint64 {
	limit := tuning.CgroupMemoryLimitBytes
	// Reclaim on cgroup-limited hosts up to 1 GiB. Thresholds are intentionally
	// high: the goal is to use available memory for throughput, and only return
	// idle Go pages when the box is genuinely near OOM (mini-sb lesson: OOM is
	// usually socket pages; FreeOSMemory cannot shrink those, but it still helps
	// when the Go heap has grown past the live set).
	if limit == 0 || limit >= 1<<30 {
		return 0
	}
	if tuning.Profile != ResourceProfileSmall && tuning.EffectiveMemoryBytes >= 1<<30 {
		return 0
	}
	percent := uint64(90)
	switch tuning.MemoryClass {
	case "micro":
		// 128 MiB class: reclaim only in the last ~15% so GO soft-limit can fill.
		percent = 85
	case "compact":
		percent = 88
	case "small":
		percent = 90
	case "standard":
		percent = 90
	default:
		return 0
	}
	return limit * percent / 100
}

func (r *MemoryReclaimer) run(ctx context.Context) {
	ticker := time.NewTicker(r.checkInterval())
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			current := currentCgroupMemory()
			r.lastCurrent.Store(current)
			if current < r.thresholdBytes || !r.reclaimReady(time.Now()) {
				continue
			}
			debug.FreeOSMemory()
			after := currentCgroupMemory()
			r.lastAfter.Store(after)
			r.reclaimCount.Add(1)
			r.lastReclaimed.Store(time.Now().UnixNano())
			log.Printf("kernel memory reclaim current=%d after=%d threshold=%d", current, after, r.thresholdBytes)
		}
	}
}

func (r *MemoryReclaimer) checkInterval() time.Duration {
	switch {
	case r.thresholdBytes > 0 && r.thresholdBytes <= 128<<20:
		return 250 * time.Millisecond
	case r.thresholdBytes <= 256<<20:
		return 500 * time.Millisecond
	default:
		return time.Second
	}
}

func (r *MemoryReclaimer) reclaimReady(now time.Time) bool {
	last := r.lastReclaimed.Load()
	return last == 0 || now.Sub(time.Unix(0, last)) >= 5*time.Second
}

func (r *MemoryReclaimer) Snapshot() MemoryReclaimerSnapshot {
	if r == nil {
		return MemoryReclaimerSnapshot{}
	}
	snapshot := MemoryReclaimerSnapshot{
		Enabled:          r.enabled,
		ThresholdBytes:   r.thresholdBytes,
		LastCurrentBytes: r.lastCurrent.Load(),
		LastAfterBytes:   r.lastAfter.Load(),
		ReclaimCount:     r.reclaimCount.Load(),
	}
	if last := r.lastReclaimed.Load(); last > 0 {
		snapshot.LastReclaimedAt = time.Unix(0, last).UTC().Format(time.RFC3339Nano)
	}
	return snapshot
}

func currentCgroupMemory() uint64 {
	for _, path := range []string{"/sys/fs/cgroup/memory.current", "/sys/fs/cgroup/memory/memory.usage_in_bytes"} {
		// #nosec G304 -- paths are fixed cgroup control files.
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		value, err := strconv.ParseUint(strings.TrimSpace(string(data)), 10, 64)
		if err == nil {
			return value
		}
	}
	return 0
}
