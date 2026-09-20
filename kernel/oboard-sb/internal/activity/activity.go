// Package activity holds bounded, process-local business activity, independently
// of destination diagnostics. Snapshots are cumulative and are not a wire report.
package activity

import (
	"math"
	"net/netip"
	"sync"
)

const Capacity = 4096
const PerAccountCapacity = 32
const RetainedMinutes = 3

type Identity struct {
	UserID, InboundID, PathID int64
	Source                    netip.Prefix
}

// Bind resolves only a local network group, never a device identity. Invalid or
// non-public sources remain unavailable; trusted-forward callers must supply
// the authenticated original source rather than the relay address.
func Bind(user, inbound, path int64, source netip.Addr) Identity {
	id := Identity{UserID: user, InboundID: inbound, PathID: path}
	source = source.Unmap()
	if !source.IsValid() || source.IsPrivate() || source.IsLoopback() || source.IsUnspecified() || source.IsMulticast() || source.IsLinkLocalUnicast() {
		return id
	}
	bits := 56
	if source.Is4() {
		bits = 24
	}
	id.Source = netip.PrefixFrom(source, bits).Masked()
	return id
}

type Bucket struct {
	Identity
	MinuteUnix                 int64
	ActivityBits               uint16
	UploadBytes, DownloadBytes uint64
}

type counters struct {
	ActivityBits               uint16
	UploadBytes, DownloadBytes uint64
}

type minute struct {
	at               int64
	buckets          map[Identity]counters
	accounts         map[int64]int
	dropped, unknown uint64
	dirty            bool
}

type Snapshot struct {
	Buckets                              []Bucket
	DroppedUpdates, UnknownSourceUpdates uint64
	TimeUnaligned                        bool
	// Completeness cannot be inferred from a process-local snapshot.
}

type Collector struct {
	mu                     sync.Mutex
	enabled                bool
	latest                 int64
	slots                  [RetainedMinutes]minute
	unalignedUntil         int64
	delivery               deliveryState
	clockSince, clockUntil int64
}

func (c *Collector) SetEnabled(enabled bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.enabled = enabled
	if !enabled {
		c.delivery = deliveryState{}
		c.clockSince = 0
		c.clockUntil = 0
		c.slots = [RetainedMinutes]minute{}
		c.latest = 0
		c.unalignedUntil = 0
	}
}

func add(a, b uint64) uint64 {
	if math.MaxUint64-a < b {
		return math.MaxUint64
	}
	return a + b
}

// Record marks only the actual payload's five-second event-time slice. Byte
// counters saturate; capacity loss is explicit. Old/backward time is not moved
// into a current bucket. No connection lifetime interpolation is performed.
func (c *Collector) Record(id Identity, unix int64, upload, download uint64) {
	if id.UserID <= 0 || upload == 0 && download == 0 {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.enabled {
		return
	}
	if unix < 0 {
		c.unalignedUntil = c.latest + RetainedMinutes*60
		return
	}
	at := unix / 60 * 60

	if c.latest-at >= RetainedMinutes*60 {
		c.unalignedUntil = c.latest + RetainedMinutes*60
		return
	}
	// Concurrent payload writers may commit a previous minute after a newer
	// one. Accept retained event time without mistaking scheduling for skew.
	if at > c.latest {
		c.latest = at
	}
	s := &c.slots[(at/60)%RetainedMinutes]
	if s.buckets == nil || s.at != at {
		*s = minute{at: at, buckets: make(map[Identity]counters), accounts: make(map[int64]int)}
	}
	if c.delivery.boot != "" && at < c.delivery.next {
		s.dirty = true
	}
	if !id.Source.IsValid() {
		s.unknown = add(s.unknown, 1)
		return
	}
	b, found := s.buckets[id]
	if !found {
		if len(s.buckets) >= Capacity || s.accounts[id.UserID] >= PerAccountCapacity {
			s.dropped = add(s.dropped, 1)
			return
		}
		s.accounts[id.UserID]++
	}
	b.ActivityBits |= 1 << uint((unix-at)/5)
	b.UploadBytes = add(b.UploadBytes, upload)
	b.DownloadBytes = add(b.DownloadBytes, download)
	s.buckets[id] = b
}

// Snapshot is non-destructive. Its caller must not sum repeated snapshots.
// Nothing here asserts reliable delivery, coverage, or legal fleet metering.
func (c *Collector) Snapshot(unix int64) Snapshot {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := Snapshot{TimeUnaligned: unix < c.unalignedUntil}
	if !c.enabled {
		return out
	}
	at := unix / 60 * 60
	for i := range c.slots {
		s := &c.slots[i]
		if s.buckets == nil || s.at > at || at-s.at >= RetainedMinutes*60 {
			continue
		}
		out.DroppedUpdates = add(out.DroppedUpdates, s.dropped)
		out.UnknownSourceUpdates = add(out.UnknownSourceUpdates, s.unknown)
		for id, b := range s.buckets {
			out.Buckets = append(out.Buckets, Bucket{Identity: id, MinuteUnix: s.at, ActivityBits: b.ActivityBits, UploadBytes: b.UploadBytes, DownloadBytes: b.DownloadBytes})
		}
	}
	return out
}
