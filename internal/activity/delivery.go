package activity

import (
	"crypto/rand"
	"encoding/hex"
	"github.com/OboardProject/oboard-agent/internal/auditwire"
	"math"
	"sort"
	"time"
)

type deliveryState struct {
	boot       string
	generation int64
	sequence   uint64
	next       int64
	pending    *auditwire.Report
	started    int64
}

// Read freezes one completed minute after a one-minute lateness allowance.
// A single immutable pending report bounds memory and is never removed by reads.
func (c *Collector) Read(now time.Time, stream string) *auditwire.Report {
	c.mu.Lock()
	defer c.mu.Unlock()
	unix := now.Unix()
	if !c.enabled || unix < 120 {
		return nil
	}
	d := &c.delivery
	if d.boot == "" {
		var id [16]byte
		if _, err := rand.Read(id[:]); err != nil {
			return nil
		}
		d.boot = hex.EncodeToString(id[:])
		d.generation = now.UnixNano()
		d.next = unix/60*60 - 120
		d.started = (unix + 59) / 60 * 60
	}
	if d.pending != nil {
		return cloneReport(d.pending)
	}
	end := unix/60*60 - 120
	at := d.next
	correction := false
	for i := range c.slots {
		s := &c.slots[i]
		if s.dirty && s.at <= end && s.at < at {
			at = s.at
			correction = true
		}
	}
	if at > end {
		return nil
	}
	// An unavailable historical minute is reported explicitly, not fabricated as zero.
	d.sequence++
	r := &auditwire.Report{CollectorBootID: d.boot, CollectorStartedAt: d.generation, StreamType: stream, Sequence: d.sequence, MinuteUnix: at, ClockState: "unknown", Complete: at >= d.started, Items: []auditwire.Item{}}
	if c.clockSince > 0 && at >= c.clockSince && at+60 <= c.clockUntil {
		r.ClockState = "aligned"
	}
	if unix < c.unalignedUntil || unix/60*60 < c.latest {
		r.ClockState = "unaligned"
		r.Complete = false
	}
	if end-at >= RetainedMinutes*60 {
		r.Complete = false
		r.DroppedUpdates = 1
		d.next = end
	} else if !correction {
		d.next += 60
	}
	s := &c.slots[(at/60)%RetainedMinutes]
	if s.at == at {
		s.dirty = false
		r.DroppedUpdates = add(r.DroppedUpdates, s.dropped)
		r.UnknownSourceUpdates = s.unknown
		for id, b := range s.buckets {
			if b.UploadBytes > math.MaxInt64 {
				b.UploadBytes = math.MaxInt64
				r.DroppedUpdates = add(r.DroppedUpdates, 1)
			}
			if b.DownloadBytes > math.MaxInt64 {
				b.DownloadBytes = math.MaxInt64
				r.DroppedUpdates = add(r.DroppedUpdates, 1)
			}
			r.Items = append(r.Items, auditwire.Item{UserID: id.UserID, InboundID: id.InboundID, PathID: id.PathID, SourcePrefix: id.Source.String(), ActivityBits: b.ActivityBits, UploadBytes: b.UploadBytes, DownloadBytes: b.DownloadBytes})
		}
	}
	if r.DroppedUpdates > 0 || r.UnknownSourceUpdates > 0 {
		r.Complete = false
	}
	sort.Slice(r.Items, func(i, j int) bool {
		a, b := r.Items[i], r.Items[j]
		if a.UserID != b.UserID {
			return a.UserID < b.UserID
		}
		if a.InboundID != b.InboundID {
			return a.InboundID < b.InboundID
		}
		if a.PathID != b.PathID {
			return a.PathID < b.PathID
		}
		return a.SourcePrefix < b.SourcePrefix
	})
	d.pending = r
	return cloneReport(r)
}

// AlignClock leases only a continuously observed interval; a gap or mismatch
// invalidates cross-node alignment without modifying immutable pending reports.
func (c *Collector) AlignClock(unix int64, aligned bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !aligned {
		c.clockSince = 0
		c.clockUntil = 0
		return
	}
	if c.clockUntil < unix || c.clockSince == 0 {
		c.clockSince = unix
	}
	c.clockUntil = unix + 45
}

func cloneReport(r *auditwire.Report) *auditwire.Report {
	v := *r
	v.Items = append([]auditwire.Item{}, r.Items...)
	return &v
}
func (c *Collector) Ack(boot string, sequence uint64) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.delivery.pending == nil {
		return false
	}
	if c.delivery.boot != boot || c.delivery.pending.Sequence != sequence {
		return false
	}
	c.delivery.pending = nil
	return true
}
