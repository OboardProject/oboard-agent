package activity

import (
	"math"
	"net/netip"
	"testing"
)

func identity(source string) Identity { return Bind(1, 2, 3, netip.MustParseAddr(source)) }

func TestPayloadSlicesAndIndependentCapacity(t *testing.T) {
	var c Collector
	id := identity("198.51.100.1")
	c.Record(id, 120, 1, 0)
	if c.slots[2].buckets != nil {
		t.Fatal("disabled allocation")
	}
	c.SetEnabled(true)
	c.Record(id, 120, 0, 0)
	if len(c.Snapshot(120).Buckets) != 0 {
		t.Fatal("heartbeat is not payload")
	}
	c.Record(id, 120, 100, 0)
	c.Record(identity("::ffff:198.51.100.9"), 135, 0, 200)
	b := c.Snapshot(179).Buckets
	if len(b) != 1 || b[0].ActivityBits != 9 || b[0].UploadBytes != 100 || b[0].DownloadBytes != 200 {
		t.Fatalf("actual slices: %+v", b)
	}
	c.Record(identity("198.51.101.1"), 175, 1, 0)
	if len(c.Snapshot(179).Buckets) != 2 {
		t.Fatal("distinct source lost")
	}
	if len(c.Snapshot(300).Buckets) != 0 {
		t.Fatal("expired buckets exposed")
	}
	c.SetEnabled(false)
	for _, s := range c.slots {
		if s.buckets != nil {
			t.Fatal("disable retained state")
		}
	}
}

func TestQualityBoundsAndOverflow(t *testing.T) {
	var c Collector
	c.SetEnabled(true)
	for i := 0; i < PerAccountCapacity+1; i++ {
		id := Bind(1, 2, 3, netip.AddrFrom4([4]byte{198, 51, byte(i), 1}))
		c.Record(id, 120, 1, 0)
	}
	c.Record(Bind(1, 2, 3, netip.Addr{}), 120, 1, 0)
	c.Record(identity("198.51.100.1"), -1, 1, 0)
	s := c.Snapshot(120)
	if len(s.Buckets) != PerAccountCapacity || s.DroppedUpdates != 1 || s.UnknownSourceUpdates != 1 || !s.TimeUnaligned {
		t.Fatalf("quality: %+v", s)
	}
	var d Collector
	d.SetEnabled(true)
	d.Record(identity("198.51.100.1"), 120, math.MaxUint64, 1)
	d.Record(identity("198.51.100.1"), 125, 1, 1)
	if d.Snapshot(125).Buckets[0].UploadBytes != math.MaxUint64 {
		t.Fatal("overflow wrapped")
	}
}

func TestRetainedOutOfOrderMinuteAndQualityExpiry(t *testing.T) {
	var c Collector
	c.SetEnabled(true)
	id := identity("198.51.100.1")
	c.Record(id, 180, 10, 0)
	c.Record(id, 179, 20, 0)
	s := c.Snapshot(180)
	if s.TimeUnaligned || len(s.Buckets) != 2 {
		t.Fatalf("retained event time was discarded: %+v", s)
	}
	var bytes uint64
	for _, b := range s.Buckets {
		bytes += b.UploadBytes
	}
	if bytes != 30 {
		t.Fatal("payload lost")
	}
	c.Record(id, 0, 100, 0)
	if !c.Snapshot(180).TimeUnaligned {
		t.Fatal("expired event not marked")
	}
	c.Record(id, 360, 1, 0)
	if c.Snapshot(360).TimeUnaligned {
		t.Fatal("old quality flag never expires")
	}
}

func TestGlobalCapacityAndAccountIsolation(t *testing.T) {
	var c Collector
	c.SetEnabled(true)
	for i := int64(1); i <= Capacity+1; i++ {
		id := identity("198.51.100.1")
		id.UserID = i
		c.Record(id, 120, 1, 0)
	}
	s := c.Snapshot(120)
	if len(s.Buckets) != Capacity || s.DroppedUpdates != 1 {
		t.Fatalf("capacity %d dropped %d", len(s.Buckets), s.DroppedUpdates)
	}
}

func TestGroupNormalization(t *testing.T) {
	if identity("2001:db8:abcd:1200::1").Source != identity("2001:db8:abcd:12ff::2").Source {
		t.Fatal("IPv6 /56 mismatch")
	}
	for _, ip := range []string{"127.0.0.1", "10.0.0.1", "::1", "fe80::1", "0.0.0.0"} {
		if identity(ip).Source.IsValid() {
			t.Fatal("relay/private source accepted", ip)
		}
	}
}

func BenchmarkRecord(b *testing.B) {
	var c Collector
	c.SetEnabled(true)
	id := identity("198.51.100.1")
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		c.Record(id, 120+int64(i%60), 1024, 1024)
	}
}
