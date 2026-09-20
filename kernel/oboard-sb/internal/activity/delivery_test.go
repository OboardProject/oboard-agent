package activity

import (
	"net/netip"
	"reflect"
	"testing"
	"time"
)

func TestDeliveryReadAckCoverageAndOverflow(t *testing.T) {
	var c Collector
	c.SetEnabled(true)
	first := c.Read(time.Unix(600, 0), "kernel")
	if first == nil || first.Complete {
		t.Fatal("startup must be incomplete")
	}
	if !reflect.DeepEqual(first, c.Read(time.Unix(660, 0), "kernel")) {
		t.Fatal("read changed pending")
	}
	if c.Ack("wrong", first.Sequence) {
		t.Fatal("wrong boot ack")
	}
	c.Ack(first.CollectorBootID, first.Sequence)
	second := c.Read(time.Unix(600, 0), "kernel")
	if second != nil {
		t.Fatal("future minute emitted")
	}
	id := Bind(1, 2, 0, netip.MustParseAddr("8.8.8.8"))
	c.Record(id, 600, 16384, 0)
	c.Record(id, 605, 1, 0)
	c.Record(id, 610, 1, 0)
	r := c.Read(time.Unix(720, 0), "kernel")
	c.Ack(r.CollectorBootID, r.Sequence)
	r = c.Read(time.Unix(720, 0), "kernel")
	if r == nil || !r.Complete || r.MinuteUnix != 600 || len(r.Items) != 1 || r.Items[0].ActivityBits != 7 {
		t.Fatalf("payload report: %+v", r)
	}
	c.Ack(r.CollectorBootID, r.Sequence)
	for i := 0; i < PerAccountCapacity+1; i++ {
		c.Record(Bind(1, int64(i+1), 0, netip.MustParseAddr("9.9.9.9")), 720, 1, 0)
	}
	r = c.Read(time.Unix(840, 0), "kernel")
	c.Ack(r.CollectorBootID, r.Sequence)
	r = c.Read(time.Unix(840, 0), "kernel")
	if r == nil || r.Complete || r.DroppedUpdates != 1 {
		t.Fatalf("overflow %+v", r)
	}
	c.SetEnabled(false)
	if c.Read(time.Unix(900, 0), "kernel") != nil {
		t.Fatal("disabled report")
	}
	c.SetEnabled(true)
	if c.Read(time.Unix(900, 0), "kernel").CollectorBootID == first.CollectorBootID {
		t.Fatal("boot reused")
	}
}
