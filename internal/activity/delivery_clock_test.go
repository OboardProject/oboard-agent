package activity

import (
	"net/netip"
	"testing"
	"time"
)

func TestDeliveryClockCoverageAndLateCumulativeCorrection(t *testing.T) {
	var c Collector
	c.SetEnabled(true)
	r := c.Read(time.Unix(600, 0), "kernel")
	if r.ClockState != "unknown" {
		t.Fatal("unmeasured clock declared aligned")
	}
	c.Ack(r.CollectorBootID, r.Sequence)
	for _, at := range []int64{600, 630, 660, 690, 720} {
		c.AlignClock(at, true)
	}
	id := Bind(1, 2, 0, netip.MustParseAddr("8.8.8.8"))
	c.Record(id, 600, 100, 0)
	r = c.Read(time.Unix(720, 0), "kernel")
	c.Ack(r.CollectorBootID, r.Sequence)
	r = c.Read(time.Unix(720, 0), "kernel")
	if r.MinuteUnix != 600 || r.ClockState != "aligned" || r.Items[0].UploadBytes != 100 {
		t.Fatalf("covered minute %+v", r)
	}
	c.Record(id, 605, 20, 0)
	if got := c.Read(time.Unix(720, 0), "kernel"); got.Sequence != r.Sequence || got.Items[0].UploadBytes != 100 {
		t.Fatal("pending changed")
	}
	c.Ack(r.CollectorBootID, r.Sequence)
	correction := c.Read(time.Unix(720, 0), "kernel")
	if correction.Sequence <= r.Sequence || correction.MinuteUnix != 600 || correction.Items[0].UploadBytes != 120 || correction.Items[0].ActivityBits != 3 {
		t.Fatalf("late delta not cumulative %+v", correction)
	}
	c.Ack(correction.CollectorBootID, correction.Sequence)
	c.AlignClock(780, true) // Coverage lease expired; no bridge over missing observations.
	r = c.Read(time.Unix(780, 0), "kernel")
	if r.ClockState != "unknown" {
		t.Fatal("gap hidden")
	}
}
