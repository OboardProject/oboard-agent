package minibox

import (
	"testing"
	"time"
)

func TestRuntimeClockConfigureAdvanceAndDisable(t *testing.T) {
	clock := NewRuntimeClock()
	reference := time.Now().UTC().Add(90 * time.Second)
	if err := clock.Configure(RuntimeClockConfig{Enabled: true, ReferenceTime: reference, Source: "ntp:test", CheckedAt: reference}); err != nil {
		t.Fatal(err)
	}
	first := clock.Now()
	time.Sleep(5 * time.Millisecond)
	second := clock.Now()
	if second.Sub(first) <= 0 || absClockDuration(first.Sub(reference)) > time.Second {
		t.Fatalf("runtime clock did not advance from reference: first=%s second=%s reference=%s", first, second, reference)
	}
	snapshot := clock.Snapshot()
	if !snapshot.Enabled || snapshot.Source != "ntp:test" || snapshot.ReferenceTime.Before(reference) {
		t.Fatalf("runtime clock snapshot = %#v", snapshot)
	}
	if err := clock.Configure(RuntimeClockConfig{Enabled: true}); err == nil {
		t.Fatal("enabled runtime clock accepted an empty reference")
	}
	if err := clock.Configure(RuntimeClockConfig{Enabled: false, ReferenceTime: reference}); err != nil {
		t.Fatal(err)
	}
	if clock.Snapshot().Enabled || !clock.Snapshot().ReferenceTime.IsZero() || absClockDuration(clock.Now().Sub(time.Now())) > time.Second {
		t.Fatalf("runtime clock was not disabled: %#v", clock.Snapshot())
	}
}

func absClockDuration(value time.Duration) time.Duration {
	if value < 0 {
		return -value
	}
	return value
}
