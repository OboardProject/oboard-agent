package agent

import "testing"

func TestDesiredTCPBufferCap(t *testing.T) {
	if got := desiredTCPBufferCap(96 << 20); got != tinyMemoryTCPBufferCap {
		t.Fatalf("96 MiB cap = %d", got)
	}
	if got := desiredTCPBufferCap(128 << 20); got != microMemoryTCPBufferCap {
		t.Fatalf("128 MiB cap = %d", got)
	}
	if got := desiredTCPBufferCap(192 << 20); got != compactMemoryTCPBufferCap {
		t.Fatalf("192 MiB cap = %d", got)
	}
	if got := desiredTCPBufferCap(256 << 20); got != lowMemoryTCPBufferCap {
		t.Fatalf("256 MiB cap = %d", got)
	}
	if got := desiredTCPBufferCap(384 << 20); got != smallMemoryTCPBufferCap {
		t.Fatalf("384 MiB cap = %d", got)
	}
	if got := desiredTCPBufferCap(768 << 20); got != 16<<20 {
		t.Fatalf("768 MiB cap = %d", got)
	}
	if got := desiredTCPBufferCap(1 << 30); got != 0 {
		t.Fatalf("1 GiB cap = %d", got)
	}
}

func TestSocketMemoryClass(t *testing.T) {
	for _, test := range []struct {
		memory uint64
		want   string
	}{{0, "unknown"}, {128 << 20, "micro"}, {256 << 20, "compact"}, {384 << 20, "small"}, {512 << 20, "standard"}} {
		if got := socketMemoryClass(test.memory); got != test.want {
			t.Fatalf("class for %d = %q, want %q", test.memory, got, test.want)
		}
	}
}

func TestCapTCPBufferTriplet(t *testing.T) {
	// Cap a larger max down to the mini-sb-style 1.6 MiB peak.
	got, changed, err := capTCPBufferTriplet("4096 131072 16777216", microMemoryTCPBufferCap)
	if err != nil || !changed || got != "4096 131072 1677722" {
		t.Fatalf("cap result = %q, %t, %v", got, changed, err)
	}
	// Already under the low-memory peak ceiling — leave alone.
	got, changed, err = capTCPBufferTriplet("4096 87380 1048576", lowMemoryTCPBufferCap)
	if err != nil || changed || got != "4096 87380 1048576" {
		t.Fatalf("safe result = %q, %t, %v", got, changed, err)
	}
	// Default larger than peak forces default down with the max.
	got, changed, err = capTCPBufferTriplet("4096 6291456 16777216", tinyMemoryTCPBufferCap)
	if err != nil || !changed || got != "4096 1677722 1677722" {
		t.Fatalf("default-clamp result = %q, %t, %v", got, changed, err)
	}
}
