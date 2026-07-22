package minibox

import (
	"testing"
	"time"
)

func TestAdaptiveSocketGovernorProfiles(t *testing.T) {
	tests := []struct {
		memory   uint64
		peak     int
		balanced int
		safe     int
		high     int64
	}{
		{96 << 20, 1677722, 512 << 10, 128 << 10, 6},
		// 128 MiB follows mini-sb-agent's 1.6 MiB peak; multi-user steps down.
		{128 << 20, 1677722, 768 << 10, 256 << 10, 12},
		{192 << 20, 6 << 20, 2 << 20, 512 << 10, 20},
		{256 << 20, 8 << 20, 2 << 20, 1 << 20, 32},
		{384 << 20, 12 << 20, 4 << 20, 1677722, 64},
		{768 << 20, 16 << 20, 4 << 20, 2 << 20, 128},
	}
	for _, test := range tests {
		profile := adaptiveSocketGovernorProfile(test.memory)
		if profile.peakCap != test.peak || profile.balancedCap != test.balanced || profile.safeCap != test.safe || profile.highWatermark != test.high {
			t.Fatalf("profile for %d = %#v", test.memory, profile)
		}
	}
	if profile := adaptiveSocketGovernorProfile(1 << 30); profile.peakCap != 0 {
		t.Fatalf(">=1 GiB profile should be disabled: %#v", profile)
	}
	if profile := adaptiveSocketGovernorProfile(0); profile.peakCap != 0 {
		t.Fatalf("unknown memory profile should be disabled: %#v", profile)
	}
}

func TestSocketGovernorRestoresOnlyAfterStableWindow(t *testing.T) {
	g := &SocketBufferGovernor{
		enabled:       true,
		profile:       socketGovernorProfile{peakCap: 1677722, balancedCap: 768 << 10, safeCap: 256 << 10, balancedWatermark: 6, highWatermark: 12},
		pressureBytes: 100,
		mode:          "safe",
		currentCap:    256 << 10,
	}
	now := time.Now()
	g.evaluate(now, 50)
	if g.stableSince.IsZero() {
		t.Fatal("stable window should start under low load")
	}
	if now.Add(9*time.Second).Sub(g.stableSince) >= 10*time.Second {
		t.Fatal("governor must not restore before ten seconds")
	}
}
