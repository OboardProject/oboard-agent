package minibox

import (
	"testing"
	"time"
)

func TestMemoryReclaimThresholdAdaptsToMemoryClass(t *testing.T) {
	tests := []struct {
		name   string
		tuning RuntimeTuning
		want   uint64
	}{
		{name: "micro", tuning: RuntimeTuning{Profile: ResourceProfileSmall, MemoryClass: "micro", CgroupMemoryLimitBytes: 128 << 20}, want: (128 << 20) * 85 / 100},
		{name: "compact", tuning: RuntimeTuning{Profile: ResourceProfileSmall, MemoryClass: "compact", CgroupMemoryLimitBytes: 256 << 20}, want: (256 << 20) * 88 / 100},
		{name: "small", tuning: RuntimeTuning{Profile: ResourceProfileSmall, MemoryClass: "small", CgroupMemoryLimitBytes: 384 << 20}, want: (384 << 20) * 90 / 100},
		{name: "standard cgroup", tuning: RuntimeTuning{Profile: ResourceProfileLarge, MemoryClass: "standard", CgroupMemoryLimitBytes: 512 << 20, EffectiveMemoryBytes: 512 << 20}, want: (512 << 20) * 90 / 100},
		{name: "large disabled", tuning: RuntimeTuning{Profile: ResourceProfileLarge, MemoryClass: "performance", CgroupMemoryLimitBytes: 2 << 30, EffectiveMemoryBytes: 2 << 30}, want: 0},
		{name: "unknown disabled", tuning: RuntimeTuning{Profile: ResourceProfileSmall, MemoryClass: "unknown"}, want: 0},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := memoryReclaimThreshold(test.tuning); got != test.want {
				t.Fatalf("threshold = %d, want %d", got, test.want)
			}
		})
	}
}

func TestMemoryReclaimerCooldown(t *testing.T) {
	r := &MemoryReclaimer{}
	now := time.Now()
	if !r.reclaimReady(now) {
		t.Fatal("new reclaimer should be ready")
	}
	r.lastReclaimed.Store(now.UnixNano())
	if r.reclaimReady(now.Add(4 * time.Second)) {
		t.Fatal("reclaimer should observe cooldown")
	}
	if !r.reclaimReady(now.Add(5 * time.Second)) {
		t.Fatal("reclaimer should be ready after cooldown")
	}
}
