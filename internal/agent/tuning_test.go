package agent

import (
	"testing"
	"time"
)

func TestSelectResourceProfile(t *testing.T) {
	cases := []struct {
		name      string
		requested string
		memory    uint64
		container bool
		want      ResourceProfile
	}{
		{name: "small physical", memory: 511 << 20, want: ResourceProfileSmall},
		{name: "threshold physical", memory: 512 << 20, want: ResourceProfileLarge},
		{name: "large kvm", memory: 2 << 30, want: ResourceProfileLarge},
		{name: "large lxc uses large", memory: 2 << 30, container: true, want: ResourceProfileLarge},
		{name: "small container stays small", memory: 256 << 20, container: true, want: ResourceProfileSmall},
		{name: "unknown memory is conservative", memory: 0, want: ResourceProfileSmall},
		{name: "manual small", requested: "small", memory: 4 << 30, want: ResourceProfileSmall},
		{name: "manual large cannot bypass known low memory", requested: "large", memory: 128 << 20, want: ResourceProfileSmall},
		{name: "manual large supports unknown dev host", requested: "large", memory: 0, want: ResourceProfileLarge},
		{name: "manual large on safe host", requested: "large", memory: 1 << 30, want: ResourceProfileLarge},
		{name: "manual large on multi-GiB container", requested: "large", memory: 2 << 30, container: true, want: ResourceProfileLarge},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := selectResourceProfile(tc.requested, tc.memory, tc.container); got != tc.want {
				t.Fatalf("profile = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestEffectiveMemoryUsesCgroupLimit(t *testing.T) {
	if got := effectiveMemory(2<<30, 256<<20); got != 256<<20 {
		t.Fatalf("effective memory = %d, want cgroup limit", got)
	}
	if got := effectiveMemory(512<<20, 2<<30); got != 512<<20 {
		t.Fatalf("effective memory = %d, want system memory", got)
	}
}

func TestMemoryIntegerConversionsAreBounded(t *testing.T) {
	if got := positiveInt64ToUint64(-1); got != 0 {
		t.Fatalf("negative cgroup limit converted to %d", got)
	}
	if got := positiveInt64ToUint64(123); got != 123 {
		t.Fatalf("positive cgroup limit converted to %d", got)
	}
	if got := saturatedUint64ToInt64(^uint64(0)); got != int64(1<<63-1) {
		t.Fatalf("saturated uint64 conversion = %d", got)
	}
}

func TestRuntimeTuningProfiles(t *testing.T) {
	tiny := agentRuntimeTuning(ResourceInfo{Profile: ResourceProfileSmall, EffectiveMemoryBytes: 64 << 20, CPUCount: 4})
	if tiny.GOMAXPROCS != 1 || tiny.GCPercent != 50 || tiny.MemoryLimitBytes != 16<<20 {
		t.Fatalf("tiny tuning = %#v", tiny)
	}
	small := agentRuntimeTuning(ResourceInfo{Profile: ResourceProfileSmall, EffectiveMemoryBytes: 256 << 20, CPUCount: 4})
	if small.GOMAXPROCS != 1 || small.GCPercent != 50 || small.MemoryLimitBytes != 32<<20 {
		t.Fatalf("small tuning = %#v", small)
	}
	large := agentRuntimeTuning(ResourceInfo{Profile: ResourceProfileLarge, EffectiveMemoryBytes: 2 << 30, CPUCount: 8})
	if large.GOMAXPROCS != 2 || large.GCPercent != 100 || large.MemoryLimitBytes != 128<<20 {
		t.Fatalf("large tuning = %#v", large)
	}
	threshold := agentRuntimeTuning(ResourceInfo{Profile: ResourceProfileLarge, EffectiveMemoryBytes: 512 << 20, CPUCount: 2})
	if threshold.MemoryLimitBytes != 64<<20 {
		t.Fatalf("threshold tuning = %#v", threshold)
	}
}

func TestProbeIntervalFollowsProfile(t *testing.T) {
	if got := (ResourceInfo{Profile: ResourceProfileSmall}).PublicIPProbeInterval(); got != 15*time.Minute {
		t.Fatalf("small public-ip interval = %s", got)
	}
	if got := (ResourceInfo{Profile: ResourceProfileLarge}).PublicIPProbeInterval(); got != 5*time.Minute {
		t.Fatalf("large public-ip interval = %s", got)
	}
}

func TestTrafficReportIntervalFollowsProfile(t *testing.T) {
	if got := (ResourceInfo{Profile: ResourceProfileSmall}).TrafficReportInterval(); got != 30*time.Second {
		t.Fatalf("small interval = %s", got)
	}
	if got := (ResourceInfo{Profile: ResourceProfileLarge}).TrafficReportInterval(); got != 15*time.Second {
		t.Fatalf("large interval = %s", got)
	}
}
