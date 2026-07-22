package minibox

import "testing"

func TestSelectResourceProfile(t *testing.T) {
	if got := selectResourceProfile(511<<20, false); got != ResourceProfileSmall {
		t.Fatalf("511 MiB profile = %q", got)
	}
	if got := selectResourceProfile(512<<20, false); got != ResourceProfileLarge {
		t.Fatalf("512 MiB profile = %q", got)
	}
	if got := selectResourceProfile(4<<30, true); got != ResourceProfileLarge {
		t.Fatalf("large container profile = %q", got)
	}
	if got := selectResourceProfile(256<<20, true); got != ResourceProfileSmall {
		t.Fatalf("small container profile = %q", got)
	}
	if got := selectResourceProfile(0, false); got != ResourceProfileSmall {
		t.Fatalf("unknown-memory profile = %q", got)
	}
}

func TestKernelRuntimeTuningFillsAvailableMemory(t *testing.T) {
	tiny := kernelRuntimeTuning(RuntimeTuning{Profile: ResourceProfileSmall, EffectiveMemoryBytes: 64 << 20})
	if tiny.GOMAXPROCS != 1 || tiny.MemoryClass != "micro" || tiny.GCPercent != 50 {
		t.Fatalf("tiny tuning = %#v", tiny)
	}
	// 64 - 12 - 20 - 8 = 24 MiB residual, floor 20.
	if tiny.MemoryLimitBytes != 24<<20 {
		t.Fatalf("64 MiB limit = %d want %d", tiny.MemoryLimitBytes, 24<<20)
	}

	// 128 MiB: residual 128-16-36-12 = 64 MiB. Use the box (mini-sb used a
	// fixed 40 MiB; we fill residual so single-user peak is not GC-starved).
	m128 := kernelRuntimeTuning(RuntimeTuning{Profile: ResourceProfileSmall, EffectiveMemoryBytes: 128 << 20})
	if m128.MemoryClass != "micro" || m128.GOMAXPROCS != 1 || m128.GCPercent != 70 {
		t.Fatalf("128 MiB tuning = %#v", m128)
	}
	if m128.MemoryLimitBytes != 64<<20 {
		t.Fatalf("128 MiB limit = %d want %d", m128.MemoryLimitBytes, 64<<20)
	}

	m192 := kernelRuntimeTuning(RuntimeTuning{Profile: ResourceProfileSmall, EffectiveMemoryBytes: 192 << 20})
	if m192.MemoryClass != "compact" || m192.GCPercent != 70 || m192.MemoryLimitBytes != 108<<20 {
		t.Fatalf("192 MiB tuning = %#v", m192)
	}

	m256 := kernelRuntimeTuning(RuntimeTuning{Profile: ResourceProfileSmall, EffectiveMemoryBytes: 256 << 20})
	if m256.MemoryClass != "compact" || m256.GCPercent != 80 || m256.GOMAXPROCS != 1 {
		t.Fatalf("256 MiB tuning = %#v", m256)
	}
	// residual 256-24-64-20 = 148 MiB
	if m256.MemoryLimitBytes != 148<<20 {
		t.Fatalf("256 MiB limit = %d want %d", m256.MemoryLimitBytes, 148<<20)
	}

	upper := kernelRuntimeTuning(RuntimeTuning{Profile: ResourceProfileSmall, EffectiveMemoryBytes: 384 << 20})
	if upper.MemoryClass != "small" || upper.GCPercent != 90 {
		t.Fatalf("upper small tuning = %#v", upper)
	}
	if upper.GOMAXPROCS < 1 || upper.GOMAXPROCS > 2 {
		t.Fatalf("upper small procs = %d", upper.GOMAXPROCS)
	}
	// residual 384-32-80-24 = 248 MiB
	if upper.MemoryLimitBytes != 248<<20 {
		t.Fatalf("384 MiB limit = %d want %d", upper.MemoryLimitBytes, 248<<20)
	}

	// 512 MiB large: residual 512-64-96-32 = 320 MiB, floor 192, ceiling 512.
	threshold := kernelRuntimeTuning(RuntimeTuning{Profile: ResourceProfileLarge, EffectiveMemoryBytes: 512 << 20})
	if threshold.MemoryClass != "standard" || threshold.GCPercent != 100 {
		t.Fatalf("threshold tuning = %#v", threshold)
	}
	if threshold.GOMAXPROCS < 1 || threshold.GOMAXPROCS > 2 {
		t.Fatalf("512 MiB procs = %d", threshold.GOMAXPROCS)
	}
	if threshold.MemoryLimitBytes != 320<<20 {
		t.Fatalf("512 MiB limit = %d want %d", threshold.MemoryLimitBytes, 320<<20)
	}

	oneGiB := kernelRuntimeTuning(RuntimeTuning{Profile: ResourceProfileLarge, EffectiveMemoryBytes: 1 << 30})
	if oneGiB.MemoryClass != "performance" || oneGiB.GCPercent != 100 {
		t.Fatalf("1 GiB tuning = %#v", oneGiB)
	}
	// residual 1024-96-128-48 = 752 MiB
	if oneGiB.MemoryLimitBytes != 752<<20 {
		t.Fatalf("1 GiB limit = %d want %d", oneGiB.MemoryLimitBytes, 752<<20)
	}

	twoGiB := kernelRuntimeTuning(RuntimeTuning{Profile: ResourceProfileLarge, EffectiveMemoryBytes: 2 << 30})
	if twoGiB.MemoryClass != "performance" || twoGiB.GCPercent != 120 {
		t.Fatalf("2 GiB tuning = %#v", twoGiB)
	}
	// residual 2048-128-192-96 = 1632 MiB, ceiling 2 GiB → 1632
	if twoGiB.MemoryLimitBytes != 1632<<20 {
		t.Fatalf("2 GiB limit = %d want %d", twoGiB.MemoryLimitBytes, 1632<<20)
	}

	high := kernelRuntimeTuning(RuntimeTuning{Profile: ResourceProfileLarge, EffectiveMemoryBytes: 4 << 30})
	if high.MemoryClass != "high" || high.GCPercent != 150 {
		t.Fatalf("high tuning = %#v", high)
	}
	// residual 4096-128-256-256 = 3456 MiB, ceiling 4 GiB
	if high.MemoryLimitBytes != 3456<<20 {
		t.Fatalf("4 GiB limit = %d want %d", high.MemoryLimitBytes, 3456<<20)
	}
}

func TestFillableGoLimitUsesResidual(t *testing.T) {
	if got := fillableGoLimit(128<<20, 40<<20, 72<<20); got != 64<<20 {
		t.Fatalf("128 fill = %d", got)
	}
	if got := fillableGoLimit(0, 40<<20, 72<<20); got != 40<<20 {
		t.Fatalf("unknown fill = %d", got)
	}
}

func TestEffectiveMemoryUsesCgroupLimit(t *testing.T) {
	if got := effectiveMemory(2<<30, 128<<20); got != 128<<20 {
		t.Fatalf("effective memory = %d", got)
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

func TestCgroupQuotaToProcs(t *testing.T) {
	if got := cgroupQuotaToProcs(100000, 100000); got != 1 {
		t.Fatalf("1 cpu quota = %d", got)
	}
	if got := cgroupQuotaToProcs(150000, 100000); got != 2 {
		t.Fatalf("1.5 cpu quota = %d", got)
	}
	if got := cgroupQuotaToProcs(0, 100000); got != 0 {
		t.Fatalf("disabled quota = %d", got)
	}
}

func TestClassifyHostReserves(t *testing.T) {
	r := classifyHostReserves(128 << 20)
	if r.agent != 16<<20 || r.socket != 36<<20 || r.os != 12<<20 {
		t.Fatalf("128 reserves = %#v", r)
	}
	if r.total() != 64<<20 {
		t.Fatalf("128 total reserve = %d", r.total())
	}
}
