package minibox

import (
	"errors"
	"os"
	"runtime"
	"runtime/debug"
	"strconv"
	"strings"
)

type ResourceProfile string

const (
	ResourceProfileAuto        ResourceProfile = "auto"
	ResourceProfileSmall       ResourceProfile = "small"
	ResourceProfileLarge       ResourceProfile = "large"
	kernelLargeMemoryThreshold                 = uint64(512 << 20)
)

type RuntimeTuning struct {
	Profile                ResourceProfile
	MemoryClass            string
	Virtualization         string
	Container              bool
	SystemMemoryBytes      uint64
	CgroupMemoryLimitBytes uint64
	EffectiveMemoryBytes   uint64
	GOMAXPROCS             int
	GCPercent              int
	MemoryLimitBytes       int64
}

// hostReserves is the non-Go budget that must stay free so the kernel process
// can fill the rest of effective memory without OOM under multi-connection load.
// Inspired by mini-sb-agent: OOM on tiny NAT boxes is usually TCP socket pages,
// not the Go heap — so GOMEMLIMIT is a soft ceiling that leaves room for
// Agent + OS + socket buffers while still letting Go use most of the remainder.
type hostReserves struct {
	agent  uint64
	socket uint64
	os     uint64
}

func (r hostReserves) total() uint64 { return r.agent + r.socket + r.os }

func ApplyRuntimeDefaults(requested string, gomaxprocs int, memoryLimit int64) (RuntimeTuning, error) {
	if envProfile := strings.TrimSpace(os.Getenv("OBOARD_RESOURCE_PROFILE")); requested == "" || requested == "auto" {
		if envProfile != "" {
			requested = envProfile
		}
	}
	profile := ResourceProfile(strings.ToLower(strings.TrimSpace(requested)))
	if profile == "" {
		profile = ResourceProfileAuto
	}
	if profile != ResourceProfileAuto && profile != ResourceProfileSmall && profile != ResourceProfileLarge {
		return RuntimeTuning{}, errors.New("resource-profile must be auto, small, or large")
	}
	systemMemory := linuxTotalMemory()
	cgroupLimit := positiveInt64ToUint64(detectedCgroupMemoryLimit())
	effective := effectiveMemory(systemMemory, cgroupLimit)
	virtualization, container := detectVirtualization()
	detectedProfile := selectResourceProfile(effective, container)
	if profile == ResourceProfileAuto {
		profile = detectedProfile
	} else if profile == ResourceProfileLarge && detectedProfile == ResourceProfileSmall {
		// Never promote a known low-memory host into the large profile.
		profile = detectedProfile
	}
	tuning := kernelRuntimeTuning(RuntimeTuning{Profile: profile, Virtualization: virtualization, Container: container, SystemMemoryBytes: systemMemory, CgroupMemoryLimitBytes: cgroupLimit, EffectiveMemoryBytes: effective})
	if gomaxprocs > 0 {
		tuning.GOMAXPROCS = gomaxprocs
	}
	if memoryLimit > 0 {
		tuning.MemoryLimitBytes = memoryLimit
	}
	if os.Getenv("GOMAXPROCS") == "" {
		runtime.GOMAXPROCS(tuning.GOMAXPROCS)
	}
	if os.Getenv("GOGC") == "" {
		debug.SetGCPercent(tuning.GCPercent)
	}
	if os.Getenv("GOMEMLIMIT") == "" {
		debug.SetMemoryLimit(tuning.MemoryLimitBytes)
	}
	_ = os.Setenv("SING_DNS_PATH", "")
	return tuning, nil
}

// selectResourceProfile picks a coarse profile from capacity.
// Containers are not forced small when effective memory is known and at least
// 512 MiB — a multi-core Docker/LXC node should use the large budget.
// Unknown memory stays conservative (small).
func selectResourceProfile(effectiveMemoryBytes uint64, container bool) ResourceProfile {
	if effectiveMemoryBytes > 0 && effectiveMemoryBytes < kernelLargeMemoryThreshold {
		return ResourceProfileSmall
	}
	if effectiveMemoryBytes == 0 {
		_ = container
		return ResourceProfileSmall
	}
	return ResourceProfileLarge
}

func kernelRuntimeTuning(info RuntimeTuning) RuntimeTuning {
	cpuCount := availableCPUCount()
	if info.Profile == ResourceProfileSmall {
		info.MemoryClass, info.GOMAXPROCS, info.GCPercent, info.MemoryLimitBytes = smallKernelBudget(info.EffectiveMemoryBytes, cpuCount)
		return info
	}
	info.MemoryClass, info.GOMAXPROCS, info.GCPercent, info.MemoryLimitBytes = largeKernelBudget(info.EffectiveMemoryBytes, cpuCount)
	return info
}

// fillableGoLimit returns how much of effective memory the Go soft-limit may
// claim after Agent / socket / OS reserves. Goal: use the box, not starve it.
// Floor/ceiling keep pathological hosts (tiny residual or huge RAM) sane.
func fillableGoLimit(memory uint64, floor, ceiling int64) int64 {
	if memory == 0 {
		return floor
	}
	reserves := classifyHostReserves(memory)
	if reserves.total() >= memory {
		// Extremely tight: leave ~25% non-Go, give the rest to Go.
		return clampInt64(saturatedUint64ToInt64(memory*75/100), floor, ceiling)
	}
	return clampInt64(saturatedUint64ToInt64(memory-reserves.total()), floor, ceiling)
}

// classifyHostReserves sizes non-Go headroom.
// Socket reserve is the critical anti-OOM term (mini-sb-agent lesson): under
// multi-thread speedtests, cgroup sock pages dominate RSS, not the Go heap.
// Agent reserve tracks the control-plane budget on shared hosts.
func classifyHostReserves(memory uint64) hostReserves {
	switch {
	case memory <= 96<<20:
		return hostReserves{agent: 12 << 20, socket: 20 << 20, os: 8 << 20}
	case memory <= 128<<20:
		// 128 MiB NAT box (mini-sb reference class): ~16 MiB agent, ~36 MiB
		// socket headroom under capped auto-tune, ~12 MiB OS → ~64 MiB for Go.
		return hostReserves{agent: 16 << 20, socket: 36 << 20, os: 12 << 20}
	case memory <= 192<<20:
		return hostReserves{agent: 20 << 20, socket: 48 << 20, os: 16 << 20}
	case memory <= 256<<20:
		return hostReserves{agent: 24 << 20, socket: 64 << 20, os: 20 << 20}
	case memory < 512<<20:
		return hostReserves{agent: 32 << 20, socket: 80 << 20, os: 24 << 20}
	case memory < 1<<30:
		return hostReserves{agent: 64 << 20, socket: 96 << 20, os: 32 << 20}
	case memory < 2<<30:
		return hostReserves{agent: 96 << 20, socket: 128 << 20, os: 48 << 20}
	case memory < 4<<30:
		return hostReserves{agent: 128 << 20, socket: 192 << 20, os: 96 << 20}
	default:
		return hostReserves{agent: 128 << 20, socket: 256 << 20, os: memory / 16}
	}
}

// smallKernelBudget covers low-memory and unknown hosts.
// Philosophy (aligned with mini-sb-agent, adapted for OBoard):
//   - single P on the tiniest boxes; upper small may use 2 Ps for multi-user
//   - GOMEMLIMIT fills residual after reserves (use the container, don't idle it)
//   - GOGC rises with available heap so single-stream throughput is not GC-bound
//
// mini-sb fixed GOMEMLIMIT=40MiB / GOGC=70 / GOMAXPROCS=1 for their 128-256 class;
// we scale that idea by effective memory instead of one hard-coded triple.
func smallKernelBudget(memory uint64, cpuCount int) (memoryClass string, gomaxprocs int, gcPercent int, memoryLimit int64) {
	if cpuCount < 1 {
		cpuCount = 1
	}
	switch {
	case memory > 0 && memory <= 96<<20:
		// Tightest class: keep single-threaded; still fill residual (~56 MiB raw
		// residual on 96 → clamp floor 20 / practical ~56 after reserves 40).
		return "micro", 1, 50, fillableGoLimit(memory, 20<<20, 48<<20)
	case memory > 0 && memory <= 128<<20:
		// 128 MiB: residual = 128-16-36-12 = 64 MiB. Match mini-sb spirit
		// (use ~half the box for Go) but allow the full residual so a single
		// unrestricted user can sustain high throughput without GC thrash.
		return "micro", 1, 70, fillableGoLimit(memory, 40<<20, 72<<20)
	case memory > 0 && memory <= 192<<20:
		// residual = 192-20-48-16 = 108 MiB
		return "compact", 1, 70, fillableGoLimit(memory, 48<<20, 120<<20)
	case memory > 0 && memory <= 256<<20:
		// residual = 256-24-64-20 = 148 MiB — use it; mini-sb's fixed 40 is too
		// timid once socket caps are adaptive.
		return "compact", 1, 80, fillableGoLimit(memory, 64<<20, 160<<20)
	case memory > 0:
		procs := 1
		if cpuCount >= 2 {
			procs = 2
		}
		// residual on 384 = 384-32-80-24 = 248 MiB
		return "small", procs, 90, fillableGoLimit(memory, 80<<20, 280<<20)
	default:
		// Unknown capacity: mini-sb-like defaults that still leave room to work.
		return "unknown", 1, 70, 40 << 20
	}
}

// largeKernelBudget is for hosts with at least 512 MiB effective memory.
// Fill residual aggressively for throughput; raise GOGC as RAM grows so long
// lived splice/direct-copy paths spend less time in GC assist.
func largeKernelBudget(memory uint64, cpuCount int) (memoryClass string, gomaxprocs int, gcPercent int, memoryLimit int64) {
	if cpuCount < 1 {
		cpuCount = 1
	}
	procs := cpuCount
	class := "standard"
	gcPercent = 100
	floor := int64(192 << 20)
	ceiling := int64(2 << 30)

	switch {
	case memory >= 4<<30:
		class, gcPercent, ceiling = "high", 150, 4<<30
	case memory >= 2<<30:
		class, gcPercent, ceiling = "performance", 120, 2<<30
		if procs > 8 {
			procs = 8
		}
	case memory >= 1<<30:
		class, gcPercent, ceiling = "performance", 100, 1536<<20
		if procs > 6 {
			procs = 6
		}
	default:
		// 512 MiB – 1 GiB
		class, gcPercent, floor, ceiling = "standard", 100, 192<<20, 512<<20
		if procs > 2 {
			procs = 2
		}
	}

	limit := fillableGoLimit(memory, floor, ceiling)
	return class, procs, gcPercent, limit
}

func positiveInt64ToUint64(value int64) uint64 {
	if value <= 0 {
		return 0
	}
	return uint64(value)
}

func saturatedUint64ToInt64(value uint64) int64 {
	const maxInt64AsUint64 = uint64(1<<63 - 1)
	if value > maxInt64AsUint64 {
		return int64(1<<63 - 1)
	}
	return int64(value)
}

// availableCPUCount returns the scheduler parallelism budget.
// Prefer cgroup CPU quota when it is tighter than runtime.NumCPU so a
// 1-vCPU container on a large host does not spawn excess Ps.
func availableCPUCount() int {
	cpuCount := runtime.NumCPU()
	if cpuCount < 1 {
		cpuCount = 1
	}
	if quota := detectedCgroupCPUQuota(); quota > 0 && quota < cpuCount {
		return quota
	}
	return cpuCount
}

func detectedCgroupCPUQuota() int {
	// cgroup v2: cpu.max = "<quota> <period>" or "max"
	if data, err := os.ReadFile("/sys/fs/cgroup/cpu.max"); err == nil {
		fields := strings.Fields(string(data))
		if len(fields) >= 2 && fields[0] != "max" {
			quota, errQuota := strconv.ParseInt(fields[0], 10, 64)
			period, errPeriod := strconv.ParseInt(fields[1], 10, 64)
			if errQuota == nil && errPeriod == nil && quota > 0 && period > 0 {
				return cgroupQuotaToProcs(quota, period)
			}
		}
	}
	// cgroup v1
	quota := readInt64File("/sys/fs/cgroup/cpu/cpu.cfs_quota_us")
	period := readInt64File("/sys/fs/cgroup/cpu/cpu.cfs_period_us")
	if quota > 0 && period > 0 {
		return cgroupQuotaToProcs(quota, period)
	}
	return 0
}

func cgroupQuotaToProcs(quota, period int64) int {
	if quota <= 0 || period <= 0 {
		return 0
	}
	// Round up partial cores so a 1500ms/1000ms quota still gets 2 Ps.
	procs := int((quota + period - 1) / period)
	if procs < 1 {
		return 1
	}
	return procs
}

func readInt64File(path string) int64 {
	// #nosec G304 -- callers pass only fixed cgroup control-file paths.
	data, err := os.ReadFile(path)
	if err != nil {
		return 0
	}
	value, err := strconv.ParseInt(strings.TrimSpace(string(data)), 10, 64)
	if err != nil {
		return 0
	}
	return value
}

func effectiveMemory(systemMemory, cgroupLimit uint64) uint64 {
	if systemMemory == 0 {
		return cgroupLimit
	}
	if cgroupLimit > 0 && cgroupLimit < systemMemory {
		return cgroupLimit
	}
	return systemMemory
}

func linuxTotalMemory() uint64 {
	b, err := os.ReadFile("/proc/meminfo")
	if err != nil {
		return 0
	}
	for _, line := range strings.Split(string(b), "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 2 && fields[0] == "MemTotal:" {
			value, _ := strconv.ParseUint(fields[1], 10, 64)
			return value * 1024
		}
	}
	return 0
}

func detectedCgroupMemoryLimit() int64 {
	for _, path := range []string{"/sys/fs/cgroup/memory.max", "/sys/fs/cgroup/memory/memory.limit_in_bytes"} {
		// #nosec G304 -- paths are fixed cgroup control files.
		b, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		value := strings.TrimSpace(string(b))
		if value == "" || value == "max" {
			continue
		}
		limit, err := strconv.ParseInt(value, 10, 64)
		if err == nil && limit > 0 && limit < 1<<60 {
			return limit
		}
	}
	return 0
}

func detectVirtualization() (string, bool) {
	if value := strings.TrimSpace(readFile("/run/systemd/container")); value != "" {
		return strings.ToLower(value), true
	}
	if value := strings.TrimSpace(os.Getenv("container")); value != "" {
		return strings.ToLower(value), true
	}
	if _, err := os.Stat("/.dockerenv"); err == nil {
		return "docker", true
	}
	if _, err := os.Stat("/run/.containerenv"); err == nil {
		return "podman", true
	}
	markers := strings.ToLower(readFile("/proc/1/cgroup") + "\n" + readFile("/proc/1/environ"))
	for _, marker := range []string{"incus", "lxc", "docker", "podman", "libpod", "kubepods", "containerd"} {
		if strings.Contains(markers, marker) {
			return marker, true
		}
	}
	product := strings.ToLower(readFile("/sys/class/dmi/id/product_name") + " " + readFile("/sys/class/dmi/id/sys_vendor"))
	for _, item := range []struct{ marker, name string }{{"kvm", "kvm"}, {"qemu", "kvm"}, {"vmware", "vmware"}, {"virtualbox", "virtualbox"}, {"microsoft corporation", "hyperv"}, {"xen", "xen"}, {"openstack", "kvm"}} {
		if strings.Contains(product, item.marker) {
			return item.name, false
		}
	}
	return "physical", false
}

func readFile(path string) string {
	// #nosec G304 -- callers use a fixed allowlist of procfs, sysfs, and OS metadata paths.
	b, _ := os.ReadFile(path)
	return string(b)
}

func clampInt64(value, minimum, maximum int64) int64 {
	if value < minimum {
		return minimum
	}
	if value > maximum {
		return maximum
	}
	return value
}
