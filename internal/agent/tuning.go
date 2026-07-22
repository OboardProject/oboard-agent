package agent

import (
	"log"
	"os"
	"runtime"
	"runtime/debug"
	"strconv"
	"strings"
	"time"
)

type ResourceProfile string

const (
	ResourceProfileAuto  ResourceProfile = "auto"
	ResourceProfileSmall ResourceProfile = "small"
	ResourceProfileLarge ResourceProfile = "large"
	largeMemoryThreshold                 = uint64(512 << 20)
)

type ResourceInfo struct {
	Profile                ResourceProfile
	Virtualization         string
	Container              bool
	SystemMemoryBytes      uint64
	CgroupMemoryLimitBytes uint64
	EffectiveMemoryBytes   uint64
	CPUCount               int
}

type RuntimeTuning struct {
	Profile          ResourceProfile
	GOMAXPROCS       int
	GCPercent        int
	MemoryLimitBytes int64
}

func validResourceProfile(profile string) bool {
	switch ResourceProfile(strings.ToLower(strings.TrimSpace(profile))) {
	case "", ResourceProfileAuto, ResourceProfileSmall, ResourceProfileLarge:
		return true
	default:
		return false
	}
}

func DetectResourceInfo(requested string) ResourceInfo {
	// The profile is based on capacity rather than current usage.
	systemMemory, _ := linuxMemory()
	cgroupLimit := positiveInt64ToUint64(detectedCgroupMemoryLimit())
	virtualization, container := detectVirtualization()
	effective := effectiveMemory(systemMemory, cgroupLimit)
	profile := selectResourceProfile(requested, effective, container)
	info := ResourceInfo{
		Profile:                profile,
		Virtualization:         virtualization,
		Container:              container,
		SystemMemoryBytes:      systemMemory,
		CgroupMemoryLimitBytes: cgroupLimit,
		EffectiveMemoryBytes:   effective,
		CPUCount:               runtime.NumCPU(),
	}
	if info.CPUCount < 1 {
		info.CPUCount = 1
	}
	return info
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

func selectResourceProfile(requested string, effectiveMemoryBytes uint64, container bool) ResourceProfile {
	requestedProfile := ResourceProfile(strings.ToLower(strings.TrimSpace(requested)))
	if requestedProfile == ResourceProfileSmall {
		return ResourceProfileSmall
	}
	// Known low-memory hosts always use the conservative profile. Multi-GiB
	// containers are no longer forced small — they share the large budget so the
	// kernel can use multi-core for multi-user traffic. Unknown capacity defaults
	// to small unless an operator explicitly forces large (dev hosts).
	if effectiveMemoryBytes > 0 && effectiveMemoryBytes < largeMemoryThreshold {
		return ResourceProfileSmall
	}
	if effectiveMemoryBytes == 0 {
		if requestedProfile == ResourceProfileLarge {
			return ResourceProfileLarge
		}
		// Unknown capacity on a container stays conservative.
		_ = container
		return ResourceProfileSmall
	}
	if requestedProfile == ResourceProfileLarge {
		return ResourceProfileLarge
	}
	return ResourceProfileLarge
}

// PublicIPProbeInterval throttles public IPv4/IPv6 detection and core version
// probes. Local CPU/memory/disk samples are refreshed on every Probe() call so
// heartbeat reports stay accurate.
func (r ResourceInfo) PublicIPProbeInterval() time.Duration {
	if r.Profile == ResourceProfileSmall {
		return 15 * time.Minute
	}
	return 5 * time.Minute
}

func (r ResourceInfo) TrafficReportInterval() time.Duration {
	if r.Profile == ResourceProfileSmall {
		return 30 * time.Second
	}
	return 15 * time.Second
}

func ApplyRuntimeTuning(info ResourceInfo) RuntimeTuning {
	tuning := agentRuntimeTuning(info)
	if os.Getenv("GOMAXPROCS") == "" {
		runtime.GOMAXPROCS(tuning.GOMAXPROCS)
	}
	if os.Getenv("GOGC") == "" {
		debug.SetGCPercent(tuning.GCPercent)
	}
	if os.Getenv("GOMEMLIMIT") == "" {
		debug.SetMemoryLimit(tuning.MemoryLimitBytes)
	}
	log.Printf("agent resource profile=%s virtualization=%s container=%t effective_memory=%d gomaxprocs=%d gogc=%d gomemlimit=%d", info.Profile, info.Virtualization, info.Container, info.EffectiveMemoryBytes, runtime.GOMAXPROCS(0), tuning.GCPercent, tuning.MemoryLimitBytes)
	return tuning
}

func agentRuntimeTuning(info ResourceInfo) RuntimeTuning {
	if info.Profile == ResourceProfileSmall {
		limit := int64(16 << 20)
		if info.EffectiveMemoryBytes > 0 {
			limit = saturatedUint64ToInt64(info.EffectiveMemoryBytes / 8)
		}
		limit = clampInt64(limit, 16<<20, 64<<20)
		return RuntimeTuning{Profile: info.Profile, GOMAXPROCS: 1, GCPercent: 50, MemoryLimitBytes: limit}
	}
	procs := info.CPUCount
	if procs > 2 {
		procs = 2
	}
	if procs < 1 {
		procs = 1
	}
	limit := int64(128 << 20)
	if info.EffectiveMemoryBytes > 0 {
		limit = saturatedUint64ToInt64(info.EffectiveMemoryBytes / 8)
	}
	limit = clampInt64(limit, 64<<20, 128<<20)
	return RuntimeTuning{Profile: info.Profile, GOMAXPROCS: procs, GCPercent: 100, MemoryLimitBytes: limit}
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

func detectVirtualization() (string, bool) {
	if value := strings.TrimSpace(readFileString("/run/systemd/container")); value != "" {
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
	markers := strings.ToLower(readFileString("/proc/1/cgroup") + "\n" + readFileString("/proc/1/environ"))
	for _, marker := range []string{"incus", "lxc", "docker", "podman", "libpod", "kubepods", "containerd"} {
		if strings.Contains(markers, marker) {
			return marker, true
		}
	}
	product := strings.ToLower(readFileString("/sys/class/dmi/id/product_name") + " " + readFileString("/sys/class/dmi/id/sys_vendor"))
	for _, item := range []struct{ marker, name string }{
		{"kvm", "kvm"}, {"qemu", "kvm"}, {"vmware", "vmware"}, {"virtualbox", "virtualbox"},
		{"microsoft corporation", "hyperv"}, {"xen", "xen"}, {"openstack", "kvm"},
	} {
		if strings.Contains(product, item.marker) {
			return item.name, false
		}
	}
	return "physical", false
}

func detectedCgroupMemoryLimit() int64 {
	for _, path := range []string{
		"/sys/fs/cgroup/memory.max",
		"/sys/fs/cgroup/memory/memory.limit_in_bytes",
	} {
		limit := readMemoryLimit(path)
		if limit > 0 {
			return limit
		}
	}
	return 0
}

func detectedCgroupMemoryUsage() uint64 {
	for _, path := range []string{
		"/sys/fs/cgroup/memory.current",
		"/sys/fs/cgroup/memory/memory.usage_in_bytes",
	} {
		if usage := readMemoryLimit(path); usage > 0 {
			return uint64(usage)
		}
	}
	return 0
}

func readMemoryLimit(path string) int64 {
	// #nosec G304 -- callers pass only fixed cgroup control-file paths.
	b, err := os.ReadFile(path)
	if err != nil {
		return 0
	}
	s := strings.TrimSpace(string(b))
	if s == "" || s == "max" {
		return 0
	}
	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil || n <= 0 || n > 1<<60 {
		return 0
	}
	return n
}
