package agent

import (
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"
)

type distroInfo struct {
	ID             string
	Version        string
	Name           string
	Libc           string
	ServiceManager string
	PackageManager string
}

type systemProbe struct {
	CPUName                   string
	CPUUsagePercent           float64
	MemoryUsedBytes           uint64
	MemoryTotalBytes          uint64
	AgentMemoryBytes          uint64
	DiskBytes                 uint64
	NetworkUploadBPS          uint64
	NetworkDownloadBPS        uint64
	NetworkTotalUploadBytes   uint64
	NetworkTotalDownloadBytes uint64
}

type networkCounterSample struct {
	UploadBytes   uint64
	DownloadBytes uint64
	SampledAt     time.Time
	Valid         bool
}

type hostStaticInfo struct {
	CPUName string
	Kernel  string
	Distro  distroInfo
}

const firstCPUSampleWait = 250 * time.Millisecond

func detectHostStaticInfo() hostStaticInfo {
	info := hostStaticInfo{CPUName: runtime.GOARCH, Kernel: kernel()}
	if runtime.GOOS == "linux" {
		if cpuName := linuxCPUName(); cpuName != "" {
			info.CPUName = cpuName
		}
		info.Distro = detectDistroInfo()
	}
	return info
}

func sampleSystemProbe(cpuName string, previousCPU procCPU) (systemProbe, procCPU) {
	p := systemProbe{CPUName: firstNonEmpty(cpuName, runtime.GOARCH)}
	if runtime.GOOS != "linux" {
		var mem runtime.MemStats
		runtime.ReadMemStats(&mem)
		p.AgentMemoryBytes = mem.Sys
		p.MemoryUsedBytes = mem.Sys
		return p, procCPU{}
	}
	if total, used := linuxMemory(); total > 0 {
		p.MemoryTotalBytes = total
		p.MemoryUsedBytes = used
	}
	if rss := linuxAgentRSS(); rss > 0 {
		p.AgentMemoryBytes = rss
	} else {
		var mem runtime.MemStats
		runtime.ReadMemStats(&mem)
		p.AgentMemoryBytes = mem.Sys
	}
	if disk := linuxDiskUsed("/"); disk > 0 {
		p.DiskBytes = disk
	}
	currentCPU, ok := readProcStatCPU()
	if !ok {
		return p, previousCPU
	}
	// First report after process start has no previous sample. Wait briefly and
	// re-read so enrollment / first heartbeat can include a real CPU percent
	// instead of permanently caching 0 until the next long probe window.
	if previousCPU.total == 0 {
		time.Sleep(firstCPUSampleWait)
		if second, okSecond := readProcStatCPU(); okSecond {
			if usage, valid := cpuUsageBetween(currentCPU, second); valid {
				p.CPUUsagePercent = clampCPUPercent(usage)
			}
			return p, second
		}
		return p, currentCPU
	}
	if usage, valid := cpuUsageBetween(previousCPU, currentCPU); valid {
		p.CPUUsagePercent = clampCPUPercent(usage)
	}
	return p, currentCPU
}

func clampCPUPercent(value float64) float64 {
	if value < 0 {
		return 0
	}
	if value > 100 {
		return 100
	}
	// One decimal keeps UI stable without pretending sub-percent precision.
	return float64(int(value*10+0.5)) / 10
}

func linuxDiskUsed(path string) uint64 {
	var st syscall.Statfs_t
	if err := syscall.Statfs(path, &st); err != nil {
		return 0
	}
	// Blocks - Bfree = used blocks including reserved space, which matches the
	// "disk pressure" view operators expect better than Bavail alone.
	if st.Blocks <= st.Bfree {
		return 0
	}
	bsize := uint64(st.Bsize)
	if bsize == 0 {
		return 0
	}
	return (st.Blocks - st.Bfree) * bsize
}

func linuxCPUName() string {
	b, err := os.ReadFile("/proc/cpuinfo")
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(b), "\n") {
		if strings.HasPrefix(line, "model name") || strings.HasPrefix(line, "Hardware") {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 {
				return strings.TrimSpace(parts[1])
			}
		}
	}
	return ""
}

func linuxMemory() (total uint64, used uint64) {
	b, err := os.ReadFile("/proc/meminfo")
	if err != nil {
		return 0, 0
	}
	var available uint64
	for _, line := range strings.Split(string(b), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		v, _ := strconv.ParseUint(fields[1], 10, 64)
		switch strings.TrimSuffix(fields[0], ":") {
		case "MemTotal":
			total = v * 1024
		case "MemAvailable":
			available = v * 1024
		}
	}
	if total > available {
		used = total - available
	}
	return total, used
}

func linuxAgentRSS() uint64 {
	b, err := os.ReadFile("/proc/self/statm")
	if err != nil {
		return 0
	}
	fields := strings.Fields(string(b))
	if len(fields) < 2 {
		return 0
	}
	rssPages, err := strconv.ParseUint(fields[1], 10, 64)
	if err != nil {
		return 0
	}
	pageSize := os.Getpagesize()
	if pageSize <= 0 {
		return 0
	}
	pageSizeBytes := uint64(pageSize)
	if rssPages > ^uint64(0)/pageSizeBytes {
		return 0
	}
	return rssPages * pageSizeBytes
}

func sampleLinuxNetwork(previous networkCounterSample, now time.Time) (systemProbe, networkCounterSample) {
	upload, download, ok := linuxNetworkTotalsFromPath("/proc/net/dev")
	if !ok {
		return systemProbe{}, previous
	}
	current := networkCounterSample{UploadBytes: upload, DownloadBytes: download, SampledAt: now, Valid: true}
	result := systemProbe{NetworkTotalUploadBytes: upload, NetworkTotalDownloadBytes: download}
	result.NetworkUploadBPS, result.NetworkDownloadBPS = networkRatesBetween(previous, current)
	return result, current
}

func networkRatesBetween(previous, current networkCounterSample) (uploadBPS, downloadBPS uint64) {
	if !previous.Valid || !current.Valid || !current.SampledAt.After(previous.SampledAt) {
		return 0, 0
	}
	elapsed := current.SampledAt.Sub(previous.SampledAt).Seconds()
	if elapsed <= 0 || elapsed > 10*60 {
		return 0, 0
	}
	if current.UploadBytes >= previous.UploadBytes {
		uploadBPS = uint64(float64(current.UploadBytes-previous.UploadBytes) / elapsed)
	}
	if current.DownloadBytes >= previous.DownloadBytes {
		downloadBPS = uint64(float64(current.DownloadBytes-previous.DownloadBytes) / elapsed)
	}
	return uploadBPS, downloadBPS
}

func linuxNetworkTotalsFromPath(path string) (upload, download uint64, ok bool) {
	// #nosec G304 -- production callers use fixed /proc paths; tests pass temporary local fixtures.
	b, err := os.ReadFile(path)
	if err != nil {
		return 0, 0, false
	}
	return parseLinuxNetworkTotals(string(b))
}

func parseLinuxNetworkTotals(raw string) (upload, download uint64, ok bool) {
	for _, line := range strings.Split(raw, "\n") {
		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 {
			continue
		}
		name := strings.TrimSpace(parts[0])
		if !monitorNetworkInterface(name) {
			continue
		}
		fields := strings.Fields(parts[1])
		if len(fields) < 9 {
			continue
		}
		rx, rxErr := strconv.ParseUint(fields[0], 10, 64)
		tx, txErr := strconv.ParseUint(fields[8], 10, 64)
		if rxErr != nil || txErr != nil {
			continue
		}
		download += rx
		upload += tx
		ok = true
	}
	return upload, download, ok
}

func monitorNetworkInterface(name string) bool {
	name = strings.ToLower(strings.TrimSpace(name))
	if name == "" || name == "lo" {
		return false
	}
	for _, prefix := range []string{"docker", "veth", "cni", "flannel", "virbr", "vmbr", "br-", "podman", "fwbr", "fwpr", "tap", "tun", "wg", "tailscale", "zt", "kube", "ifb"} {
		if strings.HasPrefix(name, prefix) {
			return false
		}
	}
	return true
}

func cpuUsageBetween(previous, current procCPU) (float64, bool) {
	if previous.total == 0 || current.total <= previous.total {
		return 0, false
	}
	// Idle can theoretically go backwards across CPU hotplug / counter resets;
	// treat that as an invalid window instead of producing a huge spike.
	if current.idle < previous.idle {
		return 0, false
	}
	dTotal := current.total - previous.total
	dIdle := current.idle - previous.idle
	if dTotal == 0 {
		return 0, false
	}
	if dIdle > dTotal {
		dIdle = dTotal
	}
	return float64(dTotal-dIdle) * 100 / float64(dTotal), true
}

type procCPU struct{ idle, total uint64 }

func readProcStatCPU() (procCPU, bool) {
	b, err := os.ReadFile("/proc/stat")
	if err != nil {
		return procCPU{}, false
	}
	line := strings.SplitN(string(b), "\n", 2)[0]
	fields := strings.Fields(line)
	if len(fields) < 5 || fields[0] != "cpu" {
		return procCPU{}, false
	}
	var vals []uint64
	for _, f := range fields[1:] {
		v, err := strconv.ParseUint(f, 10, 64)
		if err != nil {
			return procCPU{}, false
		}
		vals = append(vals, v)
	}
	var total uint64
	for _, v := range vals {
		total += v
	}
	idle := vals[3]
	if len(vals) > 4 {
		idle += vals[4]
	}
	return procCPU{idle: idle, total: total}, true
}

func detectDistroInfo() distroInfo {
	info := parseOSRelease(readFileString("/etc/os-release"))
	if info.ID == "" {
		info.ID = "linux"
	}
	if info.Name == "" {
		info.Name = info.ID
	}
	info.Libc = detectLibc(info.ID)
	info.ServiceManager = detectServiceManager()
	info.PackageManager = detectPackageManager(info.ID)
	return info
}

func parseOSRelease(content string) distroInfo {
	vals := map[string]string{}
	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") || !strings.Contains(line, "=") {
			continue
		}
		parts := strings.SplitN(line, "=", 2)
		vals[parts[0]] = unquoteOSRelease(parts[1])
	}
	return distroInfo{ID: vals["ID"], Version: vals["VERSION_ID"], Name: firstNonEmpty(vals["PRETTY_NAME"], vals["NAME"])}
}

func unquoteOSRelease(v string) string {
	v = strings.TrimSpace(v)
	if len(v) >= 2 && ((v[0] == '"' && v[len(v)-1] == '"') || (v[0] == '\'' && v[len(v)-1] == '\'')) {
		v = v[1 : len(v)-1]
	}
	v = strings.ReplaceAll(v, `\"`, `"`)
	return v
}

func detectServiceManager() string {
	if runtime.GOOS != "linux" {
		return "unsupported"
	}
	if _, err := os.Stat("/run/systemd/system"); err == nil {
		if _, err := exec.LookPath("systemctl"); err == nil {
			return "systemd"
		}
	}
	if _, err := exec.LookPath("rc-service"); err == nil {
		return "openrc"
	}
	if _, err := os.Stat("/sbin/openrc-run"); err == nil {
		return "openrc"
	}
	return "unknown"
}

func detectPackageManager(id string) string {
	switch strings.ToLower(id) {
	case "debian", "ubuntu":
		if _, err := exec.LookPath("apt-get"); err == nil {
			return "apt"
		}
	case "alpine":
		if _, err := exec.LookPath("apk"); err == nil {
			return "apk"
		}
	}
	for _, pm := range []struct{ bin, name string }{{"apk", "apk"}, {"apt-get", "apt"}, {"dnf", "dnf"}, {"yum", "yum"}, {"pacman", "pacman"}, {"zypper", "zypper"}} {
		if _, err := exec.LookPath(pm.bin); err == nil {
			return pm.name
		}
	}
	return "unknown"
}

func detectLibc(id string) string {
	if strings.EqualFold(id, "alpine") {
		return "musl"
	}
	maps := readFileString("/proc/self/maps")
	if strings.Contains(maps, "musl") {
		return "musl"
	}
	if strings.Contains(maps, "libc-") || strings.Contains(maps, "libc.so.6") || strings.Contains(maps, "ld-linux") {
		return "glibc"
	}
	if out, err := exec.Command("ldd", "--version").CombinedOutput(); err == nil {
		lower := strings.ToLower(string(out))
		if strings.Contains(lower, "musl") {
			return "musl"
		}
		if strings.Contains(lower, "glibc") || strings.Contains(lower, "gnu libc") {
			return "glibc"
		}
	}
	return "unknown"
}

func readFileString(path string) string {
	// #nosec G304 -- callers use a fixed allowlist of procfs, sysfs, and OS metadata paths.
	b, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return string(b)
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			return strings.TrimSpace(v)
		}
	}
	return ""
}
