package minibox

import (
	"context"
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type SocketGovernorSnapshot struct {
	Enabled           bool   `json:"enabled"`
	Mode              string `json:"mode,omitempty"`
	ActiveConnections int64  `json:"active_connections"`
	PeakCap           int    `json:"peak_cap_bytes,omitempty"`
	BalancedCap       int    `json:"balanced_cap_bytes,omitempty"`
	SafeCap           int    `json:"safe_cap_bytes,omitempty"`
	BalancedWatermark int64  `json:"balanced_watermark,omitempty"`
	HighWatermark     int64  `json:"high_watermark,omitempty"`
	CurrentCap        int    `json:"current_cap_bytes,omitempty"`
	LastChangedAt     string `json:"last_changed_at,omitempty"`
	Error             string `json:"error,omitempty"`
}

type socketGovernorProfile struct {
	peakCap           int
	balancedCap       int
	safeCap           int
	balancedWatermark int64
	highWatermark     int64
	checkInterval     time.Duration
}

type SocketBufferGovernor struct {
	mu            sync.Mutex
	enabled       bool
	profile       socketGovernorProfile
	pressureBytes uint64
	active        atomic.Int64
	mode          string
	currentCap    int
	stableSince   time.Time
	lastChanged   time.Time
	lastError     string
}

func StartAdaptiveSocketGovernor(ctx context.Context, tuning RuntimeTuning) *SocketBufferGovernor {
	profile := adaptiveSocketGovernorProfile(tuning.EffectiveMemoryBytes)
	governor := &SocketBufferGovernor{
		enabled:       profile.peakCap > 0 && profile.balancedCap > 0 && profile.safeCap > 0,
		profile:       profile,
		pressureBytes: memoryReclaimThreshold(tuning),
	}
	if !governor.enabled {
		return governor
	}
	governor.setMode("peak", profile.peakCap)
	go governor.run(ctx)
	return governor
}

// adaptiveSocketGovernorProfile chooses TCP auto-tune ceilings.
//
// Design goals:
//   - peak: single-user / few-flow BDP-friendly caps for high single-stream throughput
//   - balanced: multi-tab / multi-user moderate concurrency without ballooning RSS
//   - safe: many concurrent sockets; hard-cap auto-tune so page cache does not OOM
//
// Watermarks count billable tracked TCP connections only (see RateLimitTracker).
// A typical browser opens several parallel TCP streams, so balanced/high watermarks
// are intentionally above "one user one connection".
func adaptiveSocketGovernorProfile(memory uint64) socketGovernorProfile {
	switch {
	case memory == 0:
		return socketGovernorProfile{}
	case memory <= 96<<20:
		// mini-sb-agent baseline: ~1.6 MiB max keeps multi-conn NAT boxes alive.
		return socketGovernorProfile{peakCap: 1677722, balancedCap: 512 << 10, safeCap: 128 << 10, balancedWatermark: 3, highWatermark: 6, checkInterval: 250 * time.Millisecond}
	case memory <= 128<<20:
		// 128 MiB class: peak matches mini-sb 1.6 MiB (single fat flow is still
		// fine via auto-tune). Balanced/safe drop earlier under multi-user so the
		// larger Go soft-limit and socket pages can coexist without OOM.
		return socketGovernorProfile{peakCap: 1677722, balancedCap: 768 << 10, safeCap: 256 << 10, balancedWatermark: 6, highWatermark: 12, checkInterval: 250 * time.Millisecond}
	case memory <= 192<<20:
		return socketGovernorProfile{peakCap: 6 << 20, balancedCap: 2 << 20, safeCap: 512 << 10, balancedWatermark: 8, highWatermark: 20, checkInterval: 500 * time.Millisecond}
	case memory <= 256<<20:
		return socketGovernorProfile{peakCap: 8 << 20, balancedCap: 2 << 20, safeCap: 1 << 20, balancedWatermark: 12, highWatermark: 32, checkInterval: 500 * time.Millisecond}
	case memory < 512<<20:
		return socketGovernorProfile{peakCap: 12 << 20, balancedCap: 4 << 20, safeCap: 1677722, balancedWatermark: 20, highWatermark: 64, checkInterval: time.Second}
	case memory < 1<<30:
		// Smallest "large" hosts still benefit from a multi-user safe ceiling.
		// Above 1 GiB, leave Linux auto-tune alone (peak disabled).
		return socketGovernorProfile{peakCap: 16 << 20, balancedCap: 4 << 20, safeCap: 2 << 20, balancedWatermark: 32, highWatermark: 128, checkInterval: time.Second}
	default:
		return socketGovernorProfile{}
	}
}

func (g *SocketBufferGovernor) ObserveConnections(active int64) {
	if g == nil || !g.enabled {
		return
	}
	if active < 0 {
		active = 0
	}
	g.active.Store(active)
	if active >= g.profile.highWatermark {
		g.setMode("safe", g.profile.safeCap)
	} else if active >= g.profile.balancedWatermark {
		g.setMode("balanced", g.profile.balancedCap)
	}
}

func (g *SocketBufferGovernor) run(ctx context.Context) {
	ticker := time.NewTicker(g.profile.checkInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-ticker.C:
			g.evaluate(now, currentCgroupMemory())
		}
	}
}

func (g *SocketBufferGovernor) evaluate(now time.Time, currentMemory uint64) {
	active := g.active.Load()
	pressured := g.pressureBytes > 0 && currentMemory >= g.pressureBytes
	if active >= g.profile.highWatermark || pressured {
		g.mu.Lock()
		g.stableSince = time.Time{}
		g.mu.Unlock()
		g.setMode("safe", g.profile.safeCap)
		return
	}
	if g.pressureBytes > 0 && currentMemory > g.pressureBytes*95/100 {
		g.mu.Lock()
		g.stableSince = time.Time{}
		g.mu.Unlock()
		return
	}

	g.mu.Lock()
	targetMode, targetCap := "peak", g.profile.peakCap
	if active >= g.profile.balancedWatermark {
		targetMode, targetCap = "balanced", g.profile.balancedCap
	}
	if g.mode == targetMode && g.currentCap == targetCap {
		g.mu.Unlock()
		return
	}
	if g.stableSince.IsZero() {
		g.stableSince = now
		g.mu.Unlock()
		return
	}
	ready := now.Sub(g.stableSince) >= 10*time.Second
	g.mu.Unlock()
	if ready {
		g.setMode(targetMode, targetCap)
	}
}

func (g *SocketBufferGovernor) setMode(mode string, capBytes int) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if !g.enabled || (g.mode == mode && g.currentCap == capBytes) {
		return
	}
	if err := setLinuxTCPBufferCap(capBytes); err != nil {
		g.lastError = err.Error()
		log.Printf("kernel socket governor: %v", err)
		return
	}
	g.mode = mode
	g.currentCap = capBytes
	g.lastChanged = time.Now().UTC()
	g.lastError = ""
	if mode == "peak" {
		g.stableSince = time.Time{}
	}
	log.Printf("kernel socket governor mode=%s cap=%d active=%d", mode, capBytes, g.active.Load())
}

func setLinuxTCPBufferCap(capBytes int) error {
	if capBytes <= 0 {
		return nil
	}
	for _, path := range []string{"/proc/sys/net/ipv4/tcp_rmem", "/proc/sys/net/ipv4/tcp_wmem"} {
		// #nosec G304 -- paths are fixed procfs socket-tuning controls.
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		fields := strings.Fields(string(data))
		if len(fields) != 3 {
			return fmt.Errorf("invalid TCP buffer values in %s", path)
		}
		values := make([]int, 3)
		for index, field := range fields {
			values[index], err = strconv.Atoi(field)
			if err != nil || values[index] <= 0 {
				return fmt.Errorf("invalid TCP buffer value %q in %s", field, path)
			}
		}
		values[2] = capBytes
		if values[1] > values[2] {
			values[1] = values[2]
		}
		next := fmt.Sprintf("%d %d %d", values[0], values[1], values[2])
		if strings.Join(fields, " ") == next {
			continue
		}
		if err := os.WriteFile(path, []byte(next), 0o600); err != nil {
			return err
		}
	}
	return nil
}

func (g *SocketBufferGovernor) Snapshot() SocketGovernorSnapshot {
	if g == nil {
		return SocketGovernorSnapshot{}
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	snapshot := SocketGovernorSnapshot{
		Enabled:           g.enabled,
		Mode:              g.mode,
		ActiveConnections: g.active.Load(),
		PeakCap:           g.profile.peakCap,
		BalancedCap:       g.profile.balancedCap,
		SafeCap:           g.profile.safeCap,
		BalancedWatermark: g.profile.balancedWatermark,
		HighWatermark:     g.profile.highWatermark,
		CurrentCap:        g.currentCap,
		Error:             g.lastError,
	}
	if !g.lastChanged.IsZero() {
		snapshot.LastChangedAt = g.lastChanged.Format(time.RFC3339Nano)
	}
	return snapshot
}
