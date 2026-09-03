package agent

import (
	"encoding/json"
	"fmt"
	"os"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/OboardProject/oboard-agent/internal/logging"
)

const (
	// Static bootstrap caps applied once at Agent start. The kernel socket
	// governor then adapts peak/balanced/safe ceilings under live load. Keep
	// these aligned with adaptiveSocketGovernorProfile peak caps.
	// 96/128 MiB match mini-sb-agent's ~1.6 MiB max; larger classes open up.
	tinyMemoryTCPBufferCap    = 1677722
	microMemoryTCPBufferCap   = 1677722
	compactMemoryTCPBufferCap = 6 << 20
	lowMemoryTCPBufferCap     = 8 << 20
	smallMemoryTCPBufferCap   = 12 << 20
)

type socketTuningStatus struct {
	State                string    `json:"state"`
	MemoryClass          string    `json:"memory_class"`
	EffectiveMemoryBytes uint64    `json:"effective_memory_bytes"`
	MaxBufferBytes       int       `json:"max_buffer_bytes,omitempty"`
	TCPRMemBefore        string    `json:"tcp_rmem_before,omitempty"`
	TCPRMemAfter         string    `json:"tcp_rmem_after,omitempty"`
	TCPWMemBefore        string    `json:"tcp_wmem_before,omitempty"`
	TCPWMemAfter         string    `json:"tcp_wmem_after,omitempty"`
	AppliedAt            time.Time `json:"applied_at"`
	Error                string    `json:"error,omitempty"`
	RequiresHostTuning   bool      `json:"requires_host_tuning,omitempty"`
}

func desiredTCPBufferCap(memory uint64) int {
	// Mirror kernel governor: still manage 512 MiB–1 GiB hosts; leave Linux
	// auto-tune alone above 1 GiB.
	if memory == 0 || memory >= 1<<30 {
		return 0
	}
	if memory <= 96<<20 {
		return tinyMemoryTCPBufferCap
	}
	if memory <= 128<<20 {
		return microMemoryTCPBufferCap
	}
	if memory <= 192<<20 {
		return compactMemoryTCPBufferCap
	}
	if memory <= 256<<20 {
		return lowMemoryTCPBufferCap
	}
	if memory < 512<<20 {
		return smallMemoryTCPBufferCap
	}
	return 16 << 20
}

func socketMemoryClass(memory uint64) string {
	switch {
	case memory == 0:
		return "unknown"
	case memory <= 128<<20:
		return "micro"
	case memory <= 256<<20:
		return "compact"
	case memory < 512<<20:
		return "small"
	default:
		return "standard"
	}
}

func capTCPBufferTriplet(raw string, capBytes int) (string, bool, error) {
	fields := strings.Fields(raw)
	if len(fields) != 3 {
		return "", false, fmt.Errorf("expected three TCP buffer values, got %q", strings.TrimSpace(raw))
	}
	values := make([]int, 3)
	for i, field := range fields {
		value, err := strconv.Atoi(field)
		if err != nil || value <= 0 {
			return "", false, fmt.Errorf("invalid TCP buffer value %q", field)
		}
		values[i] = value
	}
	if capBytes <= 0 || values[2] <= capBytes {
		return strings.Join(fields, " "), false, nil
	}
	values[2] = capBytes
	if values[1] > values[2] {
		values[1] = values[2]
	}
	return fmt.Sprintf("%d %d %d", values[0], values[1], values[2]), true, nil
}

func (r *Runner) applyLowMemorySocketTuning() {
	status := socketTuningStatus{EffectiveMemoryBytes: r.resources.EffectiveMemoryBytes, MemoryClass: socketMemoryClass(r.resources.EffectiveMemoryBytes), AppliedAt: time.Now().UTC()}
	capBytes := desiredTCPBufferCap(r.resources.EffectiveMemoryBytes)
	status.MaxBufferBytes = capBytes
	if runtime.GOOS != "linux" || capBytes == 0 {
		status.State = "not_required"
		r.writeSocketTuningStatus(status)
		return
	}
	type target struct {
		path   string
		before *string
		after  *string
	}
	targets := []target{
		{"/proc/sys/net/ipv4/tcp_rmem", &status.TCPRMemBefore, &status.TCPRMemAfter},
		{"/proc/sys/net/ipv4/tcp_wmem", &status.TCPWMemBefore, &status.TCPWMemAfter},
	}
	applied := false
	for _, item := range targets {
		data, err := os.ReadFile(item.path)
		if err != nil {
			status.State, status.Error = "unavailable", err.Error()
			status.RequiresHostTuning = true
			r.writeSocketTuningStatus(status)
			return
		}
		*item.before = strings.TrimSpace(string(data))
		next, changed, err := capTCPBufferTriplet(*item.before, capBytes)
		if err != nil {
			status.State, status.Error = "invalid", err.Error()
			r.writeSocketTuningStatus(status)
			return
		}
		*item.after = next
		if !changed {
			continue
		}
		if err := os.WriteFile(item.path, []byte(next), 0o600); err != nil {
			status.State = "permission_denied"
			status.Error = err.Error()
			status.RequiresHostTuning = true
			logging.Warnf("socket tuning: cannot cap %s; configure it on the host: %v", item.path, err)
			r.writeSocketTuningStatus(status)
			return
		}
		applied = true
	}
	if applied {
		status.State = "applied"
		logging.Infof("socket tuning: capped TCP auto-tuning buffers at %d bytes for low-memory node", capBytes)
	} else {
		status.State = "already_safe"
	}
	r.writeSocketTuningStatus(status)
}

func (r *Runner) writeSocketTuningStatus(status socketTuningStatus) {
	data, err := json.MarshalIndent(status, "", "  ")
	if err == nil {
		_ = atomicWriteFile(r.stateDir()+"/socket-tuning.json", data, 0o600)
	}
}
