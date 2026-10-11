package proxydscp

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"weak"

	"github.com/OboardProject/oboard-agent/kernel/oboard-sb/internal/stealth"
	"github.com/sagernet/sing/service"
)

const Value = 46
const Capability = "proxy_dscp_socket_v1"

var errIPv6MPTCPUnsupported = errors.New("IPv6 MPTCP DSCP is unsupported")

type Policy struct {
	Enabled  bool  `json:"enabled"`
	Revision int64 `json:"revision"`
}
type Report struct {
	Policy
	State    string   `json:"state"`
	Value    int      `json:"value"`
	Marked   uint64   `json:"marked_sockets"`
	Errors   uint64   `json:"socket_errors"`
	Error    string   `json:"error,omitempty"`
	Excluded []string `json:"excluded"`
}
type Manager struct {
	mu                   sync.Mutex
	enabled              atomic.Bool
	policy               Policy
	marked               atomic.Uint64
	errors               atomic.Uint64
	ipv6MPTCPUnsupported atomic.Bool
	udp                  map[weak.Pointer[net.UDPConn]]struct{}
	tcp                  map[weak.Pointer[net.TCPListener]]struct{}
	nextSweep            int
	loadError            string
	path                 string
	key                  []byte
}

func New(path string, key []byte) (*Manager, error) {
	m := &Manager{path: path, key: key, udp: make(map[weak.Pointer[net.UDPConn]]struct{}), tcp: make(map[weak.Pointer[net.TCPListener]]struct{})}
	fail := func(err error) (*Manager, error) {
		m.policy = Policy{}
		m.loadError = "policy_state_unreadable"
		return m, err
	}
	if path != "" {
		raw, err := os.ReadFile(path)
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			return fail(err)
		}
		if err == nil {
			if len(key) > 0 {
				raw, err = stealth.Decrypt(key, raw)
				if err != nil {
					return fail(err)
				}
			}
			if err = json.Unmarshal(raw, &m.policy); err != nil {
				return fail(err)
			}
			if m.policy.Revision <= 0 {
				return fail(errors.New("invalid DSCP revision"))
			}
		}
	}
	m.enabled.Store(m.policy.Enabled)
	return m, nil
}
func From(ctx context.Context) *Manager { return service.FromContext[*Manager](ctx) }
func (m *Manager) Control(network, address string, conn syscall.RawConn) error {
	if m != nil && m.enabled.Load() && strings.HasPrefix(network, "tcp") {
		m.apply(conn, true)
	}
	return nil
}
func (m *Manager) apply(conn syscall.RawConn, enabled bool) {
	m.recordSocketResult(setSocket(conn, enabled), enabled)
}
func (m *Manager) recordSocketResult(err error, enabled bool) {
	if err != nil {
		if errors.Is(err, errIPv6MPTCPUnsupported) {
			m.ipv6MPTCPUnsupported.Store(true)
			return
		}
		if errors.Is(err, net.ErrClosed) {
			return
		}
		m.errors.Add(1)
		// Socket errors are aggregated; no logging on the connection path.
	} else if enabled {
		m.marked.Add(1)
	}
}
func (m *Manager) Track(value any) {
	switch value.(type) {
	case *net.UDPConn, *net.TCPListener:
	default:
		return
	}
	if m == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	switch v := value.(type) {
	case *net.UDPConn:
		m.udp[weak.Make(v)] = struct{}{}
		if len(m.udp) >= max(m.nextSweep, 256) {
			for p := range m.udp {
				if p.Value() == nil {
					delete(m.udp, p)
				}
			}
			m.nextSweep = max(256, len(m.udp)*2)
		}
		if m.enabled.Load() {
			if raw, e := v.SyscallConn(); e == nil {
				m.apply(raw, true)
			}
		}
	case *net.TCPListener:
		m.tcp[weak.Make(v)] = struct{}{}
		if raw, e := v.SyscallConn(); e == nil {
			m.apply(raw, m.enabled.Load())
		}
	}
}
func (m *Manager) Configure(p Policy) error {
	if p.Revision <= 0 {
		return errors.New("positive DSCP revision required")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if p.Revision < m.policy.Revision || (p.Revision == m.policy.Revision && p.Enabled != m.policy.Enabled) {
		return errors.New("stale or conflicting DSCP revision")
	}
	if m.path != "" && p != m.policy {
		raw, _ := json.Marshal(p)
		if len(m.key) > 0 {
			var err error
			raw, err = stealth.Encrypt(m.key, raw)
			if err != nil {
				return err
			}
		}
		file, err := os.CreateTemp(filepath.Dir(m.path), ".proxy-dscp-*")
		if err != nil {
			return err
		}
		defer os.Remove(file.Name())
		if _, err = file.Write(raw); err != nil {
			file.Close()
			return err
		}
		if err = file.Sync(); err != nil {
			file.Close()
			return err
		}
		if err = file.Close(); err != nil {
			return err
		}
		if err = os.Rename(file.Name(), m.path); err != nil {
			return err
		}

	}
	m.loadError = ""
	m.policy = p
	m.enabled.Store(p.Enabled)
	m.errors.Store(0)
	m.ipv6MPTCPUnsupported.Store(false)
	for ptr := range m.udp {
		v := ptr.Value()
		if v == nil {
			delete(m.udp, ptr)
			continue
		}
		if raw, e := v.SyscallConn(); e == nil {
			m.apply(raw, p.Enabled)
		}
	}
	for ptr := range m.tcp {
		v := ptr.Value()
		if v == nil {
			delete(m.tcp, ptr)
			continue
		}
		if raw, e := v.SyscallConn(); e == nil {
			m.apply(raw, p.Enabled)
		}
	}
	return nil
}
func (m *Manager) Snapshot() Report {
	m.mu.Lock()
	defer m.mu.Unlock()
	state := "disabled"
	if m.policy.Enabled {
		state = "partial"
	}
	if !supported {
		state = "unsupported"
	}
	errText := m.loadError
	if errText != "" {
		state = "partial"
	}
	if m.errors.Load() > 0 {
		state = "partial"
		errText = "socket_mark_failed"
	}
	if !supported {
		state = "unsupported"
	}
	excluded := []string{"hysteria2", "wireguard", "ssh", "realm", "route-direct"}
	if m.ipv6MPTCPUnsupported.Load() {
		excluded = append(excluded, "ipv6-mptcp")
	}
	return Report{Policy: m.policy, State: state, Value: Value, Marked: m.marked.Load(), Errors: m.errors.Load(), Error: errText, Excluded: excluded}
}
func (m *Manager) Handler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		var p Policy
		d := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1024))
		d.DisallowUnknownFields()
		if err := d.Decode(&p); err != nil {
			http.Error(w, "invalid DSCP policy", 400)
			return
		}
		if d.Decode(new(any)) != io.EOF {
			http.Error(w, "invalid trailing policy data", 400)
			return
		}
		if err := m.Configure(p); err != nil {
			http.Error(w, err.Error(), 409)
			return
		}
	} else if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", 405)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(m.Snapshot())
}
