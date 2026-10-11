package proxydscp

import (
	"context"
	"errors"
	"net"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func TestPolicyPersistenceAndVersionGate(t *testing.T) {
	path := filepath.Join(t.TempDir(), "policy")
	key := []byte("01234567890123456789012345678901")
	m, err := New(path, key)
	if err != nil {
		t.Fatal(err)
	}
	if err = m.Configure(Policy{true, 10}); err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(path)
	if strings.Contains(string(raw), "enabled") {
		t.Fatal("state stored in plaintext")
	}
	m, err = New(path, key)
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range []Policy{{false, 9}, {false, 10}, {true, 0}} {
		if err = m.Configure(p); err == nil {
			t.Fatal("stale policy accepted", p)
		}
	}
	if err = m.Configure(Policy{true, 10}); err != nil {
		t.Fatal(err)
	}
	if m.Snapshot().Revision != 10 || !m.Snapshot().Enabled {
		t.Fatal(m.Snapshot())
	}
	if err = m.Configure(Policy{false, 11}); err != nil {
		t.Fatal(err)
	}
	m, err = New(path, key)
	if err != nil || m.Snapshot().Enabled {
		t.Fatal("disable not durable", err)
	}
}
func TestFailedPolicySaveLeavesCurrentState(t *testing.T) {
	m, _ := New("", nil)
	if err := m.Configure(Policy{true, 1}); err != nil {
		t.Fatal(err)
	}
	m.path = filepath.Join(t.TempDir(), "missing", "state")
	if err := m.Configure(Policy{false, 2}); err == nil {
		t.Fatal("expected save failure")
	}
	if !m.Snapshot().Enabled || m.Snapshot().Revision != 1 {
		t.Fatal("failed write changed running policy")
	}
}
func TestPolicyHTTPRejectsUnknownAndTrailingData(t *testing.T) {
	m, _ := New("", nil)
	for _, body := range []string{`{"enabled":true,"revision":1,"command":"anything"}`, `{"enabled":true,"revision":1} {}`} {
		w := httptest.NewRecorder()
		m.Handler(w, httptest.NewRequest("POST", "/proxy/dscp", strings.NewReader(body)))
		if w.Code == 200 {
			t.Fatal("invalid input accepted")
		}
	}
	if m.Snapshot().Revision != 0 {
		t.Fatal("invalid request changed state")
	}
}
func BenchmarkDisabledControl(b *testing.B) {
	m, _ := New("", nil)
	b.ReportAllocs()
	for b.Loop() {
		if err := m.Control("tcp4", "127.0.0.1", nil); err != nil {
			b.Fatal(err)
		}
	}
}
func BenchmarkSocketCreation(b *testing.B) {
	for _, enabled := range []bool{false, true} {
		name := "off"
		if enabled {
			name = "ef46"
		}
		b.Run(name, func(b *testing.B) {
			m, _ := New("", nil)
			_ = m.Configure(Policy{enabled, 1})
			lc := net.ListenConfig{Control: m.Control}
			ctx := context.Background()
			b.ReportAllocs()
			for b.Loop() {
				c, err := lc.ListenPacket(ctx, "udp4", "127.0.0.1:0")
				if err != nil {
					b.Fatal(err)
				}
				m.Track(c)
				c.Close()
			}
		})
	}
}

func TestMPTCPLimitationIsNotAFullSuccessOrSocketFailure(t *testing.T) {
	m, _ := New("", nil)
	if err := m.Configure(Policy{Enabled: true, Revision: 1}); err != nil {
		t.Fatal(err)
	}
	m.recordSocketResult(errIPv6MPTCPUnsupported, true)
	m.recordSocketResult(nil, true)
	report := m.Snapshot()
	if report.Errors != 0 || report.Error != "" || report.Marked != 1 || !slices.Contains(report.Excluded, "ipv6-mptcp") {
		t.Fatal(report)
	}
	m.recordSocketResult(errors.New("real failure"), true)
	report = m.Snapshot()
	if report.Errors != 1 || report.Error != "socket_mark_failed" {
		t.Fatal("real failure hidden", report)
	}
	if err := m.Configure(Policy{Enabled: false, Revision: 2}); err != nil {
		t.Fatal(err)
	}
	report = m.Snapshot()
	if report.Errors != 0 || slices.Contains(report.Excluded, "ipv6-mptcp") {
		t.Fatal("old observation retained after reapply", report)
	}
}
