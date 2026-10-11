//go:build linux || darwin

package minibox

import (
	"context"
	"encoding/json"
	"github.com/OboardProject/oboard-agent/kernel/oboard-sb/internal/proxydscp"
	box "github.com/sagernet/sing-box"
	"github.com/sagernet/sing/service"
	"net"
	"os"
	"path/filepath"
	"testing"
)

func TestProxyDSCPSOCKSRouteHotSwitch(t *testing.T) {
	port := freeTCPPort(t)
	target, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	bannerService(t, target, "dscp-route-ok")
	config := map[string]any{"inbounds": []any{map[string]any{"type": "socks", "tag": "in-1", "listen": "127.0.0.1", "listen_port": port, "users": []any{map[string]any{"username": "test", "password": "fixture"}}}}, "outbounds": []any{map[string]any{"type": "direct", "tag": "direct"}}, "route": map[string]any{"final": "direct"}}
	raw, _ := json.Marshal(config)
	path := filepath.Join(t.TempDir(), "config.json")
	if err = os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	opts, _, err := LoadConfig(path, nil, HY2Tuning{})
	if err != nil {
		t.Fatal(err)
	}
	ctx := Context(context.Background())
	m, err := proxydscp.New("", nil)
	if err != nil {
		t.Fatal(err)
	}
	service.MustRegister[*proxydscp.Manager](ctx, m)
	b, err := box.New(box.Options{Context: ctx, Options: opts})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = b.Close() })
	if err = b.Start(); err != nil {
		t.Fatal(err)
	}
	for i, enabled := range []bool{false, true, false} {
		if err = m.Configure(proxydscp.Policy{Enabled: enabled, Revision: int64(i + 1)}); err != nil {
			t.Fatal(err)
		}
		before := m.Snapshot().Marked
		banner, err := socksBanner(port, "test", "fixture", "127.0.0.1", target.Addr().(*net.TCPAddr).Port)
		if err != nil || banner != "dscp-route-ok" {
			t.Fatal("proxy route interrupted", banner, err)
		}
		after := m.Snapshot()
		if after.Errors != 0 {
			t.Fatal("socket option failure", after)
		}
		if enabled && after.Marked <= before {
			t.Fatal("enabled dial path did not mark socket")
		}
		if !enabled && after.Marked != before {
			t.Fatal("disabled dial path marked socket")
		}
	}
}
