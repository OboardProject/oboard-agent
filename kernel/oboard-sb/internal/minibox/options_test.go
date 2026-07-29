package minibox

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/sagernet/sing-box/option"
)

func TestLoadConfigStripsRuntimeMetadata(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	raw := `{
		"_oboard":{"rate_limits":{"users":{"alice":{"speed_limit_mbps":20}}}},
		"log":{"level":"info"},
		"outbounds":[{"type":"direct","tag":"direct"}],
		"route":{"final":"direct"}
	}`
	if err := os.WriteFile(path, []byte(raw), 0o600); err != nil {
		t.Fatal(err)
	}
	opts, metadata, err := LoadConfig(path, HY2Tuning{})
	if err != nil {
		t.Fatal(err)
	}
	if opts.Log == nil || opts.Log.Level != "info" {
		t.Fatalf("log options not loaded: %#v", opts.Log)
	}
	if got := metadata.RateLimits.Users["alice"].SpeedLimitMbps; got != 20 {
		t.Fatalf("speed limit = %d, want 20", got)
	}
}

func TestLoadConfigAcceptsManagedWireGuardEndpoint(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	raw := `{
		"endpoints":[{
			"type":"wireguard",
			"tag":"warp-1",
			"address":["172.16.0.2/32"],
			"private_key":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
			"peers":[{
				"address":"engage.cloudflareclient.com",
				"port":2408,
				"public_key":"bmXOC+F1sQvdD4mp8yt3l7wY6/3mpYBvn04zP65yzM8=",
				"allowed_ips":["0.0.0.0/0","::/0"]
			}]
		}],
		"outbounds":[{"type":"direct","tag":"direct"}],
		"route":{"final":"warp-1"}
	}`
	if err := os.WriteFile(path, []byte(raw), 0o600); err != nil {
		t.Fatal(err)
	}
	opts, _, err := LoadConfig(path, HY2Tuning{})
	if err != nil {
		t.Fatal(err)
	}
	if len(opts.Endpoints) != 1 || opts.Endpoints[0].Type != "wireguard" || opts.Endpoints[0].Tag != "warp-1" {
		t.Fatalf("wireguard endpoint not loaded: %#v", opts.Endpoints)
	}
}

func TestLoadConfigAcceptsShadowsocksUoTContract(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	raw := `{
		"inbounds":[{
			"type":"shadowsocks",
			"tag":"ss-in",
			"listen":"0.0.0.0",
			"listen_port":8388,
			"network":"tcp",
			"method":"chacha20-ietf-poly1305",
			"password":"server-pass"
		}],
		"outbounds":[{
			"type":"shadowsocks",
			"tag":"ss-out",
			"server":"127.0.0.1",
			"server_port":8388,
			"method":"chacha20-ietf-poly1305",
			"password":"server-pass",
			"udp_over_tcp":{"enabled":true}
		}],
		"route":{"final":"ss-out"}
	}`
	if err := os.WriteFile(path, []byte(raw), 0o600); err != nil {
		t.Fatal(err)
	}
	opts, _, err := LoadConfig(path, HY2Tuning{})
	if err != nil {
		t.Fatal(err)
	}
	inbound, ok := opts.Inbounds[0].Options.(*option.ShadowsocksInboundOptions)
	if !ok || len(inbound.Network.Build()) != 1 || inbound.Network.Build()[0] != "tcp" {
		t.Fatalf("shadowsocks inbound is not TCP-only: %#v", opts.Inbounds[0].Options)
	}
	outbound, ok := opts.Outbounds[0].Options.(*option.ShadowsocksOutboundOptions)
	if !ok || outbound.UDPOverTCP == nil || !outbound.UDPOverTCP.Enabled {
		t.Fatalf("shadowsocks outbound UoT was not decoded: %#v", opts.Outbounds[0].Options)
	}
}
