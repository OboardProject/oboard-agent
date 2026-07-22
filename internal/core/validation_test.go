package core

import (
	"strings"
	"testing"

	"github.com/OboardProject/oboard-agent/internal/model"
)

func TestValidateSafeHostAndInterface(t *testing.T) {
	for _, host := range []string{"203.0.113.10", "example.com", "2001:db8::1", "[2001:db8::1]"} {
		if err := ValidateSafeHost(host); err != nil {
			t.Fatalf("safe host %q rejected: %v", host, err)
		}
	}
	for _, host := range []string{"-oProxyCommand=evil", "user@host", "https://evil", "host/path", "host port"} {
		if err := ValidateSafeHost(host); err == nil {
			t.Fatalf("unsafe host %q accepted", host)
		}
	}
	if err := ValidateNetworkInterfaceName("eth0.100"); err != nil {
		t.Fatal(err)
	}
	if err := ValidateNetworkInterfaceName("eth0;id"); err == nil {
		t.Fatal("unsafe interface name accepted")
	}
}

func TestValidateDNSCandidatesRejectsPrivateAddress(t *testing.T) {
	err := ValidateDNSCandidates([]model.DNSCandidate{{Transport: model.DNSTransportDoH, Server: "127.0.0.1", Port: 443, Path: "/dns-query"}})
	if err == nil || !strings.Contains(err.Error(), "private or loopback") {
		t.Fatalf("error = %v", err)
	}
}

func TestValidateTunnelConfigRejectsUnsafeValues(t *testing.T) {
	err := ValidateTunnelConfig(model.Tunnel{Type: model.TunnelTypeSSH, ConfigJSON: `{"user":"root","extra_args":["-o","ProxyCommand=sh -c id"]}`})
	if err == nil || !strings.Contains(err.Error(), "extra_args") {
		t.Fatalf("expected extra_args validation error, got %v", err)
	}
	err = ValidateTunnelConfig(model.Tunnel{Type: model.TunnelTypeWireGuard, ConfigJSON: `{"private_key":"k","peer_public_key":"p","allowed_ips":["not-cidr"]}`})
	if err == nil || !strings.Contains(err.Error(), "not an IP/CIDR") {
		t.Fatalf("expected CIDR validation error, got %v", err)
	}
}

func FuzzValidateTunnelConfig(f *testing.F) {
	f.Add("ssh", `{"user":"oboard"}`)
	f.Add("wireguard", `{"private_key":"k","peer_public_key":"p","allowed_ips":["10.0.0.0/24"]}`)
	f.Fuzz(func(t *testing.T, tunnelType, configJSON string) {
		if len(configJSON) > 1<<16 {
			t.Skip()
		}
		_ = ValidateTunnelConfig(model.Tunnel{Type: model.TunnelType(tunnelType), ConfigJSON: configJSON})
	})
}
