package agent

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/OboardProject/oboard-agent/internal/model"
)

func TestWARPRegistrationClientIsIndependent(t *testing.T) {
	t.Setenv("HTTPS_PROXY", "http://127.0.0.1:1")
	base := &http.Client{Transport: &http.Transport{Proxy: http.ProxyFromEnvironment, TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}}
	client, err := boundWARPRegistrationClient(context.Background(), base, warpRegistrationBinding{}, model.WARPRequestPlan{})
	if err != nil {
		t.Fatal(err)
	}
	defer client.CloseIdleConnections()
	transport := client.Transport.(*http.Transport)
	if transport.Proxy != nil || transport.TLSClientConfig != nil && transport.TLSClientConfig.InsecureSkipVerify {
		t.Fatal("registration inherited proxy or insecure TLS")
	}
	if client.CheckRedirect == nil || client.CheckRedirect(nil, nil) == nil {
		t.Fatal("registration allowed redirects")
	}
	if base.Transport.(*http.Transport).Proxy == nil {
		t.Fatal("shared Controller client was changed")
	}
}

func TestWARPUnderlayRejectsLiteralPeerFamilyAndPrefixes(t *testing.T) {
	endpoint := map[string]any{"peers": []map[string]any{{"address": "192.0.2.1"}}}
	dc := &model.DialConstraint{Mode: "interface", InterfaceName: "he-ipv6", Family: "ipv6_only"}
	if err := applyDialConstraintToEndpoint(endpoint, dc); err == nil {
		t.Fatal("IPv4 literal peer accepted")
	}
	dc.SourceAddress = "2001:db8::/64"
	if err := applyDialConstraintToEndpoint(map[string]any{}, dc); err == nil {
		t.Fatal("source prefix accepted as an exact source address")
	}
}

func TestWARPExplicitFamilyIsHardConstraint(t *testing.T) {
	interfaces := []model.NetworkInterfaceInfo{{Name: "he-ipv6", Up: true, Addresses: []string{"192.0.2.2/24", "2001:db8::2/64"}}}
	binding := warpBindingFromDialConstraint(&model.DialConstraint{Mode: "interface", InterfaceName: "he-ipv6", Family: "ipv6_only"})
	_, address, err := selectWARPRegistrationAddress(interfaces, binding, model.IPStackIPv4Only)
	if err != nil || !address.Is6() {
		t.Fatalf("explicit IPv6 must override server IPv4 preference: address=%v err=%v", address, err)
	}
	interfaces[0].Addresses = []string{"192.0.2.2/24"}
	if _, _, err := selectWARPRegistrationAddress(interfaces, binding, model.IPStackIPv4Only); err == nil {
		t.Fatal("IPv6-only binding fell back to IPv4")
	}
}

func TestWARPRegistrationRejectsConflictingProfileAndBranch(t *testing.T) {
	_, err := mergeWARPRegistrationBinding(warpRegistrationBinding{InterfaceName: "he-ipv6"}, &model.DialConstraint{Mode: "interface", InterfaceName: "eth0", Family: "ipv4_only"})
	if err == nil {
		t.Fatal("profile silently overrode branch binding")
	}
}

func TestWARPCachedIdentityRebindsAndClears(t *testing.T) {
	runner := New(Config{StateDir: t.TempDir()})
	runner.persistReadyWARPReport(model.WARPConfigReport{ServerID: 1, ProfileID: 1}, map[string]any{"type": "wireguard", "tag": "warp-1", "private_key": "test-identity", "bind_interface": "old", "inet4_bind_address": "192.0.2.1", "mtu": 1280})
	plan := model.WARPRequestPlan{ServerID: 1, ProfileID: 1, MTU: 1200, Underlay: &model.DialConstraint{Mode: "interface", InterfaceName: "he-ipv6", SourceAddress: "2001:db8::2", Family: "ipv6_only"}}
	report, err := runner.loadPersistedWARPConfig(plan)
	if err != nil {
		t.Fatal(err)
	}
	var endpoint map[string]any
	if err := json.Unmarshal([]byte(report.ConfigJSON), &endpoint); err != nil {
		t.Fatal(err)
	}
	if endpoint["private_key"] != "test-identity" || endpoint["bind_interface"] != "he-ipv6" || endpoint["inet6_bind_address"] != "2001:db8::2" || endpoint["inet4_bind_address"] != nil || endpoint["mtu"] != float64(1200) {
		t.Fatal("cached identity did not receive current runtime binding and MTU")
	}
	plan.Underlay = &model.DialConstraint{Mode: "auto"}
	report, err = runner.loadPersistedWARPConfig(plan)
	if err != nil {
		t.Fatal(err)
	}
	endpoint = nil
	if err := json.Unmarshal([]byte(report.ConfigJSON), &endpoint); err != nil {
		t.Fatal(err)
	}
	if endpoint["bind_interface"] != nil || endpoint["inet6_bind_address"] != nil || endpoint["inet4_bind_address"] != nil {
		t.Fatal("automatic binding retained old interface/source")
	}
}
