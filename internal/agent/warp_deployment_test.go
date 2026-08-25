package agent

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/OboardProject/oboard-agent/internal/model"
)

func TestResolveDeploymentWARPConfigReplacesControllerPlaceholder(t *testing.T) {
	config := `{"endpoints":[{"type":"wireguard","tag":"warp-7","_oboard_warp_pending":7},{"type":"wireguard","tag":"routing-rule-11-warp-7","_oboard_warp_pending":7,"bind_interface":"eth1","domain_resolver":{"server":"bootstrap-primary","strategy":"ipv6_only"}},{"type":"wireguard","tag":"routing-rule-12-warp-7","_oboard_warp_pending":7,"detour":"source-prefix-example","domain_resolver":{"server":"bootstrap-primary","strategy":"ipv6_only"}}],"route":{"rules":[{"action":"route","outbound":"warp-7"}]}}`
	plan := model.WARPRequestPlan{ProfileID: 7, OutboundTag: "warp-7", DNSStrategy: "prefer_ipv4"}
	report := model.WARPConfigReport{ProfileID: 7, Status: model.WARPStatusReady, ConfigJSON: `{"type":"wireguard","private_key":"private","address":["172.16.0.2/32"],"peers":[],"domain_resolver":{"server":"bootstrap","strategy":"prefer_ipv6"}}`}
	resolved, err := resolveDeploymentWARPConfig(config, []model.WARPRequestPlan{plan}, map[int64]model.WARPConfigReport{7: report})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(resolved, "_oboard_warp_pending") {
		t.Fatalf("pending marker survived resolution: %s", resolved)
	}
	var root map[string]any
	if err := json.Unmarshal([]byte(resolved), &root); err != nil {
		t.Fatal(err)
	}
	endpoints := root["endpoints"].([]any)
	if len(endpoints) != 3 {
		t.Fatalf("resolved WARP endpoints = %#v", endpoints)
	}
	endpoint := endpoints[0].(map[string]any)
	if endpoint["tag"] != "warp-7" || endpoint["private_key"] != "private" {
		t.Fatalf("resolved WARP endpoint = %#v", endpoint)
	}
	interfaceBound := endpoints[1].(map[string]any)
	if interfaceBound["tag"] != "routing-rule-11-warp-7" || interfaceBound["private_key"] != "private" || interfaceBound["bind_interface"] != "eth1" {
		t.Fatalf("interface-bound WARP endpoint = %#v", interfaceBound)
	}
	interfaceResolver, ok := interfaceBound["domain_resolver"].(map[string]any)
	if !ok || interfaceResolver["strategy"] != "ipv6_only" {
		t.Fatalf("interface-bound WARP domain_resolver = %#v", interfaceBound["domain_resolver"])
	}
	sourceBound := endpoints[2].(map[string]any)
	if sourceBound["tag"] != "routing-rule-12-warp-7" || sourceBound["private_key"] != "private" || sourceBound["detour"] != "source-prefix-example" {
		t.Fatalf("source-bound WARP endpoint = %#v", sourceBound)
	}
	sourceResolver, ok := sourceBound["domain_resolver"].(map[string]any)
	if !ok || sourceResolver["strategy"] != "ipv6_only" {
		t.Fatalf("source-bound WARP domain_resolver = %#v", sourceBound["domain_resolver"])
	}
	resolver, ok := endpoint["domain_resolver"].(map[string]any)
	if !ok || resolver["server"] != warpBootstrapResolverTag || resolver["strategy"] != "prefer_ipv4" {
		t.Fatalf("resolved WARP domain_resolver = %#v", endpoint["domain_resolver"])
	}
}

func TestDeriveWARPRegistrationBindingFromPendingEndpoints(t *testing.T) {
	config := `{"outbounds":[{"type":"source-prefix","tag":"source-prefix-v6","prefix":"2001:db8:100::/64"}],"endpoints":[{"type":"wireguard","tag":"warp-7","_oboard_warp_pending":7},{"type":"wireguard","tag":"routing-rule-11-warp-7","_oboard_warp_pending":7,"bind_interface":"he-ipv6"},{"type":"wireguard","tag":"routing-rule-12-warp-8","_oboard_warp_pending":8,"detour":"source-prefix-v6"}]}`
	bindings, err := deriveWARPRegistrationBindings(config)
	if err != nil {
		t.Fatal(err)
	}
	if bindings[7].InterfaceName != "he-ipv6" || bindings[7].SourcePrefix != "" {
		t.Fatalf("interface binding = %#v", bindings[7])
	}
	if bindings[8].SourcePrefix != "2001:db8:100::/64" || bindings[8].InterfaceName != "" {
		t.Fatalf("source-prefix binding = %#v", bindings[8])
	}
}

func TestDeriveWARPRegistrationBindingRejectsConflicts(t *testing.T) {
	_, err := deriveWARPRegistrationBindings(`{"endpoints":[{"_oboard_warp_pending":7,"bind_interface":"eth0"},{"_oboard_warp_pending":7,"bind_interface":"he-ipv6"}]}`)
	if err == nil || !strings.Contains(err.Error(), "conflicting registration bindings") {
		t.Fatalf("conflicting bindings error = %v", err)
	}
}

func TestSelectWARPRegistrationAddressUsesHEIPv6Interface(t *testing.T) {
	interfaces := []model.NetworkInterfaceInfo{
		{Name: "eth0", Up: true, Running: true, Addresses: []string{"192.0.2.10/24"}},
		{Name: "he-ipv6", Up: true, Running: true, Addresses: []string{"2001:470:1f00::2/64", "fe80::1/64"}},
	}
	name, address, err := selectWARPRegistrationAddress(interfaces, warpRegistrationBinding{InterfaceName: "he-ipv6"}, model.IPStackIPv4Only)
	if err != nil {
		t.Fatal(err)
	}
	if name != "he-ipv6" || address.String() != "2001:470:1f00::2" {
		t.Fatalf("selected registration source = %s %s", name, address)
	}
}

func TestPersistedWARPConfigSupportsDeploymentReplay(t *testing.T) {
	runner := New(Config{StateDir: t.TempDir()})
	report := runner.persistReadyWARPReport(model.WARPConfigReport{ServerID: 1, ProfileID: 9}, map[string]any{"type": "wireguard", "tag": "warp-9", "private_key": "private", "address": []string{"172.16.0.2/32"}, "peers": []any{}, "domain_resolver": map[string]any{"server": "bootstrap", "strategy": "prefer_ipv6"}})
	if report.Status != model.WARPStatusReady {
		t.Fatalf("persist report = %#v", report)
	}
	loaded, err := runner.loadPersistedWARPConfig(model.WARPRequestPlan{ServerID: 1, ProfileID: 9, DNSStrategy: "prefer_ipv4"})
	if err != nil {
		t.Fatal(err)
	}
	if loaded.Status != model.WARPStatusReady || !strings.Contains(loaded.ConfigJSON, "private") {
		t.Fatalf("loaded report = %#v", loaded)
	}
	var endpoint map[string]any
	if err := json.Unmarshal([]byte(loaded.ConfigJSON), &endpoint); err != nil {
		t.Fatal(err)
	}
	resolver, ok := endpoint["domain_resolver"].(map[string]any)
	if !ok || resolver["server"] != warpBootstrapResolverTag || resolver["strategy"] != "prefer_ipv4" {
		t.Fatalf("persisted WARP domain_resolver = %#v", endpoint["domain_resolver"])
	}
	onDisk, err := os.ReadFile(filepath.Join(runner.stateDir(), "warp", "9", "endpoint.json"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(onDisk), `"server":"bootstrap-primary"`) || strings.Contains(string(onDisk), `"server":"bootstrap"`) {
		t.Fatalf("persisted endpoint was not rewritten: %s", onDisk)
	}
	info, err := os.Stat(filepath.Join(runner.stateDir(), "warp", "9", "endpoint.json"))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("endpoint mode = %o, want 600", info.Mode().Perm())
	}
}

func TestNormalizeWARPDomainResolverRemovesExplicitResolverForAuto(t *testing.T) {
	endpoint := map[string]any{"domain_resolver": map[string]any{"server": "bootstrap", "strategy": "prefer_ipv4"}}
	normalizeWARPDomainResolver(endpoint, model.WARPRequestPlan{DNSStrategy: "auto"})
	if _, ok := endpoint["domain_resolver"]; ok {
		t.Fatalf("auto WARP endpoint retained domain_resolver: %#v", endpoint)
	}
}

func TestWarpMTUClampsTo1280(t *testing.T) {
	for requested, want := range map[int]int{0: 1280, 1280: 1280, 1420: 1280, 1500: 1280, 9000: 1280, 1200: 1200} {
		if got := warpMTU(requested); got != want {
			t.Fatalf("warpMTU(%d) = %d, want %d", requested, got, want)
		}
	}
}

func TestRegisterWARPWireGuardClampsServerMTU(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("content-type", "application/json")
		_, _ = w.Write([]byte(`{"id":"device-id","config":{"client_id":"AQID","interface":{"addresses":{"v4":"172.16.0.2/32","v6":"2606:4700:110:abcd::2/128"}}}}`))
	}))
	defer server.Close()

	// A server whose main-network MTU detection stored 1500 must never leak
	// into the WARP tunnel; large encrypted datagrams are fragmented and
	// dropped on typical paths, stalling page loads while small packets pass.
	endpoint, err := registerWARPWireGuard(context.Background(), server.Client(), server.URL, model.WARPRequestPlan{ProfileID: 7, MTU: 1500, DNSStrategy: "prefer_ipv4"})
	if err != nil {
		t.Fatal(err)
	}
	if endpoint["mtu"] != 1280 {
		t.Fatalf("WARP MTU = %#v, want 1280", endpoint["mtu"])
	}
}

func TestWGCFProfileToSingBoxClampsServerMTU(t *testing.T) {
	profile := `[Interface]
PrivateKey = private-key
Address = 172.16.0.2/32
MTU = 1280

[Peer]
PublicKey = public-key
Endpoint = engage.cloudflareclient.com:2408
AllowedIPs = 0.0.0.0/0, ::/0
Reserved = 1,2,3
`
	outbound, err := wgcfProfileToSingBox(profile, model.WARPRequestPlan{ProfileID: 7, MTU: 1500, DNSStrategy: "prefer_ipv4"})
	if err != nil {
		t.Fatal(err)
	}
	if outbound["mtu"] != 1280 {
		t.Fatalf("wgcf WARP MTU = %#v, want 1280", outbound["mtu"])
	}
}

func TestLoadPersistedWARPConfigClampsPoisonedMTU(t *testing.T) {
	runner := New(Config{StateDir: t.TempDir()})
	report := runner.persistReadyWARPReport(model.WARPConfigReport{ServerID: 1, ProfileID: 9}, map[string]any{"type": "wireguard", "tag": "warp-9", "private_key": "private", "address": []string{"172.16.0.2/32"}, "mtu": 1500, "peers": []any{}, "domain_resolver": map[string]any{"server": "bootstrap", "strategy": "prefer_ipv4"}})
	if report.MTU != 1280 {
		t.Fatalf("persist report MTU = %d, want 1280", report.MTU)
	}
	loaded, err := runner.loadPersistedWARPConfig(model.WARPRequestPlan{ServerID: 1, ProfileID: 9, MTU: 1500, DNSStrategy: "prefer_ipv4"})
	if err != nil {
		t.Fatal(err)
	}
	if loaded.MTU != 1280 {
		t.Fatalf("loaded report MTU = %d, want 1280", loaded.MTU)
	}
	var endpoint map[string]any
	if err := json.Unmarshal([]byte(loaded.ConfigJSON), &endpoint); err != nil {
		t.Fatal(err)
	}
	if mtu, ok := endpoint["mtu"].(float64); !ok || int(mtu) != 1280 {
		t.Fatalf("persisted endpoint MTU = %#v, want 1280", endpoint["mtu"])
	}
	onDisk, err := os.ReadFile(filepath.Join(runner.stateDir(), "warp", "9", "endpoint.json"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(onDisk), `"mtu":1500`) || !strings.Contains(string(onDisk), `"mtu":1280`) {
		t.Fatalf("persisted endpoint was not rewritten with the clamped MTU: %s", onDisk)
	}
}

func TestDeploymentStopsWhenRequiredWARPRequestFails(t *testing.T) {
	stateDir := t.TempDir()
	runner := New(Config{StateDir: stateDir, WarpCommand: "none"})
	status, result := runner.executeDeploymentTask(model.DeploymentTaskPayload{
		Version:       1,
		Config:        model.ApplyCoreConfigTaskPayload{Config: `{"endpoints":[{"type":"wireguard","tag":"warp-7","_oboard_warp_pending":7}]}`},
		ConfigChanged: true,
		WARPRequests:  []model.WARPRequestPlan{{Version: 1, ServerID: 1, ProfileID: 7, OutboundTag: "warp-7"}},
	})
	if status != "failed" || !strings.Contains(result, "WARP") {
		t.Fatalf("deployment status=%s result=%s", status, result)
	}
	if _, err := os.Stat(filepath.Join(stateDir, "sing-box.json")); !os.IsNotExist(err) {
		t.Fatalf("core config was written after WARP failure: %v", err)
	}
}
