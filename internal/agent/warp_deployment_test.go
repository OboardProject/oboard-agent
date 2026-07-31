package agent

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/OboardProject/oboard-agent/internal/model"
)

func TestResolveDeploymentWARPConfigReplacesControllerPlaceholder(t *testing.T) {
	config := `{"endpoints":[{"type":"wireguard","tag":"warp-7","_oboard_warp_pending":7}],"route":{"rules":[{"action":"route","outbound":"warp-7"}]}}`
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
	endpoint := root["endpoints"].([]any)[0].(map[string]any)
	if endpoint["tag"] != "warp-7" || endpoint["private_key"] != "private" {
		t.Fatalf("resolved WARP endpoint = %#v", endpoint)
	}
	resolver, ok := endpoint["domain_resolver"].(map[string]any)
	if !ok || resolver["server"] != warpBootstrapResolverTag || resolver["strategy"] != "prefer_ipv4" {
		t.Fatalf("resolved WARP domain_resolver = %#v", endpoint["domain_resolver"])
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
