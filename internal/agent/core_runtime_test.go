package agent

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/OboardProject/oboard-agent/internal/model"
)

// fakeCoreKernel stands in for a running oboard-sb. It reports the operational
// digest of the configuration it loaded at its last boot, exactly like the real
// kernel, so a stale process is simply one that has not booted again.
//
// Agent always persists a traffic checkpoint through GET /traffic/snapshot
// immediately before it restarts the core, so the stub uses that call as its
// restart signal. It only acts on it once the test has armed a restart, which
// stands for a service manager that really replaces the process; without that,
// the stub keeps serving its old configuration no matter who calls it.
type fakeCoreKernel struct {
	mu               sync.Mutex
	configPath       string
	loadedDigest     string
	generation       uint64
	boots            int
	restartArmed     bool
	runtimeSupported bool
	policyPushes     int
	client           *http.Client
}

func newFakeCoreKernel(t *testing.T, configPath string, runtimeSupported bool) *fakeCoreKernel {
	t.Helper()
	// Unix socket paths are short-bounded, so the socket lives outside the
	// (long) per-test temporary directory.
	socketFile, err := os.CreateTemp("/tmp", "oboard-core-*.sock")
	if err != nil {
		t.Fatal(err)
	}
	socket := socketFile.Name()
	_ = socketFile.Close()
	_ = os.Remove(socket)
	t.Cleanup(func() { _ = os.Remove(socket) })
	listener, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	kernel := &fakeCoreKernel{configPath: configPath, runtimeSupported: runtimeSupported, client: unixHTTPClient(socket)}
	kernel.boot()
	mux := http.NewServeMux()
	mux.HandleFunc("/version", func(w http.ResponseWriter, _ *http.Request) {
		capabilities := []string{"traffic_ledger"}
		if kernel.runtimeSupported {
			capabilities = append(capabilities, coreRuntimeDigestCapability)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"name": "oboard-sb", "capabilities": capabilities})
	})
	mux.HandleFunc("/runtime/status", func(w http.ResponseWriter, _ *http.Request) {
		if !kernel.runtimeSupported {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		kernel.mu.Lock()
		defer kernel.mu.Unlock()
		_ = json.NewEncoder(w).Encode(map[string]any{
			"operational_config_sha256": kernel.loadedDigest,
			"started_at":                "2026-09-02T00:00:00Z",
			"pid":                       4242,
			"generation":                kernel.generation,
		})
	})
	mux.HandleFunc("/traffic/snapshot", func(w http.ResponseWriter, _ *http.Request) {
		kernel.bootIfArmed()
		_ = json.NewEncoder(w).Encode(map[string]any{"items": []any{}})
	})
	mux.HandleFunc("/traffic/policy", func(w http.ResponseWriter, _ *http.Request) {
		kernel.mu.Lock()
		kernel.policyPushes++
		kernel.mu.Unlock()
		_ = json.NewEncoder(w).Encode(map[string]bool{"ok": true})
	})
	server := &http.Server{Handler: mux}
	go func() { _ = server.Serve(listener) }()
	t.Cleanup(func() { _ = server.Close() })
	return kernel
}

// armRestart makes the next Agent-initiated core restart actually replace the
// running configuration, the way a service manager would.
func (k *fakeCoreKernel) armRestart() {
	k.mu.Lock()
	k.restartArmed = true
	k.mu.Unlock()
}

func (k *fakeCoreKernel) bootIfArmed() {
	k.mu.Lock()
	armed := k.restartArmed
	k.restartArmed = false
	k.mu.Unlock()
	if armed {
		k.boot()
	}
}

// boot reloads the configuration from disk, the way a restarted kernel does.
func (k *fakeCoreKernel) boot() {
	raw, err := os.ReadFile(k.configPath)
	if err != nil {
		return
	}
	digest, err := operationalCoreConfigDigest(raw)
	if err != nil {
		return
	}
	k.mu.Lock()
	defer k.mu.Unlock()
	k.loadedDigest = digest
	k.generation++
	k.boots++
}

func (k *fakeCoreKernel) digest() string {
	k.mu.Lock()
	defer k.mu.Unlock()
	return k.loadedDigest
}

func (k *fakeCoreKernel) bootCount() int {
	k.mu.Lock()
	defer k.mu.Unlock()
	return k.boots
}

func (k *fakeCoreKernel) pushCount() int {
	k.mu.Lock()
	defer k.mu.Unlock()
	return k.policyPushes
}

const (
	coreConfigA          = `{"log":{"level":"warn"},"inbounds":[{"tag":"in-a","type":"socks","listen":"127.0.0.1","listen_port":11111}],"_oboard":{"rate_limits":{"users":{"alice":{"user_id":7,"lease_bytes":100}}}}}`
	coreConfigB          = `{"log":{"level":"warn"},"inbounds":[{"tag":"in-b","type":"socks","listen":"127.0.0.1","listen_port":22222}],"_oboard":{"rate_limits":{"users":{"alice":{"user_id":7,"lease_bytes":100}}}}}`
	coreConfigBRateLimit = `{"log":{"level":"warn"},"inbounds":[{"tag":"in-b","type":"socks","listen":"127.0.0.1","listen_port":22222}],"_oboard":{"rate_limits":{"users":{"alice":{"user_id":7,"lease_bytes":500}}}}}`
)

func newRuntimeTestRunner(t *testing.T, dir string, kernel *fakeCoreKernel) *Runner {
	t.Helper()
	r := New(Config{StateDir: dir, CoreBinary: filepath.Join(dir, "missing-sb"), ReloadCommand: "none", RestartCommand: "none", ResourceProfile: "large"})
	r.coreClient = kernel.client
	return r
}

// writeCoreConfig persists a configuration in the canonical form Agent itself
// writes, so a manual edit is byte-comparable with a deployment of the same
// configuration.
func writeCoreConfig(t *testing.T, dir, config string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, "sing-box.json"), []byte(resolvedCoreConfig(t, config)), 0o600); err != nil {
		t.Fatal(err)
	}
}

func resolvedCoreConfig(t *testing.T, config string) string {
	t.Helper()
	var value any
	if err := json.Unmarshal([]byte(config), &value); err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

func mustOperationalDigest(t *testing.T, config string) string {
	t.Helper()
	digest, err := operationalCoreConfigDigest([]byte(config))
	if err != nil {
		t.Fatal(err)
	}
	return digest
}

func TestOperationalDigestIgnoresRuntimePolicyAndFormatting(t *testing.T) {
	compact := `{"log":{"level":"warn"},"_oboard":{"rate_limits":{"users":{"alice":{"user_id":7}}}}}`
	reordered := "{\n  \"_oboard\" : { \"rate_limits\": {\"users\": {\"alice\": {\"user_id\": 99}}} },\n  \"log\": {\"level\": \"warn\"}\n}"
	if mustOperationalDigest(t, compact) != mustOperationalDigest(t, reordered) {
		t.Fatal("runtime policy or formatting changed the operational digest")
	}
	if mustOperationalDigest(t, `{"log":{"level":"error"},"_oboard":{"rate_limits":{}}}`) == mustOperationalDigest(t, compact) {
		t.Fatal("an operational change did not change the digest")
	}
}

// A kernel that is still serving an older configuration must be restarted even
// though the file on disk already matches the desired configuration.
func TestApplyCoreConfigRestartsStaleKernelDespiteMatchingFile(t *testing.T) {
	dir := t.TempDir()
	writeCoreConfig(t, dir, coreConfigA)
	kernel := newFakeCoreKernel(t, filepath.Join(dir, "sing-box.json"), true)
	// The file was replaced out of band; the running process kept A.
	writeCoreConfig(t, dir, coreConfigB)
	kernel.armRestart()
	r := newRuntimeTestRunner(t, dir, kernel)

	result, err := r.applyCoreConfigTask(60, model.ApplyCoreConfigTaskPayload{Config: coreConfigB})
	if err != nil {
		t.Fatal(err)
	}
	if result["reload_strategy"] != "runtime_drift_restart" {
		t.Fatalf("stale kernel was not recovered: %#v", result)
	}
	if result["runtime_drift"] != true || result["runtime_verified"] != true {
		t.Fatalf("runtime drift was not reported: %#v", result)
	}
	if kernel.digest() != mustOperationalDigest(t, coreConfigB) {
		t.Fatalf("kernel did not converge: loaded=%s", kernel.digest())
	}
}

// A kernel that cannot be brought back to the desired configuration must fail
// the task instead of reporting a converged deployment.
func TestApplyCoreConfigFailsWhenRestartDoesNotClearDrift(t *testing.T) {
	dir := t.TempDir()
	writeCoreConfig(t, dir, coreConfigA)
	kernel := newFakeCoreKernel(t, filepath.Join(dir, "sing-box.json"), true)
	writeCoreConfig(t, dir, coreConfigB)
	r := newRuntimeTestRunner(t, dir, kernel)

	result, err := r.applyCoreConfigTask(66, model.ApplyCoreConfigTaskPayload{Config: coreConfigB})
	if err == nil {
		t.Fatalf("unrecovered drift was reported as success: %#v", result)
	}
	if result["reload_strategy"] != "runtime_drift_restart_failed" {
		t.Fatalf("unexpected failure strategy: %#v", result)
	}
}

func TestApplyCoreConfigUnchangedWhenRuntimeAlreadyMatches(t *testing.T) {
	dir := t.TempDir()
	writeCoreConfig(t, dir, coreConfigB)
	kernel := newFakeCoreKernel(t, filepath.Join(dir, "sing-box.json"), true)
	r := newRuntimeTestRunner(t, dir, kernel)
	boots := kernel.bootCount()

	result, err := r.applyCoreConfigTask(61, model.ApplyCoreConfigTaskPayload{Config: coreConfigB})
	if err != nil {
		t.Fatal(err)
	}
	if result["reload_strategy"] != "unchanged" {
		t.Fatalf("converged kernel was restarted: %#v", result)
	}
	if result["runtime_verified"] != true || result["runtime_drift"] != false {
		t.Fatalf("runtime verification was not recorded: %#v", result)
	}
	if kernel.bootCount() != boots {
		t.Fatalf("kernel restarted %d time(s) for an unchanged config", kernel.bootCount()-boots)
	}
}

func TestApplyCoreConfigRuntimePolicyOnlyKeepsKernelRunning(t *testing.T) {
	dir := t.TempDir()
	writeCoreConfig(t, dir, coreConfigB)
	kernel := newFakeCoreKernel(t, filepath.Join(dir, "sing-box.json"), true)
	r := newRuntimeTestRunner(t, dir, kernel)
	boots := kernel.bootCount()

	result, err := r.applyCoreConfigTask(62, model.ApplyCoreConfigTaskPayload{Config: coreConfigBRateLimit})
	if err != nil {
		t.Fatal(err)
	}
	if result["reload_strategy"] != "runtime_policy_only" || result["connection_draining"] != false {
		t.Fatalf("rate limit update did not stay hot: %#v", result)
	}
	if kernel.bootCount() != boots {
		t.Fatalf("rate limit update restarted the kernel %d time(s)", kernel.bootCount()-boots)
	}
	if kernel.pushCount() == 0 {
		t.Fatal("runtime policy was never pushed to the kernel")
	}
}

// A rate-limit-only change must not be allowed to mask a kernel that is already
// running an older operational configuration.
func TestApplyCoreConfigRuntimePolicyDoesNotMaskRuntimeDrift(t *testing.T) {
	dir := t.TempDir()
	writeCoreConfig(t, dir, coreConfigA)
	kernel := newFakeCoreKernel(t, filepath.Join(dir, "sing-box.json"), true)
	// Disk already holds B while the kernel still runs A; the new task only
	// changes B's rate limits.
	writeCoreConfig(t, dir, coreConfigB)
	kernel.armRestart()
	r := newRuntimeTestRunner(t, dir, kernel)

	result, err := r.applyCoreConfigTask(63, model.ApplyCoreConfigTaskPayload{Config: coreConfigBRateLimit})
	if err != nil {
		t.Fatal(err)
	}
	if result["reload_strategy"] == "runtime_policy_only" {
		t.Fatalf("runtime policy update hid an operational drift: %#v", result)
	}
	if result["reload_strategy"] != "runtime_drift_restart" || result["runtime_drift"] != true {
		t.Fatalf("drift was not recovered: %#v", result)
	}
	if kernel.digest() != mustOperationalDigest(t, coreConfigBRateLimit) {
		t.Fatalf("kernel did not converge: loaded=%s", kernel.digest())
	}
}

// Changing an inbound listener is an operational change: it restarts the core
// and the restart is confirmed against the running process.
func TestApplyCoreConfigOperationalChangeUsesVerifiedRestartFallback(t *testing.T) {
	dir := t.TempDir()
	writeCoreConfig(t, dir, coreConfigA)
	kernel := newFakeCoreKernel(t, filepath.Join(dir, "sing-box.json"), true)
	kernel.armRestart()
	r := newRuntimeTestRunner(t, dir, kernel)

	result, err := r.applyCoreConfigTask(64, model.ApplyCoreConfigTaskPayload{Config: coreConfigB})
	if err != nil {
		t.Fatal(err)
	}
	if result["reload_strategy"] != "restart_fallback" {
		t.Fatalf("operational change did not restart the core: %#v", result)
	}
	if result["runtime_verified"] != true || result["runtime_drift"] != false {
		t.Fatalf("restart was not verified against the kernel: %#v", result)
	}
	if kernel.digest() != mustOperationalDigest(t, coreConfigB) {
		t.Fatalf("kernel did not converge: loaded=%s", kernel.digest())
	}
}

// Agent may be upgraded before the kernel. A kernel without
// runtime_config_digest_v1 must keep the previous behaviour instead of being
// restarted on every deployment.
func TestApplyCoreConfigToleratesKernelWithoutRuntimeDigest(t *testing.T) {
	dir := t.TempDir()
	writeCoreConfig(t, dir, coreConfigB)
	kernel := newFakeCoreKernel(t, filepath.Join(dir, "sing-box.json"), false)
	r := newRuntimeTestRunner(t, dir, kernel)
	boots := kernel.bootCount()

	result, err := r.applyCoreConfigTask(65, model.ApplyCoreConfigTaskPayload{Config: coreConfigB})
	if err != nil {
		t.Fatal(err)
	}
	if result["reload_strategy"] != "unchanged" {
		t.Fatalf("old kernel was not left alone: %#v", result)
	}
	if result["runtime_verified"] != false || result["runtime_verification"] != coreRuntimeVerificationUnsupported {
		t.Fatalf("old kernel was not reported as unsupported: %#v", result)
	}
	if kernel.bootCount() != boots {
		t.Fatalf("old kernel was restarted %d time(s)", kernel.bootCount()-boots)
	}
}

// An unreachable local API is not evidence of drift: restarting on it would
// drop sessions for a kernel that may be perfectly healthy.
func TestCoreRuntimeCheckTreatsUnreachableKernelAsUnverified(t *testing.T) {
	dir := t.TempDir()
	writeCoreConfig(t, dir, coreConfigB)
	r := New(Config{StateDir: dir, CoreBinary: filepath.Join(dir, "missing-sb"), ReloadCommand: "none", RestartCommand: "none", ResourceProfile: "large"})
	r.coreClient = unixHTTPClient(filepath.Join(dir, "absent.sock"))

	check := r.checkCoreRuntimeConfig(context.Background(), []byte(coreConfigB))
	if check.Verification != coreRuntimeVerificationUnavailable {
		t.Fatalf("unreachable kernel was not reported as unavailable: %#v", check)
	}
	if check.drift() {
		t.Fatal("unreachable kernel was mistaken for runtime drift")
	}
}

func TestScheduleAgentRestartArmsOnlyOneTimerPerProcess(t *testing.T) {
	r := New(Config{StateDir: t.TempDir(), ResourceProfile: "large"})
	calls := 0
	schedule := func() error {
		calls++
		return nil
	}
	for i := 0; i < 3; i++ {
		if err := r.scheduleAgentRestartWith(schedule); err != nil {
			t.Fatal(err)
		}
	}
	if calls != 1 {
		t.Fatalf("agent restart was scheduled %d times, want 1", calls)
	}
}

func TestScheduleAgentRestartRetriesAfterFailure(t *testing.T) {
	r := New(Config{StateDir: t.TempDir(), ResourceProfile: "large"})
	calls := 0
	failing := func() error {
		calls++
		return os.ErrPermission
	}
	if err := r.scheduleAgentRestartWith(failing); err == nil {
		t.Fatal("expected the first scheduling failure to be reported")
	}
	if err := r.scheduleAgentRestartWith(failing); err == nil {
		t.Fatal("a failed scheduling attempt must stay retryable")
	}
	if calls != 2 {
		t.Fatalf("scheduling was attempted %d times, want 2", calls)
	}
}

func TestControllerLinkDiagnosticsRedactCredentials(t *testing.T) {
	dir := t.TempDir()
	r := New(Config{StateDir: dir, ResourceProfile: "large"})
	now := time.Now().UTC()
	r.recordControllerLinkConnected(now)
	snapshot := r.recordControllerLinkClosed(now, 0, &controllerHandshakeError{StatusCode: http.StatusUnauthorized, Status: "401 Unauthorized"})
	if snapshot.DisconnectClass != controllerLinkClassHandshake || snapshot.HandshakeHTTPStatus != http.StatusUnauthorized {
		t.Fatalf("handshake rejection was not classified: %#v", snapshot)
	}
	if snapshot.ReconnectCount != 1 || snapshot.ConsecutiveFailures != 1 {
		t.Fatalf("link counters were not recorded: %#v", snapshot)
	}
	raw, err := os.ReadFile(filepath.Join(dir, controllerLinkStatePath))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "Bearer") || strings.Contains(string(raw), "agent_token") {
		t.Fatalf("controller link diagnostics leaked credentials: %s", raw)
	}
	detail := scrubControllerLinkDetail("dial wss://controller.example/api/v1/agent/ws?agent_token=supersecret: connection reset")
	if strings.Contains(detail, "supersecret") {
		t.Fatalf("signed query was not redacted: %s", detail)
	}
}
