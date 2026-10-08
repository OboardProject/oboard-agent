package agent

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/OboardProject/oboard-agent/internal/model"
	"github.com/OboardProject/oboard-agent/internal/stealth"
)

// installFakeAgentTree points the executable seam at a temporary install
// directory and returns it, so the bundled realm resolution can be exercised
// without touching a real installation.
func installFakeAgentTree(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	agentPath := filepath.Join(dir, "oboard-agent")
	if err := os.WriteFile(agentPath, []byte("agent"), 0o755); err != nil {
		t.Fatal(err)
	}
	original := osExecutable
	t.Cleanup(func() { osExecutable = original })
	osExecutable = func() (string, error) { return agentPath, nil }
	return dir
}

func writeFakeRealm(t *testing.T, dir, script string) string {
	t.Helper()
	path := filepath.Join(dir, realmProcessName)
	if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestRealmBinaryResolvesBesideAgent(t *testing.T) {
	dir := installFakeAgentTree(t)
	r := New(Config{StateDir: t.TempDir()})
	agentPath, err := canonicalFilePath(filepath.Join(dir, "oboard-agent"))
	if err != nil {
		t.Fatal(err)
	}
	want := filepath.Join(filepath.Dir(agentPath), "oboard-realm")
	if got := r.realmBinary(); got != want {
		t.Fatalf("realmBinary() = %q, want %q", got, want)
	}
}

func TestForwardCapabilityFollowsBundledRealmBinary(t *testing.T) {
	dir := installFakeAgentTree(t)
	r := New(Config{StateDir: t.TempDir()})
	if r.detectForwardCapabilities()["realm"] {
		t.Fatal("realm capability must be false before the bundled binary is installed")
	}
	path := writeFakeRealm(t, dir, "#!/bin/sh\nexit 0\n")
	if !r.detectForwardCapabilities()["realm"] {
		t.Fatal("realm capability must be true once the bundled binary is installed")
	}
	// A non-executable file is a failed or partial install, not a usable backend.
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
	if r.detectForwardCapabilities()["realm"] {
		t.Fatal("realm capability must be false when the bundled binary is not executable")
	}
}

// A host that never installed realm used to fail with an opaque "binary was not
// found". The message must now point at the action that fixes it.
func TestResolveForwardBackendsNamesTheBundledBinary(t *testing.T) {
	_, err := resolveForwardBackends([]model.PortForward{{ID: 1, Name: "a-to-b"}}, map[string]bool{"realm": false})
	if err == nil {
		t.Fatal("expected the rule to fail without the bundled binary")
	}
	if !strings.Contains(err.Error(), realmProcessName) || !strings.Contains(err.Error(), "Agent update") {
		t.Fatalf("unhelpful error: %v", err)
	}
}

func TestApplyRealmForwardsRunsBundledBinary(t *testing.T) {
	dir := installFakeAgentTree(t)
	writeFakeRealm(t, dir, "#!/bin/sh\nwhile :; do :; done\n")
	stateDir := t.TempDir()
	r := New(Config{StateDir: stateDir})
	rules := []forwardRule{{
		PortForward:     model.PortForward{ID: 1, Name: "a-to-b", ListenIP: "127.0.0.1", ListenPort: 24431, TargetAddress: "203.0.113.2", TargetPort: 8443, Protocol: model.ForwardProtocolTCP},
		ResolvedBackend: model.ForwardBackendRealm,
	}}
	if err := r.applyRealmForwards(rules); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = stopManagedProcess(filepath.Join(stateDir, realmPIDFile)) })

	b, err := os.ReadFile(filepath.Join(stateDir, realmPIDFile))
	if err != nil {
		t.Fatal(err)
	}
	var record struct {
		PID     int    `json:"pid"`
		Command string `json:"command"`
	}
	if err := json.Unmarshal(b, &record); err != nil {
		t.Fatal(err)
	}
	if record.Command != realmProcessName {
		t.Fatalf("managed command = %q, want %q", record.Command, realmProcessName)
	}
	if record.PID <= 0 {
		t.Fatalf("managed pid = %d", record.PID)
	}
	// Ownership validation must accept the bundled name, otherwise the Agent
	// would refuse to stop the process it just started.
	if !managedProcessMatches(record.PID, realmProcessName, processStartToken(record.PID)) {
		t.Fatal("bundled realm process is not recognized by its own managed record")
	}
}

func TestApplyRealmForwardsFailsWithoutBundledBinary(t *testing.T) {
	installFakeAgentTree(t)
	r := New(Config{StateDir: t.TempDir()})
	rules := []forwardRule{{
		PortForward:     model.PortForward{ID: 1, Name: "a-to-b", ListenPort: 24432, TargetAddress: "203.0.113.2", TargetPort: 8443},
		ResolvedBackend: model.ForwardBackendRealm,
	}}
	err := r.applyRealmForwards(rules)
	if err == nil || !strings.Contains(err.Error(), realmProcessName) {
		t.Fatalf("unexpected error without the bundled binary: %v", err)
	}
}

// Upgrading from a host-provided realm leaves a PID record naming the old
// process. It must still be stopped, or the stale process keeps the listen
// ports the bundled binary is about to bind.
func TestStopManagedProcessStopsLegacyHostRealm(t *testing.T) {
	dir := t.TempDir()
	legacy := filepath.Join(dir, legacyRealmName)
	if err := os.WriteFile(legacy, []byte("#!/bin/sh\nwhile :; do :; done\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(legacy)
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	pidPath := filepath.Join(t.TempDir(), realmPIDFile)
	if err := writeManagedPIDFile(pidPath, cmd.Process.Pid, legacyRealmName); err != nil {
		t.Fatal(err)
	}
	if err := stopManagedProcess(pidPath); err != nil {
		t.Fatalf("stop legacy realm: %v", err)
	}
	_ = cmd.Wait()
	if _, err := os.Stat(pidPath); !os.IsNotExist(err) {
		t.Fatalf("legacy pid file should be removed: %v", err)
	}
}

func TestRealmChild(t *testing.T) {
	if os.Getenv("OBOARD_REALM_CHILD") != "1" {
		return
	}
	var configPath string
	for i, arg := range os.Args {
		if arg == "-c" && i+1 < len(os.Args) {
			configPath = os.Args[i+1]
		}
	}
	data, err := os.ReadFile(configPath)
	if err != nil || strings.Contains(string(data), "203.0.113.2:9999") {
		os.Exit(12)
	}
	if err := os.WriteFile(configPath+".loaded", data, 0o600); err != nil {
		os.Exit(13)
	}
	for {
		time.Sleep(time.Hour)
	}
}

func TestManagedChildPIDWriteFailureReapsProcess(t *testing.T) {
	dir := installRealmChild(t)
	config := filepath.Join(t.TempDir(), "realm.toml")
	if err := os.WriteFile(config, []byte("test"), 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(filepath.Join(dir, realmProcessName), "-c", config)
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	waitCh := make(chan error, 1)
	go func() { waitCh <- cmd.Wait() }()
	if err := recordManagedChild(cmd, waitCh, t.TempDir(), realmProcessName); err == nil {
		t.Fatal("PID write failure accepted")
	}
	if processAlive(cmd.Process.Pid) {
		t.Fatal("untracked child left alive")
	}
}

func TestForwardHandoffKeepsEncryptedState(t *testing.T) {
	key, err := stealth.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	r := New(Config{StateDir: t.TempDir(), StealthKey: key})
	plan := model.PortForwardPlan{Version: 42}
	if err := r.commitForwardHandoff(&forwardHandoff{currentPath: r.statePath(portForwardsCurrent), retainedPlan: plan}); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(r.statePath(portForwardsCurrent))
	if err != nil || !stealth.IsEncrypted(raw) {
		t.Fatalf("unencrypted handoff: %v", err)
	}
	data, err := r.stateRead(portForwardsCurrent)
	if err != nil {
		t.Fatal(err)
	}
	var actual model.PortForwardPlan
	if err := json.Unmarshal(data, &actual); err != nil || actual.Version != 42 {
		t.Fatalf("plan=%+v err=%v", actual, err)
	}
}

func installRealmChild(t *testing.T) string {
	t.Helper()
	dir := installFakeAgentTree(t)
	binary, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("OBOARD_REALM_TEST_BINARY", binary)
	t.Setenv("OBOARD_REALM_CHILD", "1")
	writeFakeRealm(t, dir, "#!/bin/sh\ncase $(cat \"$2\") in *203.0.113.2:9999*) exit 12 ;; esac\nexec \"$OBOARD_REALM_TEST_BINARY\" -test.run='^TestRealmChild$' -- \"$0\" \"$@\"\n")
	return dir
}

func TestRealmPlanWritesReloadsAndRepairsRuntime(t *testing.T) {
	installRealmChild(t)
	r := New(Config{StateDir: t.TempDir()})
	t.Cleanup(func() {
		if err := stopManagedProcess(r.statePath(realmPIDFile)); err != nil {
			t.Error(err)
		}
	})
	plan := model.PortForwardPlan{Version: 1, Rules: []model.PortForward{{ID: 1, Name: "edge", Enabled: true, ListenIP: "127.0.0.1", ListenPort: 24431, TargetAddress: "203.0.113.2", TargetPort: 7099, Protocol: model.ForwardProtocolTCP}}}
	apply := func() {
		t.Helper()
		result, err := r.applyPortForwards(plan)
		if err != nil || result.Unchanged {
			t.Fatalf("apply=%+v err=%v", result, err)
		}
	}
	check := func(port string) {
		t.Helper()
		deadline := time.Now().Add(5 * time.Second)
		for {
			data, err := os.ReadFile(r.statePath(realmConfigFile) + ".loaded")
			if err == nil && strings.Contains(string(data), port) {
				return
			}
			if time.Now().After(deadline) {
				t.Fatalf("loaded=%s err=%v", data, err)
			}
			time.Sleep(20 * time.Millisecond)
		}
	}
	apply()
	check(":7099")
	plan.Rules[0].TargetPort = 7098
	apply()
	check(":7098")
	result, err := r.applyPortForwards(plan)
	if err != nil || !result.Unchanged {
		t.Fatalf("replay=%+v err=%v", result, err)
	}
	if err := os.WriteFile(r.statePath(realmConfigFile), []byte("old config"), 0o600); err != nil {
		t.Fatal(err)
	}
	apply()
	check(":7098")
	if err := stopManagedProcess(r.statePath(realmPIDFile)); err != nil {
		t.Fatal(err)
	}
	apply()
	check(":7098")
	plan.Rules[0].TargetPort = 9999
	if _, err := r.applyPortForwards(plan); err == nil {
		t.Fatal("failed child accepted")
	}
	if r.forwardDesiredState != "" {
		t.Fatal("failed apply retained shortcut")
	}
	check(":7098")
	data, err := r.stateRead(portForwardsCurrent)
	if err != nil || strings.Contains(string(data), "9999") {
		t.Fatalf("failed plan committed: %s %v", data, err)
	}
	plan.Rules[0].TargetPort = 7098
	apply()
}

func TestRealmRejectsStopFailureAndEarlyExit(t *testing.T) {
	dir := installRealmChild(t)
	r := New(Config{StateDir: t.TempDir()})
	rules := []forwardRule{{PortForward: model.PortForward{ID: 1, TargetAddress: "203.0.113.2", TargetPort: 7098, ListenPort: 24432}}}
	record := fmt.Sprintf("{\"pid\":%d,\"command\":\"unrelated\",\"start_token\":\"wrong\"}", os.Getpid())
	if err := os.WriteFile(r.statePath(realmPIDFile), []byte(record), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := r.applyRealmForwards(rules); err == nil || !strings.Contains(err.Error(), "stop previous realm") {
		t.Fatalf("stop error=%v", err)
	}
	if err := os.Remove(r.statePath(realmPIDFile)); err != nil {
		t.Fatal(err)
	}
	writeFakeRealm(t, dir, "#!/bin/sh\nexit 0\n")
	if err := r.applyRealmForwards(rules); err == nil || !strings.Contains(err.Error(), "exited before ready") {
		t.Fatalf("exit error=%v", err)
	}
	if _, err := os.Stat(r.statePath(realmPIDFile)); !os.IsNotExist(err) {
		t.Fatalf("failed child left pid: %v", err)
	}
}
