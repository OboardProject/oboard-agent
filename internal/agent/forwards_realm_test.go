package agent

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/OboardProject/oboard-agent/internal/model"
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
	want := filepath.Join(dir, "oboard-realm")
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
	writeFakeRealm(t, dir, "#!/bin/sh\nsleep 30\n")
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
	if err := os.WriteFile(legacy, []byte("#!/bin/sh\nsleep 30\n"), 0o755); err != nil {
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
