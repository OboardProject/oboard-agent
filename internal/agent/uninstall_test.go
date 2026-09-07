package agent

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/OboardProject/oboard-agent/internal/model"
)

func TestUninstallAgentTaskRejectsMalformedPayload(t *testing.T) {
	runner := New(Config{StateDir: t.TempDir(), CoreBinary: "oboard-sb"})
	status, result := runner.ExecuteAgentTask(model.AgentTask{
		ID:          12,
		Type:        model.AgentTaskTypeUninstallAgent,
		PayloadJSON: `{"purge":`,
	})
	if status != "failed" {
		t.Fatalf("status=%s result=%s", status, result)
	}
	if !strings.Contains(result, "invalid character") && !strings.Contains(result, "unexpected end") {
		t.Fatalf("unexpected malformed payload result: %s", result)
	}
}

func TestPrepareAgentUninstallRemovesCoreArtifacts(t *testing.T) {
	dir := t.TempDir()
	corePath := filepath.Join(dir, "oboard-sb")
	obagPath := filepath.Join(dir, "obag")
	profilePath := filepath.Join(dir, "profile.d", "oboard-agent.sh")
	if err := os.MkdirAll(filepath.Dir(profilePath), 0o700); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{corePath, obagPath} {
		if err := os.WriteFile(path, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(profilePath, []byte("export PATH=\""+dir+":$PATH\""), 0o600); err != nil {
		t.Fatal(err)
	}
	paths := uninstallPaths{
		AgentPath:      filepath.Join(dir, "oboard-agent"),
		CorePath:       corePath,
		InstallDir:     dir,
		ProfilePath:    profilePath,
		CoreService:    "oboard-sb",
		ServiceManager: "openrc",
	}
	if err := prepareAgentUninstall(paths); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{corePath, obagPath, profilePath} {
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Fatalf("%s still exists: %v", path, err)
		}
	}
	if _, err := os.Stat(paths.AgentPath); !os.IsNotExist(err) {
		t.Fatalf("prepare step should not remove the running agent binary: %v", err)
	}
}

func TestUninstallFinalizerCommandCoversPurgeAndServices(t *testing.T) {
	paths := uninstallPaths{
		AgentPath:      "/opt/oboard/oboard-agent",
		CorePath:       "/opt/oboard/oboard-sb",
		InstallDir:     "/opt/oboard",
		ConfigPath:     "/etc/oboard-agent/config.json",
		StateDir:       "/var/lib/oboard-agent",
		ProfilePath:    "/etc/profile.d/oboard-agent.sh",
		ServiceManager: "systemd",
	}
	command := uninstallFinalizerCommand(paths)
	for _, want := range []string{
		"systemctl stop oboard-agent oboard-sb",
		"systemctl disable oboard-agent oboard-sb",
		"/etc/systemd/system/oboard-agent.service",
		"/opt/oboard/oboard-agent",
		"/etc/oboard-agent",
		"/var/lib/oboard-agent",
	} {
		if !strings.Contains(command, want) {
			t.Fatalf("finalizer command missing %q: %s", want, command)
		}
	}
}

// TestUninstallFinalizerRejectsShellInjectionFromManagedPath runs the rendered
// finalizer through a real /bin/sh to prove that a managed path carrying a
// command substitution stays inert data instead of executing as root.
func TestUninstallFinalizerRejectsShellInjectionFromManagedPath(t *testing.T) {
	dir := t.TempDir()
	marker := filepath.Join(dir, "pwned")
	hostile := "/var/lib/oboard-agent/x'$(touch " + marker + ")'"
	paths := uninstallPaths{
		AgentPath:      "/opt/oboard/oboard-agent",
		CorePath:       "/opt/oboard/oboard-sb",
		InstallDir:     "/opt/oboard",
		ConfigPath:     "/etc/oboard-agent/config.json",
		StateDir:       hostile,
		ServiceManager: "systemd",
	}
	// Render the finalizer and neutralise only the destructive verbs, so the
	// quoting under test is exactly what a real uninstall would execute.
	command := uninstallFinalizerCommand(paths)
	script := strings.NewReplacer("rm -rf ", "echo ", "rm -f ", "echo ", "systemctl", ":").Replace(command)
	out, err := exec.Command("/bin/sh", "-c", script).CombinedOutput()
	if err != nil {
		t.Fatalf("finalizer script did not parse as POSIX sh: %v (%s)", err, out)
	}
	if _, statErr := os.Stat(marker); statErr == nil {
		t.Fatalf("command substitution from state_dir executed: %s", script)
	}
	if !strings.Contains(string(out), hostile) {
		t.Fatalf("state_dir was not passed through literally: %s", out)
	}
}

func TestValidateManagedPathRejectsShellMetacharacters(t *testing.T) {
	for _, value := range []string{
		"/var/lib/oboard-agent/x'$(id)'",
		"/var/lib/oboard-agent/x;reboot",
		"/var/lib/oboard-agent/x`id`",
		"/var/lib/oboard-agent/x y",
		"/var/lib/oboard-agent/x\nrm -rf /",
		"/var/lib/oboard-agent/x|tee",
		"/var/lib/oboard-agent/x&",
		"/var/lib/oboard-agent/x>out",
		"/var/lib/oboard-agent/x*",
	} {
		if err := validateManagedPath("state_dir", value); err == nil {
			t.Fatalf("state_dir %q was accepted", value)
		}
	}
	if err := validateManagedPath("state_dir", "/var/lib/oboard-agent"); err != nil {
		t.Fatalf("ordinary state_dir rejected: %v", err)
	}
	if err := validateManagedPath("state_dir", "/opt/oboard-agent/node-1_state.d"); err != nil {
		t.Fatalf("ordinary state_dir rejected: %v", err)
	}
}

func TestScheduleAgentUninstallFinalizerRejectsUnsupportedManager(t *testing.T) {
	err := scheduleAgentUninstallFinalizer(uninstallPaths{
		AgentPath:      "/tmp/oboard-agent",
		CorePath:       "/tmp/oboard-sb",
		InstallDir:     "/tmp",
		ConfigPath:     "/tmp/config.json",
		StateDir:       "/tmp/state",
		ServiceManager: "unsupported",
	})
	if err == nil || !strings.Contains(err.Error(), "supported service manager") {
		t.Fatalf("unexpected error: %v", err)
	}
}
