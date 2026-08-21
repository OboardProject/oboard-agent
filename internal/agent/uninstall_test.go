package agent

import (
	"os"
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
