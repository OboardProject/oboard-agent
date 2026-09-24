package agent

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestExecutableBaseStripsPlatformSuffix(t *testing.T) {
	path := filepath.Join(t.TempDir(), executableName("oboard-sb"))
	if got := executableBase(path); got != "oboard-sb" {
		t.Fatalf("executableBase(%q) = %q", path, got)
	}
	if got := executableBase(filepath.Join(t.TempDir(), "oboard-sb.json")); got != "oboard-sb.json" {
		t.Fatalf("a non-executable suffix must be kept, got %q", got)
	}
}

// The Windows uninstall finalizer runs detached as LocalSystem. Every path is
// a single-quoted PowerShell literal, and the whole installation root is
// removed only for the standard <root>\bin layout.
func TestUninstallFinalizerPowerShellQuotesPaths(t *testing.T) {
	root := filepath.Join(string(filepath.Separator)+"data", "oboard-agent")
	paths := uninstallPaths{
		AgentPath:    filepath.Join(root, "bin", "oboard-agent.exe"),
		CorePath:     filepath.Join(root, "bin", "oboard-sb.exe"),
		RealmPath:    filepath.Join(root, "bin", "oboard-realm.exe"),
		InstallDir:   filepath.Join(root, "bin"),
		ConfigDir:    filepath.Join(root, "config"),
		StateDir:     filepath.Join(root, "state"),
		AgentLog:     filepath.Join(root, "logs", "oboard-agent.log"),
		CoreLog:      filepath.Join(root, "logs", "oboard-sb.log"),
		CoreSocket:   filepath.Join(root, "run", "oboard-sb.sock"),
		CoreService:  "oboard-sb",
		AgentService: "it's-agent",
	}
	script := uninstallFinalizerPowerShell(paths)
	for _, want := range []string{
		"Stop-Service -Name 'oboard-sb' -Force",
		"Stop-Service -Name 'it''s-agent' -Force",
		"Remove-Item -LiteralPath '" + paths.StateDir + "' -Recurse -Force",
		"Remove-Item -LiteralPath '" + root + "' -Recurse -Force",
	} {
		if !strings.Contains(script, want) {
			t.Fatalf("finalizer missing %q:\n%s", want, script)
		}
	}
	paths.InstallDir = filepath.Join(root, "custom")
	if strings.Contains(uninstallFinalizerPowerShell(paths), "Remove-Item -LiteralPath '"+root+"' -Recurse") {
		t.Fatal("a non-standard layout must not remove the parent directory")
	}
}
