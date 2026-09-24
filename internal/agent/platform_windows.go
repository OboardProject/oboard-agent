//go:build windows

package agent

import (
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/windows"
)

const executableSuffix = ".exe"

// managedPathUnsafeChars must never appear in a managed path. Uninstall
// renders these paths into a PowerShell script inside single quotes, so a
// quote, expansion, or command separator could only be an attempt to escape
// that quoting. The path separator is legitimate on Windows.
const managedPathUnsafeChars = "'\"`$;&|<>()*?[]{}!#~% \t\n\r"

// WindowsAgentRoot is the single installation root on Windows. Binaries,
// configuration, state, logs, and the kernel socket all live below it so the
// installer can protect the whole tree with one ACL (SYSTEM and
// Administrators only).
func WindowsAgentRoot() string {
	programData := strings.TrimSpace(os.Getenv("ProgramData"))
	if programData == "" || !filepath.IsAbs(programData) {
		programData = `C:\ProgramData`
	}
	return filepath.Join(filepath.Clean(programData), "oboard-agent")
}

func defaultCoreAPISocket() string {
	return filepath.Join(WindowsAgentRoot(), "run", "oboard-sb.sock")
}

// DefaultStateDir is the Agent state directory when none is configured.
func DefaultStateDir() string { return filepath.Join(WindowsAgentRoot(), "state") }

// DefaultConfigPath is the system Agent configuration written by the installer.
func DefaultConfigPath() string { return filepath.Join(WindowsAgentRoot(), "config", "config.json") }

func platformCoreBinaryDirs() []string {
	return []string{filepath.Join(WindowsAgentRoot(), "bin")}
}

// runningElevated reports whether the Agent holds an elevated administrator
// token. The Windows service runs as LocalSystem, which always does.
func runningElevated() bool {
	return windows.GetCurrentProcessToken().IsElevated()
}

func platformLogDir() string { return filepath.Join(WindowsAgentRoot(), "logs") }
