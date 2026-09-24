//go:build !windows

package agent

// executableSuffix is appended to every managed binary name on this platform.
const executableSuffix = ""

// managedPathUnsafeChars must never appear in a managed path. Uninstall
// renders these paths into a root /bin/sh script, so a quote or substitution
// character would only ever be an attempt to escape the quoting rather than a
// legitimate installation directory.
const managedPathUnsafeChars = "'\"`$\\;&|<>()*?[]{}!#~ \t\n\r"

func defaultCoreAPISocket() string { return "/run/oboard-sb.sock" }

// DefaultStateDir is the Agent state directory when none is configured.
func DefaultStateDir() string { return "/var/lib/oboard-agent" }

// DefaultConfigPath is the system Agent configuration written by the installer.
func DefaultConfigPath() string { return "/etc/oboard-agent/config.json" }

func platformCoreBinaryDirs() []string { return nil }

func runningElevated() bool { return runningAsRoot() }

func platformLogDir() string { return "/var/log" }
