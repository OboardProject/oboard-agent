package agent

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/OboardProject/oboard-agent/internal/model"
)

type uninstallPaths struct {
	AgentPath      string
	CorePath       string
	RealmPath      string
	InstallDir     string
	ConfigPath     string
	ConfigDir      string
	KeyPath        string
	StateDir       string
	ProfilePath    string
	CoreService    string
	AgentService   string
	AgentLog       string
	CoreLog        string
	CoreSocket     string
	RuntimeDir     string
	Stealth        bool
	ServiceManager string
}

func (r *Runner) uninstallAgent(payloadJSON string) (map[string]any, error) {
	var payload model.UninstallAgentTaskPayload
	if err := json.Unmarshal([]byte(payloadJSON), &payload); err != nil {
		return map[string]any{"message": "agent uninstall failed"}, err
	}
	if !runningElevated() {
		return map[string]any{"message": "agent uninstall requires root"}, fmt.Errorf("remote uninstall requires root")
	}
	paths, err := r.uninstallPaths()
	if err != nil {
		return map[string]any{"message": "agent uninstall failed", "purge": payload.Purge}, err
	}
	if err := prepareAgentUninstall(paths); err != nil {
		return map[string]any{"message": "agent uninstall failed", "purge": payload.Purge}, err
	}
	return map[string]any{
		"message":    "Agent 已开始远程卸载，主服务将在回执后停止并清理",
		"purge":      payload.Purge,
		"agent_path": paths.AgentPath,
		"core_path":  paths.CorePath,
		"realm_path": paths.RealmPath,
		"state_dir":  paths.StateDir,
		"finalize":   "after_result_acknowledged",
	}, nil
}

func (r *Runner) uninstallPaths() (uninstallPaths, error) {
	targets, err := r.signedReleaseTargets()
	if err != nil {
		return uninstallPaths{}, err
	}
	agentPath := filepath.Clean(targets.Agent)
	corePath := filepath.Clean(targets.Core)
	realmPath := filepath.Clean(targets.Realm)
	installDir := filepath.Dir(agentPath)
	configPath := strings.TrimSpace(r.Config().ConfigPath)
	if configPath == "" {
		configPath = DefaultConfigPath()
	}
	profileDir := strings.TrimSpace(os.Getenv("OBOARD_PROFILE_DIR"))
	if profileDir == "" {
		profileDir = "/etc/profile.d"
	}
	manager := serviceManager()
	if manager != "systemd" && manager != "openrc" && manager != serviceManagerWindows {
		return uninstallPaths{}, fmt.Errorf("supported service manager is unavailable")
	}
	paths := uninstallPaths{
		AgentPath:      agentPath,
		CorePath:       corePath,
		RealmPath:      realmPath,
		InstallDir:     installDir,
		ConfigPath:     filepath.Clean(configPath),
		ConfigDir:      filepath.Dir(filepath.Clean(configPath)),
		StateDir:       r.stateDir(),
		ProfilePath:    filepath.Join(profileDir, "oboard-agent.sh"),
		CoreService:    r.coreService(),
		AgentService:   r.agentService(),
		AgentLog:       r.agentLogPath(),
		CoreLog:        r.coreLogPath(),
		CoreSocket:     r.coreAPISocketPath(),
		ServiceManager: manager,
	}
	if r.stealthOn() && r.Config().Stealth != nil {
		paths.Stealth = true
		paths.KeyPath = r.Config().Stealth.KeyPath
		if runtimeDir, ok := r.tunnelRuntimeDir(); ok {
			paths.RuntimeDir = runtimeDir
		}
	}
	return paths, nil
}

func prepareAgentUninstall(paths uninstallPaths) error {
	_ = stopManagedService(paths.ServiceManager, paths.CoreService)
	_ = os.Remove(paths.CorePath)
	// The bundled forwarding process is an Agent child rather than a service, so
	// stop it through its managed PID record before removing the binary.
	if strings.TrimSpace(paths.StateDir) != "" {
		_ = stopManagedProcess(filepath.Join(paths.StateDir, realmPIDFile))
	}
	if strings.TrimSpace(paths.RealmPath) != "" {
		_ = os.Remove(paths.RealmPath)
	}
	_ = os.Remove(filepath.Join(paths.InstallDir, "obag"))
	removeProfileIfManaged(paths.InstallDir, paths.ProfilePath)
	removeManagedServiceFile(paths.CoreService)
	return nil
}

func (r *Runner) finalizeAgentUninstall() error {
	paths, err := r.uninstallPaths()
	if err != nil {
		return err
	}
	return scheduleAgentUninstallFinalizer(paths)
}

func scheduleAgentUninstallFinalizer(paths uninstallPaths) error {
	if paths.ServiceManager == serviceManagerWindows {
		return runDetachedPowerShell(uninstallFinalizerPowerShell(paths))
	}
	command := uninstallFinalizerCommand(paths)
	switch paths.ServiceManager {
	case "systemd":
		unit := fmt.Sprintf("%s-uninstall-%d", paths.AgentService, os.Getpid())
		return runCommand(10*time.Second, "systemd-run", "--quiet", "--collect", "--on-active=5s", "--unit", unit, "/bin/sh", "-c", command)
	case "openrc":
		wrapped := "sleep 5; " + command
		return runCommand(5*time.Second, "sh", "-c", "nohup sh -c "+shellQuoteValue(wrapped)+" >/dev/null 2>&1 &")
	default:
		return fmt.Errorf("supported service manager is unavailable")
	}
}

func uninstallFinalizerCommand(paths uninstallPaths) string {
	manager := paths.ServiceManager
	var parts []string
	if manager == "systemd" {
		parts = append(parts,
			"systemctl stop "+shellQuoteValue(paths.AgentService)+" "+shellQuoteValue(paths.CoreService)+" 2>/dev/null || true",
			"systemctl disable "+shellQuoteValue(paths.AgentService)+" "+shellQuoteValue(paths.CoreService)+" 2>/dev/null || true",
			"rm -f "+shellQuoteValue(serviceUnitPath("systemd", paths.AgentService))+" "+shellQuoteValue(serviceUnitPath("systemd", paths.CoreService)),
			"systemctl daemon-reload 2>/dev/null || true",
		)
	} else {
		parts = append(parts,
			"rc-service "+shellQuoteValue(paths.AgentService)+" stop 2>/dev/null || true",
			"rc-service "+shellQuoteValue(paths.CoreService)+" stop 2>/dev/null || true",
			"rc-update del "+shellQuoteValue(paths.AgentService)+" default 2>/dev/null || true",
			"rc-update del "+shellQuoteValue(paths.CoreService)+" default 2>/dev/null || true",
			"rm -f "+shellQuoteValue(serviceUnitPath("openrc", paths.AgentService))+" "+shellQuoteValue(serviceUnitPath("openrc", paths.CoreService)),
		)
	}
	parts = append(parts,
		"rm -f "+shellQuoteValue(paths.AgentPath),
		"rm -f "+shellQuoteValue(paths.CorePath),
		"rm -f "+shellQuoteValue(filepath.Join(paths.InstallDir, "obag")),
	)
	if strings.TrimSpace(paths.RealmPath) != "" {
		parts = append(parts, "rm -f "+shellQuoteValue(paths.RealmPath))
	}
	if strings.TrimSpace(paths.ProfilePath) != "" {
		parts = append(parts, "rm -f "+shellQuoteValue(paths.ProfilePath))
	}
	parts = append(parts,
		"rm -rf "+shellQuoteValue(paths.ConfigDir),
		"rm -rf "+shellQuoteValue(paths.StateDir),
		"rm -f "+shellQuoteValue(paths.AgentLog)+" "+shellQuoteValue(paths.CoreLog)+" "+shellQuoteValue(paths.CoreSocket),
	)
	if paths.Stealth && paths.RuntimeDir != "" {
		parts = append(parts, "rm -rf "+shellQuoteValue(paths.RuntimeDir))
	}
	if paths.Stealth {
		// The hidden install directory carries a random name; once its
		// binaries are gone an empty directory is pure leftover. rmdir
		// never removes a directory that still holds anything.
		parts = append(parts, "rmdir "+shellQuoteValue(paths.InstallDir)+" 2>/dev/null || true")
	}
	if manager == "systemd" {
		parts = append(parts, "systemctl daemon-reload 2>/dev/null || true")
	}
	return strings.Join(parts, "; ")
}

// uninstallFinalizerPowerShell renders the Windows finalizer. It runs detached
// after the task result is acknowledged, stops and deletes both services, and
// removes the installation. Every binary, configuration, state, and log path
// lives below one installation root on Windows, so a standard layout removes
// that root as a whole.
func uninstallFinalizerPowerShell(paths uninstallPaths) string {
	quote := func(value string) string { return "'" + strings.ReplaceAll(value, "'", "''") + "'" }
	lines := []string{
		"$ErrorActionPreference = 'SilentlyContinue'",
		"Start-Sleep -Seconds 5",
	}
	for _, service := range []string{paths.CoreService, paths.AgentService} {
		lines = append(lines,
			"Stop-Service -Name "+quote(service)+" -Force",
			"& \"$env:SystemRoot\\System32\\sc.exe\" delete "+quote(service)+" | Out-Null",
		)
	}
	lines = append(lines, "Start-Sleep -Seconds 2")
	files := []string{paths.AgentPath, paths.CorePath, paths.RealmPath, paths.AgentLog, paths.CoreLog, paths.CoreSocket}
	for _, file := range files {
		if strings.TrimSpace(file) != "" {
			lines = append(lines, "Remove-Item -LiteralPath "+quote(file)+" -Force")
		}
	}
	lines = append(lines,
		"Remove-Item -LiteralPath "+quote(paths.ConfigDir)+" -Recurse -Force",
		"Remove-Item -LiteralPath "+quote(paths.StateDir)+" -Recurse -Force",
	)
	if root := filepath.Dir(paths.InstallDir); strings.EqualFold(filepath.Base(paths.InstallDir), "bin") && root != paths.InstallDir {
		lines = append(lines, "Remove-Item -LiteralPath "+quote(root)+" -Recurse -Force")
	}
	return strings.Join(lines, "\r\n")
}

func stopManagedService(manager, service string) error {
	if manager == serviceManagerWindows {
		return windowsServiceStop(service, 20*time.Second)
	}
	if manager == "systemd" {
		return runCommand(20*time.Second, "systemctl", "stop", service)
	}
	if manager == "openrc" {
		return runCommand(20*time.Second, "rc-service", service, "stop")
	}
	return fmt.Errorf("supported service manager is unavailable")
}

func removeProfileIfManaged(installDir, profilePath string) {
	content, err := os.ReadFile(profilePath)
	if err != nil || !strings.Contains(string(content), installDir) {
		return
	}
	_ = os.Remove(profilePath)
}

func removeManagedServiceFile(service string) {
	for _, path := range []string{"/etc/systemd/system/" + service + ".service", "/etc/init.d/" + service} {
		_ = os.Remove(path)
	}
}

// shellQuoteValue wraps value in POSIX single quotes. An embedded single quote
// must close the quoted run, contribute one backslash-escaped quote, and reopen
// the run. Writing that replacement as a Go raw literal emits a second
// backslash, which ends the quoting early and leaves the rest of the value as
// live shell syntax, so it has to stay an interpreted string.
func shellQuoteValue(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "'\\''") + "'"
}
