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
	StateDir       string
	ProfilePath    string
	CoreService    string
	ServiceManager string
}

func (r *Runner) uninstallAgent(payloadJSON string) (map[string]any, error) {
	var payload model.UninstallAgentTaskPayload
	if err := json.Unmarshal([]byte(payloadJSON), &payload); err != nil {
		return map[string]any{"message": "agent uninstall failed"}, err
	}
	if os.Geteuid() != 0 {
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
		configPath = "/etc/oboard-agent/config.json"
	}
	profileDir := strings.TrimSpace(os.Getenv("OBOARD_PROFILE_DIR"))
	if profileDir == "" {
		profileDir = "/etc/profile.d"
	}
	manager := serviceManager()
	if manager != "systemd" && manager != "openrc" {
		return uninstallPaths{}, fmt.Errorf("supported service manager is unavailable")
	}
	return uninstallPaths{
		AgentPath:      agentPath,
		CorePath:       corePath,
		RealmPath:      realmPath,
		InstallDir:     installDir,
		ConfigPath:     filepath.Clean(configPath),
		StateDir:       r.stateDir(),
		ProfilePath:    filepath.Join(profileDir, "oboard-agent.sh"),
		CoreService:    r.coreService(),
		ServiceManager: manager,
	}, nil
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
	removeManagedServiceFile("oboard-sb")
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
	command := uninstallFinalizerCommand(paths)
	switch paths.ServiceManager {
	case "systemd":
		unit := fmt.Sprintf("oboard-agent-uninstall-%d", os.Getpid())
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
			"systemctl stop oboard-agent oboard-sb 2>/dev/null || true",
			"systemctl disable oboard-agent oboard-sb 2>/dev/null || true",
			"rm -f /etc/systemd/system/oboard-agent.service /etc/systemd/system/oboard-sb.service",
			"systemctl daemon-reload 2>/dev/null || true",
		)
	} else {
		parts = append(parts,
			"rc-service oboard-agent stop 2>/dev/null || true",
			"rc-service oboard-sb stop 2>/dev/null || true",
			"rc-update del oboard-agent default 2>/dev/null || true",
			"rc-update del oboard-sb default 2>/dev/null || true",
			"rm -f /etc/init.d/oboard-agent /etc/init.d/oboard-sb",
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
		"rm -rf "+shellQuoteValue(filepath.Dir(paths.ConfigPath)),
		"rm -rf "+shellQuoteValue(paths.StateDir),
	)
	if manager == "systemd" {
		parts = append(parts, "systemctl daemon-reload 2>/dev/null || true")
	}
	return strings.Join(parts, "; ")
}

func stopManagedService(manager, service string) error {
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

func shellQuoteValue(value string) string {
	return "'" + strings.ReplaceAll(value, "'", `'\\''`) + "'"
}
