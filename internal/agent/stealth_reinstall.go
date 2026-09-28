package agent

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/OboardProject/oboard-agent/internal/stealth"
)

var stealthUnitConfig = regexp.MustCompile(`-config ([A-Za-z0-9_./-]+) -key ([A-Za-z0-9_./-]+)`)

// ListPreviousAgentServices identifies managed service units before a reinstall
// starts its replacement process.
func ListPreviousAgentServices(manager, keepConfig string) ([]string, error) {
	if os.Geteuid() != 0 {
		return nil, fmt.Errorf("listing previous services requires root")
	}
	return listPreviousAgentServices(stealthBootstrapOptions{Manager: manager}.withDefaults(), keepConfig)
}

func listPreviousAgentServices(opts stealthBootstrapOptions, keepConfig string) ([]string, error) {
	if opts.Manager != "systemd" && opts.Manager != "openrc" {
		return nil, fmt.Errorf("unsupported service manager")
	}
	entries, err := os.ReadDir(opts.UnitDir)
	if err != nil {
		return nil, err
	}
	suffix := ""
	if opts.Manager == "systemd" {
		suffix = ".service"
	}
	agents := map[string]bool{}
	cores := map[string]bool{}
	replacementSeen := false
	for _, entry := range entries {
		if entry.IsDir() || entry.Type()&os.ModeSymlink != 0 {
			continue
		}
		unit, err := os.ReadFile(filepath.Join(opts.UnitDir, entry.Name()))
		if err != nil {
			return nil, err
		}
		match := stealthUnitConfig.FindSubmatch(unit)
		if len(match) != 3 {
			continue
		}
		configPath, keyPath := string(match[1]), string(match[2])
		if !strings.HasSuffix(entry.Name(), suffix) || !stealth.ValidName(strings.TrimSuffix(entry.Name(), suffix)) || !strings.HasPrefix(configPath, opts.ConfigParent+string(os.PathSeparator)) {
			continue
		}
		key, err := stealth.LoadKey(keyPath)
		if err != nil {
			return nil, fmt.Errorf("cannot verify managed service %s key: %w", entry.Name(), err)
		}
		cfg, err := LoadConfigWithKey(configPath, key)
		if err != nil {
			cfg, err = LoadConfig(configPath)
			if err != nil {
				return nil, fmt.Errorf("cannot verify managed service %s config: %w", entry.Name(), err)
			}
		}
		if cfg.Stealth == nil || cfg.Stealth.Identity.Validate() != nil {
			return nil, fmt.Errorf("invalid managed service identity in %s", entry.Name())
		}
		layout := stealth.ResolveLayout(cfg.Stealth.Identity, filepath.Dir(cfg.CoreBinary), opts.ConfigParent, opts.StateParent)
		if entry.Name() != layout.AgentService+suffix || configPath != layout.ConfigPath || keyPath != layout.KeyPath || cfg.CoreBinary != layout.CoreBinary || cfg.StateDir != layout.StateDir {
			return nil, fmt.Errorf("inconsistent managed layout in %s", entry.Name())
		}
		expected := "ExecStart=" + layout.AgentBinary + " -config " + layout.ConfigPath + " -key " + layout.KeyPath
		if opts.Manager == "openrc" {
			expected = "command=" + layout.AgentBinary
		}
		if !strings.Contains("\n"+string(unit), "\n"+expected+"\n") {
			return nil, fmt.Errorf("unexpected managed command in %s", entry.Name())
		}
		if configPath == keepConfig {
			replacementSeen = true
			continue
		}
		agents[layout.AgentService] = true
		cores[layout.CoreService] = true
	}
	if !replacementSeen {
		return nil, fmt.Errorf("replacement installation could not be verified")
	}
	for _, service := range []string{"oboard-agent", "oboard-sb"} {
		unit, err := os.ReadFile(filepath.Join(opts.UnitDir, service+suffix))
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			return nil, err
		}
		prefix := "ExecStart="
		if opts.Manager == "openrc" {
			prefix = "command="
		}
		for _, line := range strings.Split(string(unit), "\n") {
			if !strings.HasPrefix(line, prefix) {
				continue
			}
			fields := strings.Fields(strings.TrimPrefix(line, prefix))
			if len(fields) > 0 && filepath.Base(fields[0]) == service {
				if service == "oboard-agent" {
					agents[service] = true
				} else {
					cores[service] = true
				}
			}
		}
	}
	orderedAgents := make([]string, 0, len(agents))
	orderedCores := make([]string, 0, len(cores))
	for service := range agents {
		orderedAgents = append(orderedAgents, service)
	}
	for service := range cores {
		orderedCores = append(orderedCores, service)
	}
	sort.Strings(orderedAgents)
	sort.Strings(orderedCores)
	return append(orderedAgents, orderedCores...), nil
}

// CleanupPreviousAgentInstalls is an installer-only operation. The replacement
// must already be enrolled and running before its installer invokes it.
func CleanupPreviousAgentInstalls(manager, keepConfig string) error {
	if os.Geteuid() != 0 {
		return fmt.Errorf("cleanup requires root")
	}
	opts := stealthBootstrapOptions{Manager: manager}.withDefaults()
	return cleanupPreviousAgentInstalls(opts, keepConfig)
}

func cleanupPreviousAgentInstalls(opts stealthBootstrapOptions, keepConfig string) error {
	if opts.Manager != "systemd" && opts.Manager != "openrc" {
		return fmt.Errorf("unsupported service manager")
	}
	entries, err := os.ReadDir(opts.UnitDir)
	if err != nil {
		return err
	}
	var old []stealth.Layout
	replacementService := ""
	for _, entry := range entries {
		if entry.IsDir() || entry.Type()&os.ModeSymlink != 0 {
			continue
		}
		unit, err := os.ReadFile(filepath.Join(opts.UnitDir, entry.Name()))
		if err != nil {
			return err
		}
		match := stealthUnitConfig.FindSubmatch(unit)
		if len(match) != 3 {
			continue
		}
		configPath, keyPath := string(match[1]), string(match[2])
		key, err := stealth.LoadKey(keyPath)
		if err != nil {
			continue
		}
		cfg, err := LoadConfigWithKey(configPath, key)
		if err != nil {
			// A stealth config that no longer decrypts but parses as plaintext
			// is a broken installation: a runtime writer once replaced the
			// encrypted envelope with a plaintext config. Recognize it so a
			// verified reinstall can remove it; the strict unit-derived checks
			// below still apply unchanged.
			plain, plainErr := LoadConfig(configPath)
			if plainErr != nil {
				continue
			}
			cfg = plain
		}
		if cfg.Stealth == nil || cfg.Stealth.Identity.AgentName == "" {
			continue
		}
		id := cfg.Stealth.Identity
		if err := id.Validate(); err != nil {
			continue
		}
		layout := stealth.ResolveLayout(id, filepath.Dir(cfg.CoreBinary), opts.ConfigParent, opts.StateParent)
		layout.AgentLog = filepath.Join(opts.LogDir, id.AgentLogName+".log")
		layout.CoreLog = filepath.Join(opts.LogDir, id.CoreLogName+".log")
		layout.CoreSocket = filepath.Join(opts.RunDir, id.SocketName+".sock")
		expectedName := layout.AgentService
		if opts.Manager == "systemd" {
			expectedName += ".service"
		}
		if entry.Name() != expectedName {
			continue
		}
		if configPath != layout.ConfigPath || keyPath != layout.KeyPath || cfg.CoreBinary != layout.CoreBinary || cfg.StateDir != layout.StateDir {
			return fmt.Errorf("inconsistent managed layout in %s", entry.Name())
		}
		expectedCommand := "ExecStart=" + layout.AgentBinary + " -config " + layout.ConfigPath + " -key " + layout.KeyPath
		if opts.Manager == "openrc" {
			expectedCommand = "command=" + layout.AgentBinary
		}
		if !strings.Contains("\n"+string(unit), "\n"+expectedCommand+"\n") {
			return fmt.Errorf("unexpected managed command in %s", entry.Name())
		}
		if configPath == keepConfig {
			replacementService = layout.AgentService
			continue
		}
		old = append(old, layout)
	}
	if replacementService == "" {
		return fmt.Errorf("replacement installation could not be verified; keeping previous installations")
	}
	if opts.Manager == "systemd" {
		if err := stealthCommandRunner(15*time.Second, "systemctl", "is-active", "--quiet", replacementService); err != nil {
			return fmt.Errorf("replacement is not running: %w", err)
		}
	} else {
		if err := stealthCommandRunner(15*time.Second, "rc-service", replacementService, "status"); err != nil {
			return fmt.Errorf("replacement is not running: %w", err)
		}
	}
	for _, layout := range old {
		if err := removePreviousInstall(opts, layout); err != nil {
			return err
		}
	}
	return cleanupStandardAgentInstall(opts)
}

func removePreviousInstall(opts stealthBootstrapOptions, layout stealth.Layout) error {
	for _, service := range []string{layout.AgentService, layout.CoreService} {
		var err error
		if opts.Manager == "systemd" {
			err = stealthCommandRunner(20*time.Second, "systemctl", "stop", service)
		} else {
			err = stealthCommandRunner(20*time.Second, "rc-service", service, "stop")
		}
		if err != nil {
			return fmt.Errorf("stop previous service %s: %w", service, err)
		}
	}
	disableServiceUnits(opts.Manager, layout.AgentService, layout.CoreService)
	for _, service := range []string{layout.AgentService, layout.CoreService} {
		name := service
		if opts.Manager == "systemd" {
			name += ".service"
		}
		if err := os.Remove(filepath.Join(opts.UnitDir, name)); err != nil && !os.IsNotExist(err) {
			return err
		}
	}
	for _, path := range []string{layout.AgentBinary, layout.CoreBinary, layout.RealmBinary, layout.ConfigPath, layout.KeyPath, filepath.Join(layout.ConfigDir, "local-security.json"), layout.AgentLog, layout.CoreLog, layout.CoreSocket} {
		if path == "" {
			continue
		}
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			return err
		}
	}
	if err := os.RemoveAll(layout.StateDir); err != nil {
		return err
	}
	_ = os.Remove(layout.ConfigDir)
	removeEmptyAgentInstallDir(filepath.Dir(layout.AgentBinary))
	if opts.Manager == "systemd" {
		return stealthCommandRunner(15*time.Second, "systemctl", "daemon-reload")
	}
	return nil
}

func cleanupStandardAgentInstall(opts stealthBootstrapOptions) error {
	configDir := filepath.Join(opts.ConfigParent, "oboard-agent")
	installDir := ""
	if data, err := os.ReadFile(filepath.Join(configDir, "install.env")); err == nil {
		for _, line := range strings.Split(string(data), "\n") {
			if strings.HasPrefix(line, "OBOARD_INSTALL_DIR=") {
				installDir = strings.Trim(strings.TrimPrefix(line, "OBOARD_INSTALL_DIR="), "'\"")
			}
		}
	}
	candidates := []string{installDir}
	if opts.ConfigParent == "/etc" {
		candidates = append(candidates, "/opt/oboard", "/usr/local/bin", "/usr/local/sbin")
	}
	// Recover a custom install directory from the service when install.env
	// is absent. Only the standard Agent executable is eligible.
	unitName := "oboard-agent"
	if opts.Manager == "systemd" {
		unitName += ".service"
	}
	if data, err := os.ReadFile(filepath.Join(opts.UnitDir, unitName)); err == nil {
		for _, line := range strings.Split(string(data), "\n") {
			for _, prefix := range []string{"ExecStart=", "command="} {
				if strings.HasPrefix(line, prefix) {
					fields := strings.Fields(strings.TrimPrefix(line, prefix))
					if len(fields) > 0 && filepath.Base(fields[0]) == "oboard-agent" {
						candidates = append(candidates, filepath.Dir(fields[0]))
					}
				}
			}
		}
		layout := stealth.Layout{AgentService: "oboard-agent", CoreService: "oboard-sb", ConfigDir: configDir, StateDir: filepath.Join(opts.StateParent, "oboard-agent")}
		// Stop and unregister first; remove files separately without recursively
		// deleting operator-selected installation or configuration directories.
		for _, service := range []string{layout.AgentService, layout.CoreService} {
			var err error
			if opts.Manager == "systemd" {
				err = stealthCommandRunner(20*time.Second, "systemctl", "stop", service)
			} else {
				err = stealthCommandRunner(20*time.Second, "rc-service", service, "stop")
			}
			if err != nil {
				return err
			}
		}
		disableServiceUnits(opts.Manager, layout.AgentService, layout.CoreService)
		for _, service := range []string{layout.AgentService, layout.CoreService} {
			if opts.Manager == "systemd" {
				service += ".service"
			}
			if err := os.Remove(filepath.Join(opts.UnitDir, service)); err != nil && !os.IsNotExist(err) {
				return err
			}
		}
	}
	for _, dir := range candidates {
		if dir == "" {
			continue
		}
		normalized, err := stealth.NormalizeInstallDir(dir)
		if err != nil || normalized == "/" {
			continue
		}
		for _, name := range []string{"oboard-agent", "oboard-sb", "oboard-realm"} {
			if err := os.Remove(filepath.Join(normalized, name)); err != nil && !os.IsNotExist(err) {
				return err
			}
		}
		if target, err := os.Readlink(filepath.Join(normalized, "obag")); err == nil && target == filepath.Join(normalized, "oboard-agent") {
			_ = os.Remove(filepath.Join(normalized, "obag"))
		}
		removeEmptyAgentInstallDir(normalized)
	}
	for _, candidate := range candidates {
		if candidate != "" {
			removeProfileIfManaged(candidate, filepath.Join(opts.ConfigParent, "profile.d", "oboard-agent.sh"))
		}
	}
	for _, name := range []string{"config.json", "install.env", "local-security.json"} {
		if err := os.Remove(filepath.Join(configDir, name)); err != nil && !os.IsNotExist(err) {
			return err
		}
	}
	_ = os.Remove(configDir)
	if err := os.RemoveAll(filepath.Join(opts.StateParent, "oboard-agent")); err != nil {
		return err
	}
	for _, name := range []string{"oboard-agent.log", "oboard-sb.log"} {
		_ = os.Remove(filepath.Join(opts.LogDir, name))
	}
	if opts.Manager == "systemd" {
		return stealthCommandRunner(15*time.Second, "systemctl", "daemon-reload")
	}
	return nil
}

func removeEmptyAgentInstallDir(dir string) {
	switch dir {
	case "", "/", "/usr", "/usr/local", "/usr/local/bin", "/usr/local/sbin", "/usr/bin", "/usr/sbin", "/bin", "/sbin", "/opt", "/etc", "/var", "/var/lib":
		return
	}
	_ = os.Remove(dir)
}
