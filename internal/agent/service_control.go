package agent

import (
	"errors"
	"strings"
	"time"
)

// allowedManagedService reports whether name is one of this installation's
// managed units. In stealth mode the two units carry generated identity
// names, so the configured names are accepted alongside the fixed ones.
func (r *Runner) allowedManagedService(name string) bool {
	name = strings.TrimSpace(name)
	switch name {
	case "oboard-agent", "oboard-sb":
		return true
	}
	if name != "" && (name == r.agentService() || name == r.coreService()) {
		return true
	}
	return false
}

func (r *Runner) managedServiceStatus(name string) (map[string]any, error) {
	manager := detectServiceManager()
	if name == "" || name == "all" {
		agent, _ := inspectManagedService(manager, r.agentService())
		core, _ := inspectManagedService(manager, r.coreService())
		return map[string]any{"manager": manager, "agent": agent, "core": core}, nil
	}
	if !r.allowedManagedService(name) {
		return nil, errors.New("service is not an OBoard managed unit")
	}
	status, err := inspectManagedService(manager, name)
	return map[string]any{"manager": manager, "service": name, "status": status}, err
}

func (r *Runner) restartManagedService(name string) (map[string]any, error) {
	if !r.allowedManagedService(name) {
		return nil, errors.New("service is not an OBoard managed unit")
	}
	manager := detectServiceManager()
	if name == r.coreService() {
		lock, err := r.acquireHostCoreLock(hostCoreLockWait)
		if err != nil {
			return nil, err
		}
		defer lock.release()
		r.coreLifecycleMu.Lock()
		defer r.coreLifecycleMu.Unlock()
		if err := stopManagedService(manager, name); err != nil {
			return nil, err
		}
		if err := startManagedService(manager, name); err != nil {
			return nil, err
		}
		return map[string]any{"accepted": true, "service": name, "manager": manager}, nil
	}
	if err := r.scheduleAgentRestart(); err != nil {
		return nil, err
	}
	return map[string]any{"accepted": true, "service": name, "manager": manager, "deferred": true}, nil
}

func inspectManagedService(manager, name string) (string, error) {
	if err := managedServiceActive(manager, name); err != nil {
		return "inactive", err
	}
	return "active", nil
}

func invokeHostPowerCommand(action string) error {
	manager := detectServiceManager()
	switch action {
	case "poweroff", "reboot":
	default:
		return errors.New("unsupported host power action")
	}
	switch manager {
	case "systemd":
		return runCommand(15*time.Second, "systemctl", action)
	case "openrc":
		if action == "poweroff" {
			return runCommand(15*time.Second, "poweroff")
		}
		return runCommand(15*time.Second, "reboot")
	default:
		return errors.New("capability_unsupported")
	}
}
