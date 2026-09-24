//go:build windows

package agent

import (
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"time"
	"unicode/utf16"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

func openWindowsService(name string) (*mgr.Mgr, *mgr.Service, error) {
	manager, err := mgr.Connect()
	if err != nil {
		return nil, nil, fmt.Errorf("connect service control manager: %w", err)
	}
	service, err := manager.OpenService(name)
	if err != nil {
		_ = manager.Disconnect()
		return nil, nil, fmt.Errorf("open service %s: %w", name, err)
	}
	return manager, service, nil
}

func windowsServiceState(name string) (svc.State, error) {
	manager, service, err := openWindowsService(name)
	if err != nil {
		return 0, err
	}
	defer manager.Disconnect()
	defer service.Close()
	status, err := service.Query()
	if err != nil {
		return 0, err
	}
	return status.State, nil
}

func windowsServiceActive(name string) error {
	state, err := windowsServiceState(name)
	if err != nil {
		return err
	}
	if state != svc.Running {
		return fmt.Errorf("service %s is not running (state %d)", name, state)
	}
	return nil
}

func waitWindowsServiceState(service *mgr.Service, want svc.State, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for {
		status, err := service.Query()
		if err != nil {
			return err
		}
		if status.State == want {
			return nil
		}
		if want == svc.Running && status.State == svc.Stopped && status.Win32ExitCode != 0 {
			return fmt.Errorf("service exited with code %d", status.Win32ExitCode)
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("service did not reach state %d within %s (state %d)", want, timeout, status.State)
		}
		time.Sleep(200 * time.Millisecond)
	}
}

func windowsServiceStart(name string, timeout time.Duration) error {
	manager, service, err := openWindowsService(name)
	if err != nil {
		return err
	}
	defer manager.Disconnect()
	defer service.Close()
	if status, err := service.Query(); err == nil && status.State == svc.Running {
		return nil
	}
	if err := service.Start(); err != nil && !errors.Is(err, windows.ERROR_SERVICE_ALREADY_RUNNING) {
		return fmt.Errorf("start service %s: %w", name, err)
	}
	return waitWindowsServiceState(service, svc.Running, timeout)
}

func windowsServiceStop(name string, timeout time.Duration) error {
	manager, service, err := openWindowsService(name)
	if err != nil {
		return err
	}
	defer manager.Disconnect()
	defer service.Close()
	status, err := service.Query()
	if err != nil {
		return err
	}
	if status.State == svc.Stopped {
		return nil
	}
	if status.State != svc.StopPending {
		if _, err := service.Control(svc.Stop); err != nil && !errors.Is(err, windows.ERROR_SERVICE_NOT_ACTIVE) {
			return fmt.Errorf("stop service %s: %w", name, err)
		}
	}
	return waitWindowsServiceState(service, svc.Stopped, timeout)
}

func windowsServiceRestart(name string, timeout time.Duration) error {
	if err := windowsServiceStop(name, timeout); err != nil {
		return err
	}
	return windowsServiceStart(name, timeout)
}

// scheduleWindowsAgentRestart restarts the Agent's own service from a detached
// process. A service cannot stop and start itself, and SCM does not terminate
// a child that left the service's console, so the helper outlives the stop.
func scheduleWindowsAgentRestart(service string) error {
	return runDetachedPowerShell(fmt.Sprintf("Start-Sleep -Seconds 5; Restart-Service -Name '%s' -Force", strings.ReplaceAll(service, "'", "''")))
}

// windowsPowerShell resolves Windows PowerShell from the system directory
// instead of PATH, so a writable PATH entry cannot substitute the binary that
// runs with the Agent's privileges.
func windowsPowerShell() (string, error) {
	system, err := windows.GetSystemDirectory()
	if err != nil {
		return "", err
	}
	path := system + `\WindowsPowerShell\v1.0\powershell.exe`
	if _, err := os.Stat(path); err != nil {
		return "", fmt.Errorf("windows powershell is unavailable: %w", err)
	}
	return path, nil
}

// runDetachedPowerShell starts script in a hidden PowerShell that outlives the
// Agent service. The script travels as -EncodedCommand so no path in it is
// reinterpreted by a command-line parser.
func runDetachedPowerShell(script string) error {
	powershell, err := windowsPowerShell()
	if err != nil {
		return err
	}
	encoded := utf16.Encode([]rune(script))
	raw := make([]byte, 0, len(encoded)*2)
	for _, unit := range encoded {
		raw = append(raw, byte(unit), byte(unit>>8))
	}
	// #nosec G204 -- powershell resolves to the system installation and the script is Agent-rendered.
	cmd := exec.Command(powershell, "-NoLogo", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-EncodedCommand", base64.StdEncoding.EncodeToString(raw))
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: windows.CREATE_NEW_PROCESS_GROUP | windows.DETACHED_PROCESS}
	if err := cmd.Start(); err != nil {
		return err
	}
	return cmd.Process.Release()
}
