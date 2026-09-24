//go:build windows

package agent

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/windows"
)

func processGroupAttr() *syscall.SysProcAttr {
	return &syscall.SysProcAttr{HideWindow: true, CreationFlags: windows.CREATE_NEW_PROCESS_GROUP}
}

// terminateProcessGroup ends the command and every process it started.
// Windows has no process-group signal, so the tree is walked by taskkill from
// the system directory.
func terminateProcessGroup(cmd *exec.Cmd) error {
	if cmd == nil || cmd.Process == nil {
		return nil
	}
	system, err := windows.GetSystemDirectory()
	if err != nil {
		return cmd.Process.Kill()
	}
	// #nosec G204 -- taskkill resolves to the system directory and the PID is an integer.
	kill := exec.Command(filepath.Join(system, "taskkill.exe"), "/T", "/F", "/PID", fmt.Sprint(cmd.Process.Pid))
	kill.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	done := make(chan error, 1)
	if err := kill.Start(); err != nil {
		return cmd.Process.Kill()
	}
	go func() { done <- kill.Wait() }()
	select {
	case err := <-done:
		if err != nil {
			_ = cmd.Process.Kill()
		}
		return nil
	case <-time.After(remoteExecGrace):
		_ = kill.Process.Kill()
		return cmd.Process.Kill()
	}
}

func killProcessGroup(cmd *exec.Cmd) {
	_ = terminateProcessGroup(cmd)
}

func processAlive(pid int) bool {
	if pid <= 0 {
		return false
	}
	handle, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, uint32(pid))
	if err != nil {
		return false
	}
	defer windows.CloseHandle(handle)
	var code uint32
	if err := windows.GetExitCodeProcess(handle, &code); err != nil {
		return false
	}
	const stillActive = 259
	return code == stillActive
}

// fileIsExecutable reports a Windows executable by extension; NTFS has no
// execute permission bit that os.FileMode could reflect.
func fileIsExecutable(path string, _ os.FileInfo) bool {
	return strings.EqualFold(filepath.Ext(path), ".exe")
}

// platformProcessImage returns the full image path of pid, which replaces the
// procfs command line when matching a managed process by name.
func platformProcessImage(pid int) (string, bool) {
	if pid <= 0 {
		return "", false
	}
	handle, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, uint32(pid))
	if err != nil {
		return "", true
	}
	defer windows.CloseHandle(handle)
	buf := make([]uint16, windows.MAX_LONG_PATH)
	size := uint32(len(buf))
	if err := windows.QueryFullProcessImageName(handle, 0, &buf[0], &size); err != nil {
		return "", true
	}
	return windows.UTF16ToString(buf[:size]), true
}

// platformProcessStartToken returns the process creation time. Together with
// the PID it identifies one process instance, as the procfs start time does
// on Linux, so a recycled PID is never mistaken for a managed process.
func platformProcessStartToken(pid int) (string, bool) {
	if pid <= 0 {
		return "", true
	}
	handle, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, uint32(pid))
	if err != nil {
		return "", true
	}
	defer windows.CloseHandle(handle)
	var creation, exit, kernel, user windows.Filetime
	if err := windows.GetProcessTimes(handle, &creation, &exit, &kernel, &user); err != nil {
		return "", true
	}
	if !processAlive(pid) {
		return "", true
	}
	return fmt.Sprint(creation.Nanoseconds()), true
}

// backgroundProcessAttr starts a managed helper without a console window. A
// console program started from a service would otherwise get a console of its
// own in session 0.
func backgroundProcessAttr() *syscall.SysProcAttr {
	return &syscall.SysProcAttr{HideWindow: true, CreationFlags: windows.CREATE_NO_WINDOW}
}
