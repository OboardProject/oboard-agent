//go:build !windows

package agent

import (
	"os"
	"os/exec"
	"syscall"
	"time"
)

func processGroupAttr() *syscall.SysProcAttr {
	return &syscall.SysProcAttr{Setpgid: true}
}

func signalProcessGroup(cmd *exec.Cmd, signal syscall.Signal) error {
	if cmd == nil || cmd.Process == nil {
		return nil
	}
	return syscall.Kill(-cmd.Process.Pid, signal)
}

func terminateProcessGroup(cmd *exec.Cmd) error {
	return signalProcessGroup(cmd, syscall.SIGTERM)
}

// killProcessGroup clears whatever survived the command itself. The leader is
// already reaped by Wait, so group membership is probed with signal 0 rather
// than waited on: a second Wait on the same process would race the one that
// collected the exit status.
func killProcessGroup(cmd *exec.Cmd) {
	if cmd == nil || cmd.Process == nil {
		return
	}
	if signalProcessGroup(cmd, syscall.SIGTERM) != nil {
		return
	}
	deadline := time.Now().Add(remoteExecGrace)
	for time.Now().Before(deadline) {
		if signalProcessGroup(cmd, 0) != nil {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	_ = signalProcessGroup(cmd, syscall.SIGKILL)
}

func processAlive(pid int) bool {
	return syscall.Kill(pid, syscall.Signal(0)) == nil
}

func fileIsExecutable(_ string, info os.FileInfo) bool {
	return info.Mode().Perm()&0o111 != 0
}

// platformProcessImage and platformProcessStartToken defer to procfs and ps
// on Unix.
func platformProcessImage(int) (string, bool)      { return "", false }
func platformProcessStartToken(int) (string, bool) { return "", false }

// backgroundProcessAttr keeps the default process attributes for managed
// helper processes on Unix.
func backgroundProcessAttr() *syscall.SysProcAttr { return nil }
