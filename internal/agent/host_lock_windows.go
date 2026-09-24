//go:build windows

package agent

import (
	"errors"
	"os"

	"golang.org/x/sys/windows"
)

// The Windows installer takes the same lock by opening the file with
// FileShare.None semantics through LockFileEx, so the Agent and an operator
// update serialize exactly as flock(2) and flock(1) do on Linux.
func tryLockHostFile(file *os.File) error {
	overlapped := new(windows.Overlapped)
	return windows.LockFileEx(windows.Handle(file.Fd()), windows.LOCKFILE_EXCLUSIVE_LOCK|windows.LOCKFILE_FAIL_IMMEDIATELY, 0, 1, 0, overlapped)
}

func unlockHostFile(file *os.File) {
	overlapped := new(windows.Overlapped)
	_ = windows.UnlockFileEx(windows.Handle(file.Fd()), 0, 1, 0, overlapped)
}

func hostLockContended(err error) bool {
	return errors.Is(err, windows.ERROR_LOCK_VIOLATION) || errors.Is(err, windows.ERROR_SHARING_VIOLATION)
}
