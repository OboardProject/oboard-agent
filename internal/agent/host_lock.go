package agent

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"time"
)

// The Agent serializes its own kernel lifecycle work with coreLifecycleMu, but
// that mutex only exists inside this process. A shell update running from SSH
// replaces the binaries and restarts the kernel with no knowledge of it, so an
// operator update and a Controller-driven apply_deployment could interleave.
//
// hostCoreLock is the shared boundary: an advisory flock(2) on a file both
// sides agree on. The installer takes the same lock with flock(1), which uses
// the same kernel primitive, so the two serialize against each other.
const hostCoreLockName = "core-lifecycle.lock"

// hostCoreLockWait bounds how long a task waits for an operator update to
// finish. Failing after this is better than a task that hangs until the
// Controller times it out with no explanation. It is a var so tests do not have
// to wait out the production window.
var hostCoreLockWait = 90 * time.Second

// errHostCoreLockBusy is returned when another process holds the lock. It is a
// real task failure: something else is changing the kernel right now, and
// applying on top of it would race the file it is installing.
var errHostCoreLockBusy = errors.New("另一个 OBoard 更新或内核操作正在进行，请稍后重试")

func (r *Runner) hostCoreLockPath() string {
	return filepath.Join(r.stateDir(), hostCoreLockName)
}

type hostCoreLock struct {
	file *os.File
}

func (l *hostCoreLock) release() {
	if l == nil || l.file == nil {
		return
	}
	_ = syscall.Flock(int(l.file.Fd()), syscall.LOCK_UN)
	_ = l.file.Close()
	l.file = nil
}

// acquireHostCoreLock takes the cross-process kernel lifecycle lock.
//
// A lock file that cannot be created at all (read-only or missing state
// directory) is not a reason to refuse work: the lock is a coordination aid,
// and the Agent still holds coreLifecycleMu. Only genuine contention fails,
// because that means another process is actively mutating the same files.
func (r *Runner) acquireHostCoreLock(timeout time.Duration) (*hostCoreLock, error) {
	if timeout <= 0 {
		timeout = hostCoreLockWait
	}
	dir := r.stateDir()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return &hostCoreLock{}, nil
	}
	path := r.hostCoreLockPath()
	// #nosec G304 -- a fixed file name below the Agent's configured state directory.
	file, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return &hostCoreLock{}, nil
	}
	deadline := time.Now().Add(timeout)
	for {
		if err := syscall.Flock(int(file.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err == nil {
			_ = file.Truncate(0)
			_, _ = file.WriteAt([]byte(fmt.Sprintf("agent %d\n", os.Getpid())), 0)
			return &hostCoreLock{file: file}, nil
		} else if !errors.Is(err, syscall.EWOULDBLOCK) && !errors.Is(err, syscall.EAGAIN) {
			// The filesystem does not support advisory locking. Proceed rather
			// than block every deployment on a coordination aid.
			_ = file.Close()
			return &hostCoreLock{}, nil
		}
		if time.Now().After(deadline) {
			_ = file.Close()
			return nil, errHostCoreLockBusy
		}
		time.Sleep(250 * time.Millisecond)
	}
}
