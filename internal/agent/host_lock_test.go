package agent

import (
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/OboardProject/oboard-agent/internal/model"
)

// holdHostCoreLock takes the same advisory lock the shell installer takes with
// flock(1), so the test stands in for an operator update running over SSH.
func holdHostCoreLock(t *testing.T, stateDir string) func() {
	t.Helper()
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		t.Fatal(err)
	}
	file, err := os.OpenFile(filepath.Join(stateDir, hostCoreLockName), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if err := syscall.Flock(int(file.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		_ = file.Close()
		t.Skipf("filesystem does not support advisory locking: %v", err)
	}
	return func() {
		_ = syscall.Flock(int(file.Fd()), syscall.LOCK_UN)
		_ = file.Close()
	}
}

func shortenHostCoreLockWait(t *testing.T) {
	t.Helper()
	previous := hostCoreLockWait
	hostCoreLockWait = 300 * time.Millisecond
	t.Cleanup(func() { hostCoreLockWait = previous })
}

// A shell update and a Controller-driven apply both change the kernel. The Go
// mutex only covers this process, so the two are serialized with an advisory
// file lock that flock(1) in the installer takes as well.
func TestApplyCoreConfigDefersToConcurrentHostUpdate(t *testing.T) {
	shortenHostCoreLockWait(t)
	dir := t.TempDir()
	release := holdHostCoreLock(t, dir)
	defer release()

	r := New(Config{StateDir: dir, CoreBinary: filepath.Join(dir, "missing-sb"), ReloadCommand: "none", RestartCommand: "none", ResourceProfile: "large"})
	result, err := r.applyCoreConfigTask(51, model.ApplyCoreConfigTaskPayload{Config: `{"log":{"level":"info"}}`})
	if !errors.Is(err, errHostCoreLockBusy) {
		t.Fatalf("apply did not defer to the host update: err=%v result=%#v", err, result)
	}
	if result["reload_strategy"] != "host_lock_busy" {
		t.Fatalf("reload_strategy = %v", result["reload_strategy"])
	}
	if _, statErr := os.Stat(filepath.Join(dir, "sing-box.json")); !os.IsNotExist(statErr) {
		t.Fatalf("a deferred apply must not write the kernel configuration: %v", statErr)
	}
}

// The lock is released once the apply finishes, so an operator update queued
// behind a deployment is not blocked forever.
func TestApplyCoreConfigReleasesHostLock(t *testing.T) {
	shortenHostCoreLockWait(t)
	dir := t.TempDir()
	r := New(Config{StateDir: dir, CoreBinary: filepath.Join(dir, "missing-sb"), ReloadCommand: "none", RestartCommand: "none", ResourceProfile: "large"})
	if _, err := r.applyCoreConfigTask(52, model.ApplyCoreConfigTaskPayload{Config: `{"log":{"level":"info"}}`}); err != nil {
		t.Fatal(err)
	}
	release := holdHostCoreLock(t, dir)
	release()
}

// A state directory that cannot hold a lock file must not stop deployments: the
// lock coordinates with an external process, it does not authorize the work.
func TestHostCoreLockToleratesUnusableStateDir(t *testing.T) {
	r := New(Config{StateDir: filepath.Join(os.DevNull, "state"), ResourceProfile: "large"})
	lock, err := r.acquireHostCoreLock(time.Second)
	if err != nil {
		t.Fatalf("unusable lock path must not fail the task: %v", err)
	}
	lock.release()
}
