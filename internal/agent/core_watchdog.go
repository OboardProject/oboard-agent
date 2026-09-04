package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/OboardProject/oboard-agent/internal/logging"
)

const (
	coreWatchdogInterval    = 5 * time.Second
	coreWatchdogStableReset = 2 * time.Minute
)

const (
	coreWatchdogStateRunning            = "running"
	coreWatchdogStateRuntimeDrift       = "runtime_drift"
	coreWatchdogStateRuntimeUnreachable = "runtime_unreachable"
	coreWatchdogStateBinaryDrift        = "binary_drift"
	coreWatchdogStateBinaryStale        = "binary_stale"
	coreWatchdogStateRecovering         = "recovering"
	coreWatchdogStateWaitingForConfig   = "waiting_for_config"
	coreWatchdogStateBackoff            = "backoff"
)

type coreWatchdogStatus struct {
	Service             string    `json:"service"`
	State               string    `json:"state"`
	RestartCount        int       `json:"restart_count"`
	Consecutive         int       `json:"consecutive_restarts"`
	LastCheckedAt       time.Time `json:"last_checked_at"`
	LastRestartAt       time.Time `json:"last_restart_at,omitempty"`
	NextAttemptAt       time.Time `json:"next_attempt_at,omitempty"`
	StableSince         time.Time `json:"stable_since,omitempty"`
	LastError           string    `json:"last_error,omitempty"`
	ConfigPath          string    `json:"config_path"`
	RecoveryAction      string    `json:"recovery_action,omitempty"`
	DesiredDigest       string    `json:"desired_digest,omitempty"`
	LoadedDigest        string    `json:"loaded_digest,omitempty"`
	RuntimeVerified     bool      `json:"runtime_verified"`
	RuntimeVerification string    `json:"runtime_verification,omitempty"`
	LastRuntimeCheckAt  time.Time `json:"last_runtime_check_at,omitempty"`
	LastRestartReason   string    `json:"last_restart_reason,omitempty"`
	BuildState          string    `json:"build_state,omitempty"`
	RunningBuild        string    `json:"running_build,omitempty"`
	InstalledBuild      string    `json:"installed_build,omitempty"`
	// BinaryRecoveryBuild latches the installed build a restart was already
	// attempted for, so a kernel that refuses to come up on it is reported
	// once instead of restarted on every backoff window.
	BinaryRecoveryBuild string `json:"binary_recovery_build,omitempty"`
}

func (s *coreWatchdogStatus) applyBuildIdentity(check coreRuntimeCheck) {
	s.BuildState = check.buildState()
	s.RunningBuild = check.RunningBuild.String()
	s.InstalledBuild = check.InstalledBuild.String()
}

func coreWatchdogBackoff(consecutive int) time.Duration {
	switch {
	case consecutive <= 1:
		return 0
	case consecutive == 2:
		return 5 * time.Second
	case consecutive == 3:
		return 15 * time.Second
	case consecutive == 4:
		return 30 * time.Second
	default:
		return 2 * time.Minute
	}
}

func (r *Runner) startCoreWatchdog(ctx context.Context) {
	ticker := time.NewTicker(coreWatchdogInterval)
	defer ticker.Stop()
	status := coreWatchdogStatus{Service: r.coreService(), ConfigPath: filepath.Join(r.stateDir(), "sing-box.json")}
	r.runCoreWatchdogCheck(ctx, &status, time.Now().UTC())
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-ticker.C:
			r.runCoreWatchdogCheck(ctx, &status, now.UTC())
		}
	}
}

// runCoreWatchdogCheck escalates from "is the unit alive" to "does the living
// process serve the configuration on disk". A kernel that is active but stuck
// on an older configuration is a silent outage, so it is treated as a recovery
// case rather than as a healthy service.
func (r *Runner) runCoreWatchdogCheck(ctx context.Context, status *coreWatchdogStatus, now time.Time) {
	if ctx.Err() != nil || !r.managedRestartEnabled() {
		return
	}
	status.Service = r.coreService()
	status.LastCheckedAt = now
	// #nosec G304 -- ConfigPath is a fixed file below the Agent's configured state directory.
	desired, readErr := os.ReadFile(status.ConfigPath)
	if readErr != nil || len(desired) == 0 {
		status.State = coreWatchdogStateWaitingForConfig
		status.LastError = ""
		status.DesiredDigest = ""
		status.LoadedDigest = ""
		status.RuntimeVerified = false
		status.RuntimeVerification = ""
		status.BuildState = ""
		status.RunningBuild = ""
		status.InstalledBuild = ""
		r.writeCoreWatchdogStatus(*status)
		return
	}

	r.coreLifecycleMu.Lock()
	defer r.coreLifecycleMu.Unlock()
	// An operator update is replacing binaries and restarting the kernel right
	// now. Everything the watchdog would observe during that window is
	// transient, and restarting into it would fight the update.
	hostLock, hostLockErr := r.acquireHostCoreLock(2 * time.Second)
	if hostLockErr != nil {
		return
	}
	defer hostLock.release()
	if err := r.coreServiceActive(); err == nil {
		wasRunning := status.State == coreWatchdogStateRunning
		check := r.checkCoreRuntimeConfig(ctx, desired)
		status.LastRuntimeCheckAt = now
		status.DesiredDigest = check.DesiredDigest
		status.LoadedDigest = check.LoadedDigest
		status.RuntimeVerified = check.verified()
		status.RuntimeVerification = check.Verification
		status.applyBuildIdentity(check)
		if check.drift() {
			r.recoverCoreRuntimeDrift(ctx, status, desired, now)
			return
		}
		if check.Verification == coreRuntimeVerificationUnavailable {
			// The unit is alive but its local API is not answering. Report it
			// instead of restarting: a restart cannot fix a socket the Agent
			// simply cannot reach, and an unnecessary restart drops sessions.
			status.State = coreWatchdogStateRuntimeUnreachable
			if check.Err != nil {
				status.LastError = check.Err.Error()
			}
			r.writeCoreWatchdogStatus(*status)
			return
		}
		if check.binaryDrift() {
			r.recoverCoreBinaryDrift(ctx, status, desired, now, check)
			return
		}
		if check.BuildState == coreBuildStateCurrent {
			// The installed build is serving traffic, so a future replacement
			// gets a fresh recovery attempt.
			status.BinaryRecoveryBuild = ""
		}
		status.State = coreWatchdogStateRunning
		status.LastError = ""
		if status.StableSince.IsZero() {
			status.StableSince = now
		}
		if now.Sub(status.StableSince) >= coreWatchdogStableReset {
			status.Consecutive = 0
			status.NextAttemptAt = time.Time{}
		}
		if !wasRunning {
			_ = r.configureCoreClock(ctx)
		}
		r.writeCoreWatchdogStatus(*status)
		return
	}
	status.StableSince = time.Time{}
	if !status.NextAttemptAt.IsZero() && now.Before(status.NextAttemptAt) {
		status.State = coreWatchdogStateBackoff
		r.writeCoreWatchdogStatus(*status)
		return
	}

	status.Consecutive++
	if err := validateSingBox(r.coreBinary(), status.ConfigPath, r.commandTimeout()); err != nil {
		status.State = "invalid_config"
		status.LastError = err.Error()
		status.NextAttemptAt = now.Add(2 * time.Minute)
		logging.Errorf("core watchdog: refusing to restart %s with invalid config: %v", status.Service, err)
		r.writeCoreWatchdogStatus(*status)
		return
	}
	r.restartCoreFromWatchdog(ctx, status, desired, now, "service_stopped")
}

// recoverCoreRuntimeDrift restarts a kernel that is running but has diverged
// from the configuration on disk.
func (r *Runner) recoverCoreRuntimeDrift(ctx context.Context, status *coreWatchdogStatus, desired []byte, now time.Time) {
	if !status.NextAttemptAt.IsZero() && now.Before(status.NextAttemptAt) {
		status.State = coreWatchdogStateBackoff
		r.writeCoreWatchdogStatus(*status)
		return
	}
	status.State = coreWatchdogStateRuntimeDrift
	status.StableSince = time.Time{}
	status.Consecutive++
	if err := validateSingBox(r.coreBinary(), status.ConfigPath, r.commandTimeout()); err != nil {
		status.State = "invalid_config"
		status.LastError = err.Error()
		status.NextAttemptAt = now.Add(2 * time.Minute)
		logging.Errorf("core watchdog: refusing to restart %s with invalid config: %v", status.Service, err)
		r.writeCoreWatchdogStatus(*status)
		return
	}
	logging.Warnf("core watchdog: %s runs configuration %s but %s is desired; restarting", status.Service, status.LoadedDigest, status.DesiredDigest)
	r.restartCoreFromWatchdog(ctx, status, desired, now, "runtime_drift")
}

// recoverCoreBinaryDrift restarts a kernel whose process is older than the
// executable installed on disk. Installing a release replaces the file by
// rename and leaves every running process on its original inode, so without
// this the node keeps serving the pre-upgrade build indefinitely while both the
// configuration digest and the reported version look correct.
//
// Recovery is attempted once per installed build. A restart that does not clear
// the drift means the process is pinned by something outside Agent — a unit
// file pointing at another path, or a manually started kernel — and repeating
// it every backoff window would drop sessions forever without converging.
func (r *Runner) recoverCoreBinaryDrift(ctx context.Context, status *coreWatchdogStatus, desired []byte, now time.Time, check coreRuntimeCheck) {
	installed := check.InstalledBuild.String()
	if status.BinaryRecoveryBuild != "" && status.BinaryRecoveryBuild == installed {
		status.State = coreWatchdogStateBinaryStale
		status.LastError = fmt.Sprintf("core still runs %s; installed build %s is not being picked up by %s", check.RunningBuild.String(), installed, status.Service)
		r.writeCoreWatchdogStatus(*status)
		return
	}
	if !status.NextAttemptAt.IsZero() && now.Before(status.NextAttemptAt) {
		status.State = coreWatchdogStateBackoff
		r.writeCoreWatchdogStatus(*status)
		return
	}
	status.State = coreWatchdogStateBinaryDrift
	status.StableSince = time.Time{}
	status.Consecutive++
	if err := validateSingBox(r.coreBinary(), status.ConfigPath, r.commandTimeout()); err != nil {
		// The installed kernel cannot run what is deployed. Restarting would
		// turn a stale-but-serving node into an outage.
		status.State = "invalid_config"
		status.LastError = err.Error()
		status.NextAttemptAt = now.Add(2 * time.Minute)
		logging.Errorf("core watchdog: refusing to restart %s onto the installed build with invalid config: %v", status.Service, err)
		r.writeCoreWatchdogStatus(*status)
		return
	}
	status.BinaryRecoveryBuild = installed
	logging.Warnf("core watchdog: %s runs %s but %s is installed; restarting", status.Service, check.RunningBuild.String(), installed)
	r.restartCoreFromWatchdog(ctx, status, desired, now, "binary_drift")
}

func (r *Runner) restartCoreFromWatchdog(ctx context.Context, status *coreWatchdogStatus, desired []byte, now time.Time, reason string) {
	status.State = coreWatchdogStateRecovering
	status.RecoveryAction = "managed_restart"
	status.LastRestartReason = reason
	status.LastRestartAt = now
	status.RestartCount++
	r.writeCoreWatchdogStatus(*status)
	logging.Warnf("core watchdog: starting automatic recovery of %s reason=%s", status.Service, reason)
	if err := r.restartCore(); err != nil {
		status.State = "restart_failed"
		status.LastError = err.Error()
		status.NextAttemptAt = now.Add(coreWatchdogBackoff(status.Consecutive + 1))
		logging.Errorf("core watchdog: restart %s failed: %v", status.Service, err)
		r.writeCoreWatchdogStatus(*status)
		return
	}
	if err := r.waitCoreServiceStable(3 * time.Second); err != nil {
		status.State = "crashed_after_restart"
		status.LastError = err.Error()
		status.NextAttemptAt = now.Add(coreWatchdogBackoff(status.Consecutive + 1))
		logging.Errorf("core watchdog: %s did not remain running after restart: %v", status.Service, err)
		r.writeCoreWatchdogStatus(*status)
		return
	}
	check := r.awaitCoreRuntimeActivation(ctx, desired, r.coreRuntimeVerifyWindow())
	status.LastRuntimeCheckAt = time.Now().UTC()
	status.DesiredDigest = check.DesiredDigest
	status.LoadedDigest = check.LoadedDigest
	status.RuntimeVerified = check.verified()
	status.RuntimeVerification = check.Verification
	status.applyBuildIdentity(check)
	if check.drift() {
		status.State = coreWatchdogStateRuntimeDrift
		status.LastError = "core still runs an older configuration after restart"
		status.NextAttemptAt = now.Add(coreWatchdogBackoff(status.Consecutive + 1))
		logging.Errorf("core watchdog: %s still runs %s after restart, expected %s", status.Service, check.LoadedDigest, check.DesiredDigest)
		r.writeCoreWatchdogStatus(*status)
		return
	}
	if check.binaryDrift() {
		status.State = coreWatchdogStateBinaryStale
		status.LastError = "core still runs the previous build after restart"
		status.NextAttemptAt = now.Add(coreWatchdogBackoff(status.Consecutive + 1))
		logging.Errorf("core watchdog: %s still runs %s after restart, expected %s", status.Service, check.RunningBuild.String(), check.InstalledBuild.String())
		r.writeCoreWatchdogStatus(*status)
		return
	}
	status.State = "recovered"
	status.LastError = ""
	status.StableSince = time.Now().UTC()
	_ = r.configureCoreClock(ctx)
	status.NextAttemptAt = now.Add(coreWatchdogBackoff(status.Consecutive + 1))
	logging.Infof("core watchdog: %s recovered successfully reason=%s", status.Service, reason)
	r.writeCoreWatchdogStatus(*status)
}

func (r *Runner) writeCoreWatchdogStatus(status coreWatchdogStatus) {
	data, err := json.MarshalIndent(status, "", "  ")
	if err != nil {
		return
	}
	_ = atomicWriteFile(filepath.Join(r.stateDir(), "core-watchdog.json"), data, 0o600)
}
