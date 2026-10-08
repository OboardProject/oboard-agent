package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"github.com/OboardProject/oboard-agent/internal/model"
	"github.com/OboardProject/oboard-agent/internal/runtimesecurity"
	"github.com/OboardProject/oboard-agent/internal/securefile"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

var runtimeSecurityBinaryCheck = checkRuntimeSecurityBinary
var runtimeSecurityPlatformSupported = func() bool { return runtime.GOOS == "linux" }

const runtimeSecurityPendingFile = "runtime-security-pending.json"
const runtimeSecurityReportFile = "runtime-security-report.json"
const runtimeSecurityDesiredFile = "runtime-security-desired.json"

func (r *Runner) runtimeSecurityDesired() model.RuntimeSecurityRequest {
	value := model.RuntimeSecurityRequest{Mode: "standard"}
	if raw, err := r.stateRead(runtimeSecurityDesiredFile); err == nil {
		if json.Unmarshal(raw, &value) != nil || (value.Mode != "standard" && value.Mode != "enhanced") {
			value.Mode = "invalid"
		}
	} else if !os.IsNotExist(err) {
		value.Mode = "invalid"
	}
	return value
}
func (r *Runner) cachedRuntimeSecurity() *model.RuntimeSecurityReport {
	return r.runtimeSecurityReport.Load()
}
func (r *Runner) kernelSecurity(ctx context.Context) (*runtimesecurity.Kernel, error) {
	var value struct {
		Security *runtimesecurity.Kernel `json:"runtime_security"`
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://oboard-sb/runtime/status", nil)
	if err != nil {
		return nil, err
	}
	response, err := r.coreAPIClient().Do(request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if response.StatusCode != 200 {
		return nil, errors.New("kernel security unavailable")
	}
	if err := json.NewDecoder(io.LimitReader(response.Body, 64<<10)).Decode(&value); err != nil {
		return nil, err
	}
	return value.Security, nil
}
func (r *Runner) inspectRuntimeSecurity(ctx context.Context) model.RuntimeSecurityReport {
	desired := r.runtimeSecurityDesired()
	policy, err := r.localSecurityStore().Load()
	local := "unknown"
	if err == nil {
		local = policy.Mode
	}
	kernel, _ := r.kernelSecurity(ctx)
	_, keyErr := r.runtimeStorageKey()
	targets := []runtimesecurity.Target{
		{ID: "agent_config", Path: r.configPath()},
		{ID: "config_directory", Path: filepath.Dir(r.configPath()), Directory: true},
		{ID: "state_directory", Path: r.stateDir(), Directory: true},
		{ID: "core_binary", Path: r.coreBinary(), Public: true},
		{ID: "kernel_config", Path: r.statePath(singBoxConfigFile), Optional: true},
		{ID: "local_policy", Path: r.localSecurityPath(), Optional: true},
		{ID: "management_socket", Path: r.coreAPISocketPath(), Socket: true, Optional: true},
		{ID: "agent_log", Path: r.agentLogPath(), Optional: true},
		{ID: "core_log", Path: r.coreLogPath(), Optional: true},
	}
	if binary, err := selfExecutablePath(); err == nil {
		targets = append(targets, runtimeSecurityBinaryTarget(binary))
	}
	report := runtimesecurity.Inspect(ctx, runtimesecurity.Input{Mode: desired.Mode, Revision: desired.Revision, LocalPolicy: local, Targets: targets, Kernel: kernel, Encrypted: keyErr == nil && r.runtimeStorageRequired()})
	manager := detectServiceManager()
	if manager == "systemd" || manager == "openrc" {
		for _, service := range []struct{ id, name string }{{"agent_service", r.agentService()}, {"core_service", r.coreService()}} {
			if filepath.Base(service.name) != service.name || service.name == "." || service.name == ".." {
				continue
			}
			report.Checks = append(report.Checks, runtimesecurity.InspectService(serviceUnitPath(manager, service.name), manager, service.id, report.CheckedAt))
		}
	}
	treeStatus := runtimesecurity.CheckManagedTree(ctx, r.stateDir())
	report.Checks = append(report.Checks, model.RuntimeSecurityCheck{ID: "managed_state_tree", Category: "filesystem", Severity: "high", Status: treeStatus, Supported: true, CheckedAt: report.CheckedAt, Message: "受管状态目录的有界权限检查（最多 128 项、深度 3）", Remedy: "修复非预期权限或符号链接；unknown 表示未完成覆盖"})
	if desired.Mode == "enhanced" && treeStatus != "passed" && report.State == "enhanced" {
		report.State = "partial"
	}
	previous := r.cachedRuntimeSecurity()
	if previous == nil {
		if raw, err := r.stateRead(runtimeSecurityReportFile); err == nil {
			var stored model.RuntimeSecurityReport
			if json.Unmarshal(raw, &stored) == nil {
				previous = &stored
			}
		}
	}
	if previous != nil && previous.Revision == report.Revision && previous.ActualMode == report.ActualMode {
		report.AppliedAt = previous.AppliedAt
		if previous.ErrorCode != "" {
			report.ErrorCode, report.Phase, report.State = previous.ErrorCode, previous.Phase, previous.State
		}
	}
	if desired.Mode == "invalid" {
		report.DesiredMode = "standard"
		report.State = "failed"
		report.ErrorCode = "runtime_security_desired_unreadable"
		report.Phase = "storage"
	}
	return report
}
func runtimeSecurityBinaryTarget(path string) runtimesecurity.Target {
	return runtimesecurity.Target{ID: "agent_binary", Path: path, Public: true}
}
func (r *Runner) runtimeSecurityCheck(ctx context.Context) model.RuntimeSecurityReport {
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	report := r.inspectRuntimeSecurity(ctx)
	r.runtimeSecurityReport.Store(&report)
	return report
}
func (r *Runner) periodicRuntimeSecurityCheck(ctx context.Context) {
	if !r.runtimeSecurityMu.TryLock() {
		return
	}
	defer r.runtimeSecurityMu.Unlock()
	r.runtimeSecurityCheck(ctx)
}
func (r *Runner) runtimeSecurityLoop(ctx context.Context) {
	r.periodicRuntimeSecurityCheck(ctx)
	ticker := time.NewTicker(6 * time.Hour)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			r.periodicRuntimeSecurityCheck(ctx)
		}
	}
}
func (r *Runner) applyRuntimeSecurity(raw string) (map[string]any, error) {
	var request model.RuntimeSecurityRequest
	decoder := json.NewDecoder(bytes.NewBufferString(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&request); err != nil {
		return nil, errors.New("invalid runtime security request")
	}
	if decoder.Decode(new(any)) != io.EOF {
		return nil, errors.New("invalid runtime security request")
	}
	if request.Mode != "" && request.Mode != "standard" && request.Mode != "enhanced" {
		return nil, errors.New("invalid runtime security mode")
	}
	if !r.runtimeSecurityMu.TryLock() {
		return nil, errors.New("runtime_security_busy")
	}
	defer r.runtimeSecurityMu.Unlock()
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	if request.Mode == "" {
		report := r.runtimeSecurityCheck(ctx)
		return map[string]any{"runtime_security": report}, nil
	}
	policy, err := r.localSecurityStore().Load()
	if err != nil {
		return nil, errors.New("local_security_unreadable")
	}
	if request.Mode == "standard" && policy.Mode == model.RemoteAccessModeHardened {
		return nil, errors.New("local_hardened_denies_downgrade")
	}
	previousDesired := r.runtimeSecurityDesired()
	if request.Revision <= 0 || request.Revision < previousDesired.Revision {
		return nil, errors.New("stale_runtime_security_revision")
	}
	if request.Revision == previousDesired.Revision && request.Mode != previousDesired.Mode {
		return nil, errors.New("runtime_security_revision_conflict")
	}
	encoded, _ := json.Marshal(request)
	if err := r.stateWritePathSynced(r.statePath(runtimeSecurityDesiredFile), encoded, 0600); err != nil {
		return nil, errors.New("runtime_security_save_failed")
	}
	fail := func(code, phase string) (map[string]any, error) {
		report := r.runtimeSecurityCheck(ctx)
		report.State = "failed"
		if code == "runtime_security_unsupported" {
			report.State = "unsupported"
		}
		report.ErrorCode = code
		report.Phase = phase
		r.persistRuntimeSecurityReport(report)
		return map[string]any{"runtime_security": report, "message": code}, errors.New(code)
	}
	if !runtimeSecurityPlatformSupported() {
		return fail("runtime_security_unsupported", "preflight")
	}
	if err := r.recoverRuntimeSecurity(); err != nil {
		return fail("runtime_security_recovery_failed", "rollback")
	}
	current, err := r.kernelSecurity(ctx)
	if err != nil || current == nil || !current.Supported {
		return fail("runtime_security_unsupported", "preflight")
	}
	if !runtimeSecurityProfileMatches(current, request.Mode) && strings.TrimSpace(r.Config().RestartCommand) == "none" {
		return fail("runtime_security_restart_unavailable", "preflight")
	}
	r.coreLifecycleMu.Lock()
	defer r.coreLifecycleMu.Unlock()
	lock, err := r.acquireHostCoreLock(hostCoreLockWait)
	if err != nil {
		return fail("host_lock_busy", "lock")
	}
	defer lock.release()
	if request.Mode == "enhanced" {
		if err := runtimeSecurityBinaryCheck(r.coreBinary()); err != nil {
			return fail("runtime_security_unsupported", "preflight")
		}
		if err := r.enableRuntimeStorage(); err != nil {
			return fail("runtime_storage_failed", "storage")
		}
	}
	old, oldErr := r.stateRead(runtimeSecurityFile)
	if oldErr != nil && !os.IsNotExist(oldErr) {
		return fail("runtime_security_policy_unreadable", "prepare")
	}
	if os.IsNotExist(oldErr) {
		old = []byte("{\"mode\":\"standard\"}")
	}
	if !runtimeSecurityProfileMatches(current, request.Mode) {
		if err := r.stateWritePathSynced(r.statePath(runtimeSecurityPendingFile), old, 0600); err != nil {
			return fail("runtime_security_journal_failed", "prepare")
		}
	}
	if err := r.stateWritePathSynced(r.statePath(runtimeSecurityFile), encoded, 0600); err != nil {
		return fail("runtime_security_policy_write_failed", "prepare")
	}
	// No restart for a check or an already effective profile.
	if !runtimeSecurityProfileMatches(current, request.Mode) {
		err = r.restartCore()
		if err == nil {
			err = r.waitCoreServiceStable(10 * time.Second)
		}
		if err == nil {
			actual, readErr := r.kernelSecurity(ctx)
			if readErr != nil || !runtimeSecurityProfileMatches(actual, request.Mode) {
				err = errors.New("profile was not confirmed by the running kernel")
			}
		}
		if err == nil {
			err = r.verifyRuntimeSecurityConfig(ctx)
		}
		if err != nil {
			// Restore only the profile. Never roll back authorization or user leases.
			if os.IsNotExist(oldErr) {
				old = []byte("{\"mode\":\"standard\"}")
			}
			if restoreErr := r.stateWritePathSynced(r.statePath(runtimeSecurityFile), old, 0600); restoreErr != nil {
				return fail("runtime_security_rollback_write_failed", "rollback")
			}
			if restartErr := r.restartCore(); restartErr != nil {
				return fail("runtime_security_rollback_restart_failed", "rollback")
			}
			if stableErr := r.waitCoreServiceStable(10 * time.Second); stableErr != nil {
				return fail("runtime_security_rollback_unverified", "rollback")
			}
			restored, verifyErr := r.kernelSecurity(ctx)
			if verifyErr != nil || !runtimeSecurityProfileMatches(restored, current.Mode) || r.verifyRuntimeSecurityConfig(ctx) != nil {
				return fail("runtime_security_rollback_unverified", "rollback")
			}
			if err := securefile.Remove(r.statePath(runtimeSecurityPendingFile)); err != nil && !os.IsNotExist(err) {
				return fail("runtime_security_journal_cleanup_failed", "rollback")
			}
			return fail("runtime_security_apply_rolled_back", "verify")
		}
	}
	if err := securefile.Remove(r.statePath(runtimeSecurityPendingFile)); err != nil && !os.IsNotExist(err) {
		return fail("runtime_security_journal_cleanup_failed", "verify")
	}
	report := r.runtimeSecurityCheck(ctx)
	now := time.Now().UTC()
	report.AppliedAt = &now
	report.Phase = "confirmed"
	report.ErrorCode = ""
	if report.State == "failed" {
		report.State = "partial"
	}
	r.persistRuntimeSecurityReport(report)
	return map[string]any{"runtime_security": report, "message": "运行安全配置已由 Agent 检查"}, nil
}

func (r *Runner) persistRuntimeSecurityReport(report model.RuntimeSecurityReport) {
	r.runtimeSecurityReport.Store(&report)
	raw, err := json.Marshal(report)
	if err == nil {
		_ = r.stateWritePathSynced(r.statePath(runtimeSecurityReportFile), raw, 0600)
	}
}

func runtimeSecurityProfileMatches(value *runtimesecurity.Kernel, mode string) bool {
	if value == nil || !value.Supported || value.Mode != mode {
		return false
	}
	return mode == "standard" || (value.NoNewPrivileges && !value.Dumpable && value.CoreDumpsDisabled)
}

// A pending profile is always rolled back before the watchdog starts. This
// journal contains policy only, never authorization or proxy credentials.
func (r *Runner) recoverRuntimeSecurity() error {
	old, err := r.stateRead(runtimeSecurityPendingFile)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	var policy model.RuntimeSecurityRequest
	if json.Unmarshal(old, &policy) != nil || (policy.Mode != "standard" && policy.Mode != "enhanced") {
		return errors.New("invalid security recovery journal")
	}
	r.coreLifecycleMu.Lock()
	defer r.coreLifecycleMu.Unlock()
	lock, err := r.acquireHostCoreLock(hostCoreLockWait)
	if err != nil {
		return err
	}
	defer lock.release()
	if err := r.stateWritePathSynced(r.statePath(runtimeSecurityFile), old, 0600); err != nil {
		return err
	}
	if err := r.restartCore(); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := r.waitCoreServiceStable(10 * time.Second); err != nil {
		return err
	}
	actual, err := r.kernelSecurity(ctx)
	if err != nil || !runtimeSecurityProfileMatches(actual, policy.Mode) || r.verifyRuntimeSecurityConfig(ctx) != nil {
		return errors.New("security recovery not verified")
	}
	if err := securefile.Remove(r.statePath(runtimeSecurityPendingFile)); err != nil {
		return err
	}
	report := r.runtimeSecurityCheck(ctx)
	report.State = "failed"
	report.Phase = "rollback"
	report.ErrorCode = "runtime_security_interrupted_rolled_back"
	r.persistRuntimeSecurityReport(report)
	return nil
}

func checkRuntimeSecurityBinary(binary string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, binary, "-runtime-security-check")
	output := &limitBuffer{limit: 4096}
	command.Stdout = output
	if err := command.Run(); err != nil {
		return errors.New("kernel security preflight failed")
	}
	var profile runtimesecurity.Kernel
	if json.Unmarshal([]byte(output.String()), &profile) != nil || !runtimeSecurityProfileMatches(&profile, "enhanced") {
		return errors.New("kernel security preflight was not confirmed")
	}
	return nil
}
func (r *Runner) preflightRuntimeSecurityUpdate(binary string) error {
	raw, err := r.stateRead(runtimeSecurityFile)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return errors.New("runtime security policy unreadable")
	}
	var policy model.RuntimeSecurityRequest
	if json.Unmarshal(raw, &policy) != nil {
		return errors.New("runtime security policy invalid")
	}
	if policy.Mode == "enhanced" {
		if err := os.Chmod(binary, 0700); err != nil {
			return errors.New("staged kernel security preflight unavailable")
		}
		return runtimeSecurityBinaryCheck(binary)
	}
	if policy.Mode != "standard" {
		return errors.New("runtime security policy invalid")
	}
	return nil
}

func (r *Runner) verifyRuntimeSecurityConfig(ctx context.Context) error {
	desired, err := r.stateRead(singBoxConfigFile)
	if err != nil {
		return errors.New("runtime configuration unavailable")
	}
	check := r.awaitCoreRuntimeConfig(ctx, desired, r.coreRuntimeVerifyWindow())
	if !check.verified() || check.drift() {
		return errors.New("runtime configuration was not verified")
	}
	return nil
}
