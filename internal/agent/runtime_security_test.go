package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"github.com/OboardProject/oboard-agent/internal/model"
	"github.com/OboardProject/oboard-agent/internal/protectedstate"
	"os"
	"path/filepath"
	"testing"
)

func TestRuntimeSecurityStorageRecovery(t *testing.T) {
	dir := t.TempDir()
	r := New(Config{StateDir: dir, ConfigPath: filepath.Join(dir, "agent.json")})
	secret := []byte("private-ssh-credentials")
	if err := r.stateWrite(sshInboundsCurrent, secret, 0600); err != nil {
		t.Fatal(err)
	}
	if err := r.enableRuntimeStorage(); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(r.statePath(sshInboundsCurrent))
	if err != nil {
		t.Fatal(err)
	}
	if !protectedstate.IsProtected(raw) || bytes.Contains(raw, secret) {
		t.Fatal("state not protected")
	}
	if err := r.enableRuntimeStorage(); err != nil {
		t.Fatal("idempotent retry", err)
	}
	restarted := New(Config{StateDir: dir, ConfigPath: filepath.Join(dir, "agent.json")})
	got, err := restarted.stateRead(sshInboundsCurrent)
	if err != nil || !bytes.Equal(got, secret) {
		t.Fatal("restart restore", err)
	}
	if err := os.WriteFile(r.statePath(sshInboundsCurrent), secret, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := r.stateRead(sshInboundsCurrent); err == nil {
		t.Fatal("plaintext replacement accepted")
	}
	if err := os.Remove(r.statePath(runtimeSecretsKey)); err != nil {
		t.Fatal(err)
	}
	if err := r.enableRuntimeStorage(); err == nil {
		t.Fatal("lost key silently regenerated")
	}
	if err := r.stateWrite(sshInboundsCurrent, secret, 0600); err == nil {
		t.Fatal("lost key wrote plaintext")
	}
}
func TestRuntimeSecurityLocalPolicyFailClosed(t *testing.T) {
	dir := t.TempDir()
	r := New(Config{StateDir: dir, ConfigPath: filepath.Join(dir, "agent.json")})
	if err := os.WriteFile(r.localSecurityPath(), []byte("broken"), 0600); err != nil {
		t.Fatal(err)
	}
	if r.localSecurityPolicy().Allows("remote_terminal") {
		t.Fatal("corrupt local policy allowed terminal")
	}
	if _, err := r.applyRuntimeSecurity("{\"mode\":\"standard\",\"revision\":1}"); err == nil {
		t.Fatal("corrupt policy accepted")
	}
	if _, err := r.applyRuntimeSecurity("{} {}"); err == nil {
		t.Fatal("trailing JSON accepted")
	}
	if err := os.WriteFile(r.statePath(runtimeSecurityDesiredFile), []byte("broken"), 0600); err != nil {
		t.Fatal(err)
	}
	if r.runtimeSecurityDesired().Mode != "invalid" {
		t.Fatal("corrupt desired state downgraded")
	}
}

func TestRuntimeSecurityApplyRollbackAndRetry(t *testing.T) {
	previousCheck := runtimeSecurityBinaryCheck
	runtimeSecurityBinaryCheck = func(string) error { return nil }
	t.Cleanup(func() { runtimeSecurityBinaryCheck = previousCheck })
	previousPlatform := runtimeSecurityPlatformSupported
	runtimeSecurityPlatformSupported = func() bool { return true }
	t.Cleanup(func() { runtimeSecurityPlatformSupported = previousPlatform })
	dir := t.TempDir()
	r := New(Config{StateDir: dir, ConfigPath: filepath.Join(dir, "agent.json")})
	if err := r.stateWrite(singBoxConfigFile, []byte("{\"inbounds\":[],\"outbounds\":[{\"type\":\"direct\",\"tag\":\"direct\"}]}"), 0600); err != nil {
		t.Fatal(err)
	}
	kernel := newFakeCoreKernel(t, r.statePath(singBoxConfigFile), true)
	r.coreClient = kernel.client
	kernel.mu.Lock()
	kernel.runtimeSecurityMode = "standard"
	kernel.mu.Unlock()
	r.coreServiceActiveCheck = func() error { return nil }
	starts := 0
	failNext := true
	r.coreRestartCommand = func() error {
		starts++
		if failNext {
			failNext = false
			return os.ErrPermission
		}
		data, err := r.stateRead(runtimeSecurityFile)
		if err != nil {
			return err
		}
		var desired model.RuntimeSecurityRequest
		if err := json.Unmarshal(data, &desired); err != nil {
			return err
		}
		kernel.mu.Lock()
		kernel.runtimeSecurityMode = desired.Mode
		kernel.mu.Unlock()
		kernel.boot()
		return nil
	}
	result, err := r.applyRuntimeSecurity("{\"mode\":\"enhanced\",\"revision\":1}")
	if err == nil || starts != 2 {
		t.Fatalf("rollback: starts=%d err=%v", starts, err)
	}
	report := result["runtime_security"].(model.RuntimeSecurityReport)
	if report.ErrorCode != "runtime_security_apply_rolled_back" || report.ActualMode != "standard" {
		t.Fatalf("rollback report: %+v", report)
	}
	if _, err := r.applyRuntimeSecurity("{\"mode\":\"enhanced\",\"revision\":2}"); err != nil {
		t.Fatal("retry", err)
	}
	if starts != 3 {
		t.Fatal("retry restart count", starts)
	}
	if _, err := r.applyRuntimeSecurity("{\"mode\":\"enhanced\",\"revision\":2}"); err != nil {
		t.Fatal("idempotent apply", err)
	}
	if _, err := r.applyRuntimeSecurity("{}"); err != nil {
		t.Fatal("read-only check", err)
	}
	if starts != 3 {
		t.Fatal("idempotent apply or check restarted core", starts)
	}
	if _, err := r.applyRuntimeSecurity("{\"mode\":\"standard\",\"revision\":1}"); err == nil {
		t.Fatal("stale revision accepted")
	}
	if err := r.stateWrite(runtimeSecurityPendingFile, []byte("{\"mode\":\"standard\"}"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := r.recoverRuntimeSecurity(); err != nil {
		t.Fatal("interrupted transition recovery", err)
	}
	if _, err := os.Stat(r.statePath(runtimeSecurityPendingFile)); !os.IsNotExist(err) {
		t.Fatal("recovery journal remains", err)
	}
	if r.cachedRuntimeSecurity().ActualMode != "standard" || r.cachedRuntimeSecurity().ErrorCode != "runtime_security_interrupted_rolled_back" {
		t.Fatal("recovery result not reported")
	}
	if err := r.localSecurityStore().SetMode("hardened"); err != nil {
		t.Fatal(err)
	}
	if _, err := r.applyRuntimeSecurity("{\"mode\":\"standard\",\"revision\":3}"); err == nil {
		t.Fatal("remote Hardened downgrade accepted")
	}
}

func TestRuntimeSecurityUpdatePreservesEnforcement(t *testing.T) {
	dir := t.TempDir()
	r := New(Config{StateDir: dir})
	if err := r.preflightRuntimeSecurityUpdate(filepath.Join(dir, "missing")); err != nil {
		t.Fatal("standard update changed", err)
	}
	if err := r.stateWrite(runtimeSecurityFile, []byte("{\"mode\":\"enhanced\"}"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := r.preflightRuntimeSecurityUpdate(filepath.Join(dir, "missing")); err == nil {
		t.Fatal("enhanced update accepted unavailable preflight")
	}
	raw, err := r.stateRead(runtimeSecurityFile)
	if err != nil || !bytes.Contains(raw, []byte("enhanced")) {
		t.Fatal("failed update relaxed profile")
	}
}

func TestRuntimeSecurityStorageEvidenceAndInterruptedKeyLoss(t *testing.T) {
	dir := t.TempDir()
	r := New(Config{StateDir: dir, ConfigPath: filepath.Join(dir, "agent.json")})
	if err := r.stateWrite(sshInboundsCurrent, []byte("secret"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := r.enableRuntimeStorage(); err != nil {
		t.Fatal(err)
	}
	if encrypted, err := r.verifyRuntimeStorage(context.Background()); err != nil || !encrypted {
		t.Fatal(encrypted, err)
	}
	raw, err := os.ReadFile(r.statePath(sshInboundsCurrent))
	if err != nil {
		t.Fatal(err)
	}
	raw[len(raw)-1] ^= 1
	if err := os.WriteFile(r.statePath(sshInboundsCurrent), raw, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := r.verifyRuntimeStorage(context.Background()); err == nil {
		t.Fatal("damaged state reported safe")
	}
	for _, name := range []string{runtimeStorageReady, runtimeSecretsKey} {
		if err := os.Remove(r.statePath(name)); err != nil {
			t.Fatal(err)
		}
	}
	if err := r.enableRuntimeStorage(); err == nil {
		t.Fatal("partial conversion replaced lost key")
	}
}
func TestRuntimeSecurityRepairClosedInputAndPermissions(t *testing.T) {
	dir := t.TempDir()
	config := filepath.Join(dir, "agent.json")
	r := New(Config{StateDir: dir, ConfigPath: config})
	if err := os.WriteFile(config, []byte("{}"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := r.repairRuntimePermissions(); err != nil {
		t.Fatal(err)
	}
	if info, err := os.Stat(config); err != nil || info.Mode().Perm() != 0600 {
		t.Fatal(info, err)
	}
	for _, raw := range []string{`{"repair":true,"mode":"standard"}`, `{"repair":true,"path":"/etc/passwd"}`, `{"repair":true,"command":"whoami"}`} {
		if _, err := r.applyRuntimeSecurity(raw); err == nil {
			t.Fatal("unsafe repair accepted")
		}
	}
}

func TestRuntimeSecurityUpdateVerificationRejectsLostRestrictions(t *testing.T) {
	dir := t.TempDir()
	r := New(Config{StateDir: dir, ConfigPath: filepath.Join(dir, "agent.json")})
	if err := r.stateWrite(singBoxConfigFile, []byte(`{"inbounds":[],"outbounds":[{"type":"direct","tag":"direct"}]}`), 0600); err != nil {
		t.Fatal(err)
	}
	kernel := newFakeCoreKernel(t, r.statePath(singBoxConfigFile), true)
	r.coreClient = kernel.client
	if err := r.stateWrite(runtimeSecurityFile, []byte(`{"mode":"enhanced"}`), 0600); err != nil {
		t.Fatal(err)
	}
	kernel.mu.Lock()
	kernel.runtimeSecurityMode = "standard"
	kernel.mu.Unlock()
	if err := r.verifyInstalledRuntimeSecurity(context.Background()); err == nil {
		t.Fatal("upgrade lost restrictions but passed verification")
	}
	kernel.mu.Lock()
	kernel.runtimeSecurityMode = "enhanced"
	kernel.mu.Unlock()
	if err := r.verifyInstalledRuntimeSecurity(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestRuntimeSecurityReportWriteFailureIsVisible(t *testing.T) {
	dir := t.TempDir()
	r := New(Config{StateDir: dir})
	if err := os.Mkdir(r.statePath(runtimeSecurityReportFile), 0700); err != nil {
		t.Fatal(err)
	}
	if err := r.persistRuntimeSecurityReport(model.RuntimeSecurityReport{State: "enhanced"}); err == nil {
		t.Fatal("report save failure ignored")
	}
	if report := r.cachedRuntimeSecurity(); report == nil || report.State != "failed" || report.ErrorCode != "runtime_security_report_save_failed" {
		t.Fatal(report)
	}
}
