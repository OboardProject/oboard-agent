package agent

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/OboardProject/oboard-agent/internal/model"
)

func TestParseCoreBuildIdentity(t *testing.T) {
	identity, err := parseCoreBuildIdentity(`{"name":"oboard-sb","version":"0.0.1","build":"20260902132000","commit":"e7db20f"}`)
	if err != nil {
		t.Fatal(err)
	}
	if identity.Build != "20260902132000" || identity.Commit != "e7db20f" {
		t.Fatalf("unexpected identity: %#v", identity)
	}
	if _, err := parseCoreBuildIdentity("oboard-sb 0.0.1"); err == nil {
		t.Fatal("plain text version output was accepted as a build identity")
	}
	if _, err := parseCoreBuildIdentity(`{"name":"oboard-sb","version":"0.0.1"}`); err == nil {
		t.Fatal("an identity without build or commit was accepted")
	}
}

func TestCoreBuildIdentitySame(t *testing.T) {
	base := coreBuildIdentity{Version: "0.0.1", Build: "b1", Commit: "c1"}
	if !base.same(coreBuildIdentity{Build: "b1", Commit: "c1"}) {
		t.Fatal("identical builds were reported as different")
	}
	if base.same(coreBuildIdentity{Build: "b2", Commit: "c1"}) {
		t.Fatal("a different build was reported as the same")
	}
	if base.same(coreBuildIdentity{Build: "b1", Commit: "c2"}) {
		t.Fatal("a shared build tag hid a different commit")
	}
	// A build tag alone is enough when one side does not carry a commit.
	if !base.same(coreBuildIdentity{Build: "b1"}) {
		t.Fatal("a missing commit was treated as a mismatch")
	}
	// An unidentifiable side is never a match, so it can never look stale.
	if base.same(coreBuildIdentity{}) || (coreBuildIdentity{}).same(base) {
		t.Fatal("an empty identity was compared as a match")
	}
}

// The state an upgrade leaves behind: a new executable on disk and the previous
// process still serving traffic.
func TestCheckCoreRuntimeConfigDetectsBinaryDrift(t *testing.T) {
	dir := t.TempDir()
	writeCoreConfig(t, dir, coreConfigA)
	kernel := newFakeCoreKernel(t, filepath.Join(dir, "sing-box.json"), true)
	kernel.reportBuild("old-build")
	binary := writeFakeCoreBinary(t, dir, "new-build")
	r := newRuntimeTestRunnerWithCore(t, dir, kernel, binary)

	check := r.checkCoreRuntimeConfig(context.Background(), []byte(resolvedCoreConfig(t, coreConfigA)))
	if !check.verified() || check.drift() {
		t.Fatalf("configuration should be converged: %#v", check)
	}
	if check.BuildState != coreBuildStateStale || !check.binaryDrift() {
		t.Fatalf("a replaced kernel binary was not detected: %#v", check)
	}
	result := map[string]any{}
	check.annotate(result)
	if result["runtime_binary_drift"] != true || result["runtime_build_state"] != coreBuildStateStale {
		t.Fatalf("binary drift was not reported: %#v", result)
	}
}

func TestCheckCoreRuntimeConfigReportsCurrentBuild(t *testing.T) {
	dir := t.TempDir()
	writeCoreConfig(t, dir, coreConfigA)
	kernel := newFakeCoreKernel(t, filepath.Join(dir, "sing-box.json"), true)
	kernel.reportBuild("same-build")
	binary := writeFakeCoreBinary(t, dir, "same-build")
	r := newRuntimeTestRunnerWithCore(t, dir, kernel, binary)

	check := r.checkCoreRuntimeConfig(context.Background(), []byte(resolvedCoreConfig(t, coreConfigA)))
	if check.BuildState != coreBuildStateCurrent || check.binaryDrift() {
		t.Fatalf("a current kernel was reported as stale: %#v", check)
	}
}

// Kernels released before /runtime/status still identify their running build
// through /version. This is the upgrade state that can strand a process on an
// unlinked executable when the first Agent carrying activation support lands.
func TestCheckCoreRuntimeConfigDetectsLegacyKernelBinaryDrift(t *testing.T) {
	dir := t.TempDir()
	writeCoreConfig(t, dir, coreConfigA)
	kernel := newFakeCoreKernel(t, filepath.Join(dir, "sing-box.json"), false)
	kernel.reportBuild("old-build")
	binary := writeFakeCoreBinary(t, dir, "new-build")
	r := newRuntimeTestRunnerWithCore(t, dir, kernel, binary)

	check := r.checkCoreRuntimeConfig(context.Background(), []byte(resolvedCoreConfig(t, coreConfigA)))
	if check.Verification != coreRuntimeVerificationUnsupported {
		t.Fatalf("legacy runtime verification = %q, want unsupported", check.Verification)
	}
	if check.BuildState != coreBuildStateStale || !check.binaryDrift() {
		t.Fatalf("legacy kernel build drift was not detected: %#v", check)
	}
	if check.RunningBuild.Build != "old-build" || check.InstalledBuild.Build != "new-build" {
		t.Fatalf("legacy build identities = %#v", check)
	}
}

// A kernel that predates coreRuntimeBuildIdentityCapability cannot be judged,
// and must never be restarted for it: that would churn every node during a
// rolling upgrade where Agent lands before the kernel does.
func TestCheckCoreRuntimeConfigLeavesOlderKernelBuildUnknown(t *testing.T) {
	dir := t.TempDir()
	writeCoreConfig(t, dir, coreConfigA)
	kernel := newFakeCoreKernel(t, filepath.Join(dir, "sing-box.json"), true)
	binary := writeFakeCoreBinary(t, dir, "new-build")
	r := newRuntimeTestRunnerWithCore(t, dir, kernel, binary)

	check := r.checkCoreRuntimeConfig(context.Background(), []byte(resolvedCoreConfig(t, coreConfigA)))
	if check.BuildState != coreBuildStateUnknown || check.binaryDrift() {
		t.Fatalf("a kernel that reports no build was judged: %#v", check)
	}
}

// The same restraint applies when Agent cannot read the installed executable.
func TestCheckCoreRuntimeConfigLeavesBuildUnknownWhenBinaryUnreadable(t *testing.T) {
	dir := t.TempDir()
	writeCoreConfig(t, dir, coreConfigA)
	kernel := newFakeCoreKernel(t, filepath.Join(dir, "sing-box.json"), true)
	kernel.reportBuild("old-build")
	r := newRuntimeTestRunner(t, dir, kernel)

	check := r.checkCoreRuntimeConfig(context.Background(), []byte(resolvedCoreConfig(t, coreConfigA)))
	if check.BuildState != coreBuildStateUnknown || check.binaryDrift() {
		t.Fatalf("an unreadable binary produced a verdict: %#v", check)
	}
	if check.BuildErr == nil {
		t.Fatal("the reason the build could not be read was not recorded")
	}
}

// Recovery is attempted once per installed build. A kernel that will not come
// up on the new executable must be reported, not restarted forever.
func TestRecoverCoreBinaryDriftDoesNotRetryTheSameBuild(t *testing.T) {
	dir := t.TempDir()
	writeCoreConfig(t, dir, coreConfigA)
	kernel := newFakeCoreKernel(t, filepath.Join(dir, "sing-box.json"), true)
	binary := writeFakeCoreBinary(t, dir, "new-build")
	r := newRuntimeTestRunnerWithCore(t, dir, kernel, binary)

	check := coreRuntimeCheck{
		Verification:   coreRuntimeVerificationVerified,
		BuildState:     coreBuildStateStale,
		RunningBuild:   coreBuildIdentity{Version: "0.0.1", Build: "old-build"},
		InstalledBuild: coreBuildIdentity{Version: "0.0.1", Build: "new-build"},
	}
	status := coreWatchdogStatus{
		Service:             "oboard-sb",
		ConfigPath:          filepath.Join(dir, "sing-box.json"),
		BinaryRecoveryBuild: check.InstalledBuild.String(),
	}
	before := status.RestartCount
	r.recoverCoreBinaryDrift(context.Background(), &status, []byte(resolvedCoreConfig(t, coreConfigA)), time.Now().UTC(), check)

	if status.State != coreWatchdogStateBinaryStale {
		t.Fatalf("a latched build was retried: state=%s", status.State)
	}
	if status.RestartCount != before {
		t.Fatalf("the kernel was restarted again for an already attempted build")
	}
	if status.LastError == "" {
		t.Fatal("the unresolved binary drift was not reported")
	}
}

// The idempotent-replay shortcut answers from last-applied-version.json alone.
// It may only do so while the running kernel still serves what was recorded.
func TestApplyCoreConfigReplayRefusesShortcutWhenKernelDrifted(t *testing.T) {
	dir := t.TempDir()
	writeCoreConfig(t, dir, coreConfigB)
	// The kernel booted on A and never picked B up, even though a previous
	// apply recorded version 70 as done.
	kernel := newFakeCoreKernel(t, filepath.Join(dir, "sing-box.json"), true)
	writeCoreConfig(t, dir, coreConfigA)
	kernel.boot()
	writeCoreConfig(t, dir, coreConfigB)
	r := newRuntimeTestRunner(t, dir, kernel)

	payload := model.ApplyCoreConfigTaskPayload{Config: coreConfigB}
	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	if err := r.persistAppliedVersion(model.AgentTaskTypeApplyCoreConfig, 70, payloadBytes); err != nil {
		t.Fatal(err)
	}
	kernel.armRestart()

	result, err := r.applyCoreConfigTask(70, payload)
	if err != nil {
		t.Fatal(err)
	}
	if result["idempotent_replay"] == true {
		t.Fatalf("a drifted kernel was answered from version state: %#v", result)
	}
	if result["reload_strategy"] != "runtime_drift_restart" {
		t.Fatalf("the drifted kernel was not recovered: %#v", result)
	}
	if kernel.digest() != mustOperationalDigest(t, resolvedCoreConfig(t, coreConfigB)) {
		t.Fatalf("kernel did not converge: loaded=%s", kernel.digest())
	}
}

// A replay over a converged kernel must stay cheap.
func TestApplyCoreConfigReplayShortcutsWhenKernelConverged(t *testing.T) {
	dir := t.TempDir()
	writeCoreConfig(t, dir, coreConfigB)
	kernel := newFakeCoreKernel(t, filepath.Join(dir, "sing-box.json"), true)
	r := newRuntimeTestRunner(t, dir, kernel)

	payload := model.ApplyCoreConfigTaskPayload{Config: coreConfigB}
	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	if err := r.persistAppliedVersion(model.AgentTaskTypeApplyCoreConfig, 71, payloadBytes); err != nil {
		t.Fatal(err)
	}
	boots := kernel.bootCount()

	result, err := r.applyCoreConfigTask(71, payload)
	if err != nil {
		t.Fatal(err)
	}
	if result["idempotent_replay"] != true {
		t.Fatalf("a converged kernel did not take the replay shortcut: %#v", result)
	}
	if kernel.bootCount() != boots {
		t.Fatal("the replay restarted a converged kernel")
	}
}

func TestActivateInstalledCoreReportsUnmanagedRestart(t *testing.T) {
	dir := t.TempDir()
	writeCoreConfig(t, dir, coreConfigA)
	kernel := newFakeCoreKernel(t, filepath.Join(dir, "sing-box.json"), true)
	kernel.reportBuild("old-build")
	binary := writeFakeCoreBinary(t, dir, "new-build")
	r := newRuntimeTestRunnerWithCore(t, dir, kernel, binary)

	result, err := r.activateInstalledCore(context.Background(), true)
	if err != nil {
		t.Fatal(err)
	}
	if result["core_activation"] != "unmanaged" {
		t.Fatalf("an unmanaged core was silently reported as activated: %#v", result)
	}
}

func TestActivateInstalledCoreUsesConfirmedInstallWhenBuildIsUnknown(t *testing.T) {
	dir := t.TempDir()
	writeCoreConfig(t, dir, coreConfigA)
	kernel := newFakeCoreKernel(t, filepath.Join(dir, "sing-box.json"), false)
	binary := writeFakeCoreBinary(t, dir, "same-on-disk-build")
	r := New(Config{
		StateDir: dir, CoreBinary: binary, CoreService: "oboard-sb-activation-test-missing",
		RestartCommand: "systemd-restart", ResourceProfile: "large", CommandTimeoutSeconds: 2,
	})
	r.coreClient = kernel.client

	result, err := r.activateInstalledCore(context.Background(), true)
	if err == nil {
		t.Fatalf("missing test service unexpectedly restarted: %#v", result)
	}
	if result["core_activation"] != "restart_failed" {
		t.Fatalf("confirmed installation did not attempt activation: %#v", result)
	}
}

// An update that installs the binaries but fails to activate the new kernel
// still has to restart this Agent onto its own new executable.
func TestAgentUpdateInstalled(t *testing.T) {
	if !agentUpdateInstalled("succeeded", `{"installed":true}`) {
		t.Fatal("a succeeded update was not treated as installed")
	}
	if !agentUpdateInstalled("failed", `{"installed":true}`) {
		t.Fatal("a failed activation discarded the completed install")
	}
	if agentUpdateInstalled("failed", `{"installed":false}`) {
		t.Fatal("a failed download was treated as installed")
	}
	if agentUpdateInstalled("failed", "not json") {
		t.Fatal("an unparsable result was treated as installed")
	}
}

// A release that changes the operational-digest normalization rule splits the
// two sides of the activation check: the still-running old Agent computes the
// desired digest with the old rule while the newly restarted kernel reports
// with the new one. The kernel owns the rule, so when the running build is the
// one this update just installed and the kernel's own -operational-digest of
// the file on disk matches what the process reports, the activation is
// converged instead of failing every credential-bearing node.
func TestActivateInstalledCoreAcceptsKernelDigestAcrossRuleChange(t *testing.T) {
	dir := t.TempDir()
	writeCoreConfig(t, dir, coreConfigA)
	kernel := newFakeCoreKernel(t, filepath.Join(dir, "sing-box.json"), true)
	// The restarted kernel reports a digest computed with the new rule, which
	// differs from what this (old-rule) Agent expects for the same file.
	kernelRuleDigest := strings.Repeat("ab", 32)
	kernel.reportDigest(kernelRuleDigest)
	kernel.stageBuild("new-build")
	kernel.armRestart()
	binary := writeFakeCoreBinaryWithDigest(t, dir, "new-build", kernelRuleDigest)
	r := newRuntimeTestRunnerWithCore(t, dir, kernel, binary)
	cfg := r.Config()
	cfg.RestartCommand = "systemd-restart"
	r.storeConfig(cfg)
	r.coreRestartCommand = func() error { kernel.bootIfArmed(); return nil }
	r.coreServiceActiveCheck = func() error { return nil }

	result, err := r.activateInstalledCore(context.Background(), true)
	if err != nil {
		t.Fatalf("a kernel-confirmed activation failed: %v (%#v)", err, result)
	}
	if result["core_activation"] != "restarted" {
		t.Fatalf("kernel-confirmed activation was not accepted: %#v", result)
	}
	if result["core_running_build_after"] != "0.0.1 / build new-build" {
		t.Fatalf("the running build was not the installed one: %#v", result)
	}
}

// A kernel whose own digest of the file disagrees with what the process
// reports is a real drift, and the kernel verdict must not clear it.
func TestActivateInstalledCoreKeepsDriftWhenKernelDigestDisagrees(t *testing.T) {
	dir := t.TempDir()
	writeCoreConfig(t, dir, coreConfigA)
	kernel := newFakeCoreKernel(t, filepath.Join(dir, "sing-box.json"), true)
	kernel.reportDigest(strings.Repeat("cd", 32))
	kernel.stageBuild("new-build")
	kernel.armRestart()
	// The kernel's own digest of the file differs from the reported digest.
	binary := writeFakeCoreBinaryWithDigest(t, dir, "new-build", strings.Repeat("ef", 32))
	r := newRuntimeTestRunnerWithCore(t, dir, kernel, binary)
	cfg := r.Config()
	cfg.RestartCommand = "systemd-restart"
	r.storeConfig(cfg)
	r.coreRestartCommand = func() error { kernel.bootIfArmed(); return nil }
	r.coreServiceActiveCheck = func() error { return nil }

	result, err := r.activateInstalledCore(context.Background(), true)
	if err == nil {
		t.Fatalf("a real drift was cleared by the kernel verdict: %#v", result)
	}
	if result["core_activation"] != "config_drift" {
		t.Fatalf("unexpected activation result: %#v", result)
	}
}

// Kernels that predate -operational-digest cannot arbitrate, so the verdict
// must report "no answer" and the original drift failure stands.
func TestActivateInstalledCoreKeepsDriftWhenKernelCannotDigest(t *testing.T) {
	dir := t.TempDir()
	writeCoreConfig(t, dir, coreConfigA)
	kernel := newFakeCoreKernel(t, filepath.Join(dir, "sing-box.json"), true)
	kernel.reportDigest(strings.Repeat("cd", 32))
	kernel.stageBuild("new-build")
	kernel.armRestart()
	// A kernel that exits 2 for the verb it never learned.
	binary := writeFakeCoreBinary(t, dir, "new-build")
	r := newRuntimeTestRunnerWithCore(t, dir, kernel, binary)

	verdict, answered := r.kernelDigestVerdict(context.Background(), filepath.Join(dir, "sing-box.json"), strings.Repeat("cd", 32))
	if answered {
		t.Fatal("a kernel without the digest verb was treated as an arbiter")
	}
	if verdict {
		t.Fatal("an unanswered verdict must never confirm convergence")
	}
}

// The verdict only accepts a well-formed hex digest from the kernel; garbage
// output is a non-answer, never a confirmation.
func TestKernelDigestVerdictRejectsMalformedOutput(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "sb-garbage"), []byte("#!/bin/sh\necho definitely-not-a-digest\n"), 0o755); err != nil { // #nosec G306 -- test fixture
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "sb-empty"), []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil { // #nosec G306 -- test fixture
		t.Fatal(err)
	}
	r := New(Config{StateDir: dir, ResourceProfile: "large"})
	for _, binary := range []string{"sb-garbage", "sb-empty"} {
		if _, answered := r.kernelDigestVerdict(context.Background(), filepath.Join(dir, binary), strings.Repeat("ab", 32)); answered {
			t.Fatalf("%s output was accepted as an arbiter answer", binary)
		}
	}
	if verdict, answered := r.kernelDigestVerdict(context.Background(), filepath.Join(dir, "sb-garbage"), ""); answered || verdict {
		t.Fatal("an empty loaded digest must short-circuit")
	}
}
