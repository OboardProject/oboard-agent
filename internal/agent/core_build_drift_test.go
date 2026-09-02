package agent

import (
	"context"
	"encoding/json"
	"path/filepath"
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
