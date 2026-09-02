package agent

import (
	"encoding/json"
	"testing"

	"github.com/OboardProject/oboard-agent/internal/model"
)

// requireSuperseded asserts a stale configuration task was skipped instead of
// applied or failed, and that it names the version this Agent really holds.
func requireSuperseded(t *testing.T, result map[string]any, err error, wantApplied int64) {
	t.Helper()
	if err != nil {
		t.Fatalf("a superseded task must not be an error: %v", err)
	}
	if result["superseded"] != true || result["applied_version"] != wantApplied {
		t.Fatalf("superseded result = %#v, want applied_version %d", result, wantApplied)
	}
}

// requireSupersededTaskResult is the same assertion for the raw task envelope
// returned by deployment tasks.
func requireSupersededTaskResult(t *testing.T, status, resultJSON string, wantApplied int64) {
	t.Helper()
	if status != "succeeded" {
		t.Fatalf("superseded status = %q, want succeeded so no failure is recorded: %s", status, resultJSON)
	}
	var result map[string]any
	if err := json.Unmarshal([]byte(resultJSON), &result); err != nil {
		t.Fatal(err)
	}
	if result["superseded"] != true || result["applied_version"] != float64(wantApplied) {
		t.Fatalf("superseded result = %#v, want applied_version %d", result, wantApplied)
	}
}

// TestCheckAppliedVersionClassifiesAcrossKinds covers the property that makes
// the shared watermark safe to keep: both configuration kinds are one totally
// ordered stream, and an older task of either kind is obsolete rather than
// broken.
func TestCheckAppliedVersionClassifiesAcrossKinds(t *testing.T) {
	runner := New(Config{StateDir: t.TempDir(), ResourceProfile: "large"})
	payload := []byte(`{"config":"a"}`)
	if err := runner.persistAppliedVersion(model.AgentTaskTypeApplyCoreConfig, 50, payload); err != nil {
		t.Fatal(err)
	}

	verdict, state, err := runner.checkAppliedVersion(model.AgentTaskTypeApplyDeployment, 40, []byte(`{"config":"b"}`))
	if err != nil {
		t.Fatalf("an older task of the other kind must not be an error: %v", err)
	}
	if verdict != appliedVersionSuperseded {
		t.Fatalf("verdict = %d, want superseded", verdict)
	}
	if state.Version != 50 || state.Kind != model.AgentTaskTypeApplyCoreConfig {
		t.Fatalf("reported state = %#v, want the core config watermark", state)
	}

	verdict, _, err = runner.checkAppliedVersion(model.AgentTaskTypeApplyCoreConfig, 50, payload)
	if err != nil || verdict != appliedVersionReplay {
		t.Fatalf("same version and payload verdict = %d err = %v, want replay", verdict, err)
	}

	if _, _, err = runner.checkAppliedVersion(model.AgentTaskTypeApplyCoreConfig, 50, []byte(`{"config":"c"}`)); err == nil {
		t.Fatal("one version describing two payloads must stay a hard failure")
	}

	verdict, _, err = runner.checkAppliedVersion(model.AgentTaskTypeApplyDeployment, 51, payload)
	if err != nil || verdict != appliedVersionApply {
		t.Fatalf("newer task verdict = %d err = %v, want apply", verdict, err)
	}
}

// TestSupersededDeploymentReportsSuccessWithAppliedVersion locks in the wire
// contract the Controller reconciles against: a skipped task succeeds and says
// which version this Agent actually holds.
func TestSupersededDeploymentReportsSuccessWithAppliedVersion(t *testing.T) {
	runner := New(Config{StateDir: t.TempDir(), ResourceProfile: "large"})
	if err := runner.persistAppliedVersion(model.AgentTaskTypeApplyCoreConfig, 80, []byte(`{}`)); err != nil {
		t.Fatal(err)
	}
	status, resultJSON := runner.executeDeploymentTask(model.DeploymentTaskPayload{Version: 70})
	if status != "succeeded" {
		t.Fatalf("status = %q, want succeeded so the Controller does not record a failure", status)
	}
	var result struct {
		Superseded     bool   `json:"superseded"`
		Version        int64  `json:"version"`
		AppliedVersion int64  `json:"applied_version"`
		AppliedKind    string `json:"applied_kind"`
	}
	if err := json.Unmarshal([]byte(resultJSON), &result); err != nil {
		t.Fatal(err)
	}
	if !result.Superseded || result.Version != 70 || result.AppliedVersion != 80 || result.AppliedKind != model.AgentTaskTypeApplyCoreConfig {
		t.Fatalf("result = %#v", result)
	}
}
