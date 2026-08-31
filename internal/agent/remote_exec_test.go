package agent

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/OboardProject/oboard-agent/internal/model"
)

func TestRemoteExecArgvDoesNotExpandShell(t *testing.T) {
	dir := t.TempDir()
	runner := New(Config{StateDir: dir, CommandTimeoutSeconds: 20, ResourceProfile: "small", TimeCorrectionMode: "off", LogMaxMB: 8, CoreLogMaxMB: 8})
	payload, _ := json.Marshal(model.RemoteExecTaskPayload{
		RequestID: "req-argv-1",
		Origin:    model.RemoteExecOriginMCP,
		Privilege: model.PrivilegeRemoteExec,
		Command:   model.RemoteExecCommand{Mode: model.RemoteExecModeArgv, Argv: []string{"echo", "$(id)"}},
		Limits:    model.RemoteExecLimits{TimeoutSeconds: 5},
	})
	status, raw := runner.executeRemoteExecTask(model.AgentTask{PayloadJSON: string(payload)})
	if status != "succeeded" {
		t.Fatalf("status=%s result=%s", status, raw)
	}
	var result model.RemoteExecResult
	if err := json.Unmarshal([]byte(raw), &result); err != nil {
		t.Fatal(err)
	}
	if result.ExitCode != 0 {
		t.Fatalf("exit=%d stderr=%s", result.ExitCode, result.Stderr)
	}
	if result.Stdout != "$(id)\n" && result.Stdout != "$(id)" {
		t.Fatalf("stdout=%q, want literal $(id)", result.Stdout)
	}
}

func TestRemoteExecJournalAtMostOnce(t *testing.T) {
	dir := t.TempDir()
	journal := newRemoteExecJournal(filepath.Join(dir, "remote-exec"))
	if rec, err := journal.Begin("req-1", "abc"); err != nil || rec != nil {
		t.Fatalf("first begin: rec=%v err=%v", rec, err)
	}
	if _, err := journal.Begin("req-1", "abc"); err != errRemoteExecRunning {
		t.Fatalf("running replay: %v", err)
	}
	if err := journal.Complete("req-1", "abc", []byte(`{"exit_code":0}`)); err != nil {
		t.Fatal(err)
	}
	rec, err := journal.Begin("req-1", "abc")
	if err != nil || rec == nil || rec.State != remoteExecStateCompleted {
		t.Fatalf("completed replay: rec=%v err=%v", rec, err)
	}
	if _, err := journal.Begin("req-1", "other"); err != errRemoteExecConflict {
		t.Fatalf("conflict: %v", err)
	}
}

func TestRemoteExecJournalSurvivesRestart(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "remote-exec")
	first := newRemoteExecJournal(path)
	if _, err := first.Begin("req-persist", "hash"); err != nil {
		t.Fatal(err)
	}
	if err := first.Complete("req-persist", "hash", []byte(`{"exit_code":7}`)); err != nil {
		t.Fatal(err)
	}
	second := newRemoteExecJournal(path)
	rec, err := second.Begin("req-persist", "hash")
	if err != nil || rec == nil || string(rec.ResultJSON) != `{"exit_code":7}` {
		t.Fatalf("persisted replay: rec=%v err=%v", rec, err)
	}
}

func TestLocalSecurityHardenedDenies(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "local-security.json")
	if err := os.WriteFile(path, []byte(`{"version":1,"mode":"hardened","allow":{"remote_terminal":false,"mcp_enabled":false}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	runner := New(Config{ConfigPath: filepath.Join(dir, "config.json"), StateDir: dir, CommandTimeoutSeconds: 20, ResourceProfile: "small", TimeCorrectionMode: "off", LogMaxMB: 8, CoreLogMaxMB: 8})
	if runner.localGateAllows("remote_terminal") || runner.localGateAllows("mcp_enabled") {
		t.Fatal("hardened deny should block remote access")
	}
}

func TestRemoteExecStdoutLimitTruncates(t *testing.T) {
	dir := t.TempDir()
	runner := New(Config{StateDir: dir, CommandTimeoutSeconds: 20, ResourceProfile: "small", TimeCorrectionMode: "off", LogMaxMB: 8, CoreLogMaxMB: 8})
	payload, _ := json.Marshal(model.RemoteExecTaskPayload{
		RequestID: "req-limit-1",
		Origin:    model.RemoteExecOriginMCP,
		Privilege: model.PrivilegeRemoteExec,
		Command:   model.RemoteExecCommand{Mode: model.RemoteExecModeArgv, Argv: []string{"echo", "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"}},
		Limits:    model.RemoteExecLimits{TimeoutSeconds: 5, StdoutBytes: 16, StderrBytes: 16},
	})
	status, raw := runner.executeRemoteExecTask(model.AgentTask{PayloadJSON: string(payload)})
	if status != "succeeded" {
		t.Fatalf("status=%s result=%s", status, raw)
	}
	var result model.RemoteExecResult
	if err := json.Unmarshal([]byte(raw), &result); err != nil {
		t.Fatal(err)
	}
	if !result.StdoutTruncated {
		t.Fatalf("expected truncated stdout: %#v", result)
	}
	if result.StdoutBytes > 16 {
		t.Fatalf("stdout bytes %d exceed limit", result.StdoutBytes)
	}
}

func TestRemoteExecTimeoutKillsProcessGroup(t *testing.T) {
	dir := t.TempDir()
	runner := New(Config{StateDir: dir, CommandTimeoutSeconds: 20, ResourceProfile: "small", TimeCorrectionMode: "off", LogMaxMB: 8, CoreLogMaxMB: 8})
	payload, _ := json.Marshal(model.RemoteExecTaskPayload{
		RequestID: "req-timeout-1",
		Origin:    model.RemoteExecOriginMCP,
		Privilege: model.PrivilegeRemoteShell,
		Command:   model.RemoteExecCommand{Mode: model.RemoteExecModeShell, Shell: "sleep 30"},
		Limits:    model.RemoteExecLimits{TimeoutSeconds: 1, StdoutBytes: 1024, StderrBytes: 1024},
	})
	started := time.Now()
	status, raw := runner.executeRemoteExecTask(model.AgentTask{PayloadJSON: string(payload)})
	if elapsed := time.Since(started); elapsed > 8*time.Second {
		t.Fatalf("timeout took too long: %s", elapsed)
	}
	var result model.RemoteExecResult
	_ = json.Unmarshal([]byte(raw), &result)
	if result.Error != "remote_exec_timeout" && status != "failed" {
		t.Fatalf("status=%s result=%s", status, raw)
	}
}

func TestUpdateAgentConfigRejectsLocalSecurity(t *testing.T) {
	dir := t.TempDir()
	runner := New(Config{StateDir: dir, CommandTimeoutSeconds: 20, ResourceProfile: "small", TimeCorrectionMode: "off", LogMaxMB: 8, CoreLogMaxMB: 8})
	_, err := runner.updateAgentConfig(Config{}, map[string]json.RawMessage{"local-security": []byte(`{}`)})
	if err == nil {
		t.Fatal("update_agent_config must reject local-security keys")
	}
}
