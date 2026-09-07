package agent

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/OboardProject/oboard-agent/internal/agentsecurity"
	"github.com/OboardProject/oboard-agent/internal/model"
)

func testAgentConfig(dir string, serverID int64) Config {
	return Config{
		StateDir: dir, ConfigPath: filepath.Join(dir, "agent.json"), ServerID: serverID,
		CommandTimeoutSeconds: 20, ResourceProfile: "small", TimeCorrectionMode: "off",
		LogMaxMB: 8, CoreLogMaxMB: 8,
	}
}

func stubHostPower(t *testing.T, invoker func(string) error) {
	t.Helper()
	hostPowerInvoker = invoker
	hostPowerInContainer = func() bool { return false }
	t.Cleanup(func() {
		hostPowerInvoker = invokeHostPowerCommand
		hostPowerInContainer = runningInContainer
	})
}

func TestHostPowerUsesStubAndRecordsIntent(t *testing.T) {
	dir := t.TempDir()
	called := 0
	stubHostPower(t, func(action string) error {
		called++
		if action != model.HostPowerActionReboot {
			t.Fatalf("unexpected action %s", action)
		}
		return nil
	})
	cfg := testAgentConfig(dir, 9)
	if err := agentsecurity.NewStore(agentsecurity.PathForConfig(cfg.ConfigPath)).SetAllow("host-power", true); err != nil {
		t.Fatal(err)
	}
	runner := New(cfg)
	payload := model.HostPowerTaskPayload{
		ProtocolVersion: model.HostPowerProtocolVersion,
		OperationID:     "op_test",
		Action:          model.HostPowerActionReboot,
		ServerID:        9,
		Source:          model.RemoteExecOriginScript,
		IssuedAt:        time.Now().UTC(),
		ExpiresAt:       time.Now().UTC().Add(time.Minute),
		PayloadDigest:   "digest-1",
	}
	raw, _ := json.Marshal(payload)
	status, result := runner.executeHostPowerTask(model.AgentTask{PayloadJSON: string(raw)})
	if status != "succeeded" {
		t.Fatalf("status=%s result=%s", status, result)
	}
	if called != 1 {
		t.Fatalf("invoker called %d times", called)
	}
	status, result = runner.executeHostPowerTask(model.AgentTask{PayloadJSON: string(raw)})
	if status == "succeeded" {
		t.Fatalf("replay must not report success: %s", result)
	}
}

func TestHostPowerLocalPolicyDeniesByDefault(t *testing.T) {
	dir := t.TempDir()
	stubHostPower(t, func(string) error {
		t.Fatal("invoker must not run")
		return nil
	})
	runner := New(testAgentConfig(dir, 9))
	payload := model.HostPowerTaskPayload{
		ProtocolVersion: model.HostPowerProtocolVersion,
		OperationID:     "op_denied",
		Action:          model.HostPowerActionPoweroff,
		ServerID:        9,
		Source:          model.RemoteExecOriginScript,
		IssuedAt:        time.Now().UTC(),
		ExpiresAt:       time.Now().UTC().Add(time.Minute),
		PayloadDigest:   "digest-2",
	}
	raw, _ := json.Marshal(payload)
	status, result := runner.executeHostPowerTask(model.AgentTask{PayloadJSON: string(raw)})
	if status != "failed" || !strings.Contains(result, "permission_denied") {
		t.Fatalf("expected local deny, got %s %s", status, result)
	}
}

func TestOperationJournalKeepsPending(t *testing.T) {
	dir := t.TempDir()
	journal := newOperationJournal(dir)
	if _, err := journal.Begin("op1", "d1", "reboot"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, operationJournalFileName)); err != nil {
		t.Fatal(err)
	}
	if _, err := journal.Begin("op1", "other", "reboot"); err != errOperationConflict {
		t.Fatalf("expected conflict, got %v", err)
	}
}
