package agent

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"time"

	"github.com/OboardProject/oboard-agent/internal/model"
)

var hostPowerInvoker = invokeHostPowerCommand

func (r *Runner) executeHostPowerTask(task model.AgentTask) (string, string) {
	var payload model.HostPowerTaskPayload
	if err := json.Unmarshal([]byte(task.PayloadJSON), &payload); err != nil {
		return "failed", jsonResult(err.Error())
	}
	if payload.ProtocolVersion != model.HostPowerProtocolVersion {
		return "failed", jsonMap(map[string]any{"error_code": "capability_unsupported", "error": "unsupported host power protocol"})
	}
	if payload.ServerID != r.serverID() {
		return "failed", jsonMap(map[string]any{"error_code": "resource_out_of_scope", "error": "host power target does not match this agent"})
	}
	if payload.Source != model.RemoteExecOriginScript {
		return "failed", jsonMap(map[string]any{"error_code": "permission_denied", "error": "host power requires a script origin"})
	}
	if payload.Action != model.HostPowerActionPoweroff && payload.Action != model.HostPowerActionReboot {
		return "failed", jsonMap(map[string]any{"error_code": "invalid_input", "error": "action must be poweroff or reboot"})
	}
	if !r.localGateAllows("host_power") {
		return "failed", jsonMap(map[string]any{"error_code": "permission_denied", "error": "agent local host power policy denied this operation"})
	}
	now := time.Now().UTC()
	if payload.ExpiresAt.IsZero() || !now.Before(payload.ExpiresAt) {
		return "failed", jsonMap(map[string]any{"error_code": "operation_expired", "error": "host power task has expired"})
	}
	if payload.ExpectedBootID != "" && payload.ExpectedBootID != currentBootID() {
		return "failed", jsonMap(map[string]any{"error_code": "condition_changed", "error": "host boot identity changed"})
	}
	if runningInContainer() {
		return "failed", jsonMap(map[string]any{"error_code": "capability_unsupported", "error": "container hosts cannot control host power"})
	}
	digest := payload.PayloadDigest
	if digest == "" {
		sum := sha256.Sum256([]byte(task.PayloadJSON))
		digest = hex.EncodeToString(sum[:])
	}
	journal := newOperationJournal(r.stateDir())
	record, err := journal.Begin(payload.OperationID, digest, payload.Action)
	if errors.Is(err, errOperationConflict) {
		return "failed", jsonMap(map[string]any{"error_code": "idempotency_conflict", "error": err.Error()})
	}
	if errors.Is(err, errOperationJournalFull) || isJournalStorageError(err) {
		return "failed", jsonMap(map[string]any{"error_code": "result_unknown", "error": "host power journal cannot accept a new action"})
	}
	if err != nil {
		return "failed", jsonMap(map[string]any{"error_code": "result_unknown", "error": err.Error()})
	}
	if record != nil && record.State != "pending" {
		if record.State == "succeeded" {
			return "failed", jsonMap(map[string]any{"error_code": "result_unknown", "error": "refusing to replay a completed host power record as success"})
		}
		return record.State, string(record.ResultJSON)
	}
	lock, err := r.acquireStrictHostLock(hostCoreLockWait)
	if err != nil {
		_ = journal.Complete(payload.OperationID, digest, "failed", json.RawMessage(`{"error_code":"condition_changed"}`))
		return "failed", jsonMap(map[string]any{"error_code": "condition_changed", "error": err.Error()})
	}
	defer lock.release()
	if err := journal.Complete(payload.OperationID, digest, "initiated", json.RawMessage(`{"stage":"initiated"}`)); err != nil {
		return "failed", jsonMap(map[string]any{"error_code": "result_unknown", "error": "failed to persist host power intent"})
	}
	if err := hostPowerInvoker(payload.Action); err != nil {
		result := json.RawMessage(`{"error_code":"result_unknown","stage":"unknown"}`)
		_ = journal.Complete(payload.OperationID, digest, "unknown", result)
		return "failed", jsonMap(map[string]any{"error_code": "result_unknown", "error": err.Error(), "stage": model.HostPowerReceiptUnknown})
	}
	result := mustJSON(map[string]any{"operation_id": payload.OperationID, "stage": model.HostPowerReceiptInitiated, "accepted": true})
	_ = journal.Complete(payload.OperationID, digest, "initiated", result)
	return "succeeded", string(result)
}

func (r *Runner) serverID() int64 {
	return r.Config().ServerID
}

func currentBootID() string {
	raw, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(raw))
}

func runningInContainer() bool {
	if _, err := os.Stat("/.dockerenv"); err == nil {
		return true
	}
	if _, err := os.Stat("/run/.containerenv"); err == nil {
		return true
	}
	raw, err := os.ReadFile("/proc/1/cgroup")
	if err != nil {
		return false
	}
	text := string(raw)
	return strings.Contains(text, "docker") || strings.Contains(text, "lxc") || strings.Contains(text, "podman") || strings.Contains(text, "containerd")
}

func mustJSON(value any) json.RawMessage {
	raw, _ := json.Marshal(value)
	return raw
}
