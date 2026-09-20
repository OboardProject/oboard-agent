package model_test

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/OboardProject/oboard-agent/internal/model"
	"github.com/OboardProject/oboard-agent/internal/security"
)

func TestPluginHostPowerWireAndSignature(t *testing.T) {
	payload := model.HostPowerTaskPayload{
		ProtocolVersion: model.HostPowerProtocolVersion,
		OperationID:     "op_plugin", Action: model.HostPowerActionReboot,
		ServerID: 9, Source: model.RemoteExecOriginPlugin, RunID: "run_plugin",
		PluginRevisionID: 12, TriggerBindingID: 3, GrantID: 4,
		IssuedAt:      time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		ExpiresAt:     time.Date(2026, 1, 1, 0, 1, 0, 0, time.UTC),
		PayloadDigest: "digest",
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	const expected = `{"protocol_version":1,"operation_id":"op_plugin","action":"reboot","server_id":9,"source":"plugin","run_id":"run_plugin","plugin_revision_id":12,"trigger_binding_id":3,"grant_id":4,"issued_at":"2026-01-01T00:00:00Z","expires_at":"2026-01-01T00:01:00Z","payload_digest":"digest"}`
	if string(raw) != expected {
		t.Fatalf("wire mismatch: %s", raw)
	}
	var decoded model.HostPowerTaskPayload
	if err := json.Unmarshal(raw, &decoded); err != nil || decoded.PluginRevisionID != 12 {
		t.Fatalf("decode revision: %+v, %v", decoded, err)
	}
	envelope := security.TaskEnvelope{ID: 7, ServerID: 9, Type: model.AgentTaskTypeHostPowerAction, ConfigVersion: 2, Nonce: "plugin-nonce", PayloadJSON: string(raw)}
	signature := security.SignTaskEnvelope("plugin-contract-test", envelope)
	if !security.VerifyTaskEnvelopeSignature("plugin-contract-test", envelope, signature) {
		t.Fatal("plugin payload signature rejected")
	}
	for _, altered := range []string{
		strings.Replace(expected, `"source":"plugin"`, `"source":"script"`, 1),
		strings.Replace(expected, `"plugin_revision_id":12`, `"plugin_revision_id":13`, 1),
		strings.Replace(expected, "plugin_revision_id", "script_revision_id", 1),
	} {
		envelope.PayloadJSON = altered
		if security.VerifyTaskEnvelopeSignature("plugin-contract-test", envelope, signature) {
			t.Fatal("signature accepted modified plugin source/revision")
		}
	}
}
