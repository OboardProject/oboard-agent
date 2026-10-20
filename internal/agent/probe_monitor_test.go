package agent

import (
	"encoding/json"
	"github.com/OboardProject/oboard-agent/internal/model"
	"testing"
	"time"
)

func TestProbeMonitorOriginKeepsPluginBoundary(t *testing.T) {
	runner := diagnosticRunner(t, false)
	task := dnsTask(t, func(p *model.NetworkDNSLookupTaskPayload) {
		p.Origin = model.NetworkDiagnosticOriginMonitor
		p.PluginID = ""
		p.InstanceID = 0
		p.RunID = ""
	})
	status, result := runner.executeNetworkDiagnosticTask(task)
	if diagnosticCode(t, status, result) != model.NetworkDiagnosticCodeInvalidInput {
		t.Fatal("monitor origin accepted for non-trace task")
	}
	envelope := model.NetworkDiagnosticEnvelope{ProtocolVersion: model.NetworkDiagnosticProtocolVersion, Origin: model.NetworkDiagnosticOriginMonitor, OperationID: "monitor-1", IssuedAt: time.Now(), ExpiresAt: time.Now().Add(time.Minute)}
	if _, _, ok := runner.validateDiagnosticEnvelope(envelope); !ok {
		t.Fatal("native monitor depends on plugin gate")
	}
	envelope.PluginID = "plugin"
	if _, _, ok := runner.validateDiagnosticEnvelope(envelope); ok {
		t.Fatal("monitor with plugin identity accepted")
	}
	envelope.PluginID = ""
	envelope.Origin = model.NetworkDiagnosticOriginPlugin
	if _, _, ok := runner.validateDiagnosticEnvelope(envelope); ok {
		t.Fatal("plugin bypassed local gate")
	}
}

func TestGoogleRegionProbeRequiresMonitorOrigin(t *testing.T) {
	runner := diagnosticRunner(t, true)
	payload := model.GoogleRegionTaskPayload{NetworkDiagnosticEnvelope: model.NetworkDiagnosticEnvelope{ProtocolVersion: model.NetworkDiagnosticProtocolVersion, Origin: model.NetworkDiagnosticOriginPlugin, OperationID: "op-1", RunID: "run-1", PluginID: "acme.demo", InstanceID: 1, IssuedAt: time.Now(), ExpiresAt: time.Now().Add(time.Minute)}, IPFamily: model.NetworkFamilyIPv4}
	raw, _ := json.Marshal(payload)
	status, result := runner.executeNetworkDiagnosticTask(model.AgentTask{Type: model.AgentTaskTypeGoogleRegion, PayloadJSON: string(raw)})
	if diagnosticCode(t, status, result) != model.NetworkDiagnosticCodeInvalidInput {
		t.Fatal("plugin origin accepted for the Google region probe")
	}
	payload.Origin, payload.PluginID, payload.InstanceID, payload.RunID, payload.IPFamily = model.NetworkDiagnosticOriginMonitor, "", 0, "", model.NetworkFamilyAuto
	raw, _ = json.Marshal(payload)
	status, result = runner.executeNetworkDiagnosticTask(model.AgentTask{Type: model.AgentTaskTypeGoogleRegion, PayloadJSON: string(raw)})
	if diagnosticCode(t, status, result) != model.NetworkDiagnosticCodeInvalidInput {
		t.Fatal("monitor probe accepted an auto address family")
	}
	if !isNetworkDiagnosticTask(model.AgentTaskTypeGoogleRegion) {
		t.Fatal("Google region probe is not routed as a diagnostic")
	}
}
