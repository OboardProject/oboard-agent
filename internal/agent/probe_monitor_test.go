package agent

import (
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
