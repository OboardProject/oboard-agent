package security

import (
	"testing"
)

func TestValidateControllerURLProductionRejectsPublicHTTP(t *testing.T) {
	if _, err := ValidateControllerURL("http://203.0.113.10:8080", false, false); err == nil {
		t.Fatal("production public http should be rejected")
	}
	if _, err := ValidateControllerURL("http://127.0.0.1:8080", false, false); err != nil {
		t.Fatalf("localhost http should be allowed: %v", err)
	}
	if _, err := ValidateControllerURL("http://203.0.113.10:8080", false, true); err != nil {
		t.Fatalf("explicit insecure override should be allowed: %v", err)
	}
}

func TestControllerWebSocketURLPreservesBasePath(t *testing.T) {
	got, err := ControllerWebSocketURL("https://panel.example.com/hidden-panel/", false, false)
	if err != nil {
		t.Fatal(err)
	}
	if want := "wss://panel.example.com/hidden-panel/api/v1/agent/connect"; got != want {
		t.Fatalf("ControllerWebSocketURL() = %q; want %q", got, want)
	}
}

func TestTaskEnvelopeSignatureCoversEnvelope(t *testing.T) {
	task := TaskEnvelope{ID: 1, ServerID: 2, Type: "apply_core_config", ConfigVersion: 3, Nonce: "n", PayloadJSON: `{"x":1}`}
	sig := SignTaskEnvelope("secret", task)
	if !VerifyTaskEnvelopeSignature("secret", task, sig) {
		t.Fatal("v2 signature should verify")
	}
	task.Type = "collect_logs"
	if VerifyTaskEnvelopeSignature("secret", task, sig) {
		t.Fatal("v2 signature must cover task type")
	}
}
