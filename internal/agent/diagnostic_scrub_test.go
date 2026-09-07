package agent

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestScrubDiagnosticOutputRedactsUUIDAndTrustedForwardKey(t *testing.T) {
	raw, _ := json.Marshal(map[string]any{
		"inbounds": []map[string]any{{
			"users": []map[string]any{{"uuid": "11111111-1111-4111-8111-111111111111", "password": "proxy-pass"}},
		}},
		"_oboard": map[string]any{
			"trusted_forward": map[string]any{
				"receivers": []map[string]any{{"key": "tf-receiver-secret"}},
			},
		},
	})
	got := scrubDiagnosticOutput(string(raw))
	for _, secret := range []string{"11111111-1111-4111-8111-111111111111", "proxy-pass", "tf-receiver-secret"} {
		if strings.Contains(got, secret) {
			t.Fatalf("diagnostic output leaked %q: %s", secret, got)
		}
	}
	if !strings.Contains(got, "[redacted]") {
		t.Fatalf("expected redaction markers, got %s", got)
	}
}

func TestScrubDiagnosticOutputRedactsNestedJSONContent(t *testing.T) {
	inner, _ := json.Marshal(map[string]any{
		"inbounds": []map[string]any{{"users": []map[string]any{{"uuid": "22222222-2222-4222-8222-222222222222"}}}},
		"_oboard":  map[string]any{"trusted_forward": map[string]any{"receivers": []map[string]any{{"key": "nested-tf-key"}}}},
	})
	wrapped, _ := json.Marshal(map[string]any{
		"files": map[string]any{"sing_box_config": map[string]any{"content": string(inner)}},
	})
	got := scrubDiagnosticOutput(string(wrapped))
	for _, secret := range []string{"22222222-2222-4222-8222-222222222222", "nested-tf-key"} {
		if strings.Contains(got, secret) {
			t.Fatalf("nested diagnostic content leaked %q: %s", secret, got)
		}
	}
}
