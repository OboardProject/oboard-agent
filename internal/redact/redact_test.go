package redact

import (
	"strings"
	"testing"
)

func TestRedactCredentials(t *testing.T) {
	for _, input := range []string{
		"token=supersecret stage=apply", "password: supersecret", "Bearer supersecret", "https://user:supersecret@example.test", "{\"psk\":\"supersecret\"}", "-----BEGIN PRIVATE KEY-----\nsupersecret\n-----END PRIVATE KEY-----",
	} {
		result := Text(input)
		if strings.Contains(result, "supersecret") {
			t.Fatalf("secret escaped: %q", result)
		}
	}
	if got := Text("stage=apply version=v1 error=timeout"); got != "stage=apply version=v1 error=timeout" {
		t.Fatal(got)
	}
	if got := Text("token=supersecret stage=apply"); !strings.Contains(got, "token=") || !strings.Contains(got, "stage=apply") {
		t.Fatal(got)
	}
}
