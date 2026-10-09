package runtimeguard

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
)

func TestProcessEvidenceDoesNotExportSecrets(t *testing.T) {
	previous := os.Args
	os.Args = []string{"oboard-sb", "--password=never-export-value"}
	t.Cleanup(func() { os.Args = previous })
	t.Setenv("RUNTIME_TEST_TOKEN", "never-export-env")
	SetLocalAPI("unix:/private/management.sock")
	state := State{}
	processEvidence(&state)
	if !state.SensitiveArguments || !state.SensitiveEnvironment || state.LocalAPI != "unix" {
		t.Fatal(state)
	}
	raw, _ := json.Marshal(state)
	if strings.Contains(string(raw), "never-export") || strings.Contains(string(raw), "management.sock") {
		t.Fatal("secret or local path exported")
	}
	SetLocalAPI("127.0.0.1:9000")
	state = State{}
	processEvidence(&state)
	if state.LocalAPI != "tcp" {
		t.Fatal(state.LocalAPI)
	}
}
