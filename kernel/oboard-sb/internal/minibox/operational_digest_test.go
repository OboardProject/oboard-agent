package minibox

import (
	"os"
	"path/filepath"
	"testing"
)

// The kernel and Agent must derive the same operational digest from the same
// bytes. These vectors are duplicated in the Agent test suite; if either side
// changes its normalization, one of the two suites fails.
func TestOperationalConfigDigestIgnoresRuntimePolicy(t *testing.T) {
	base := `{"log":{"level":"warn"},"_oboard":{"rate_limits":{"users":{"alice":{"user_id":7,"lease_bytes":100}}},"connection_audit":{"enabled":true}}}`
	changedRuntimePolicy := `{"log":{"level":"warn"},"_oboard":{"rate_limits":{"users":{"alice":{"user_id":7,"lease_bytes":900}}},"connection_audit":{"enabled":false}}}`
	reformatted := "{\n\t\"_oboard\": {\n\t\t\"connection_audit\": {\"enabled\": true},\n\t\t\"rate_limits\": {\"users\": {\"alice\": {\"lease_bytes\": 100, \"user_id\": 7}}}\n\t},\n\t\"log\": {\"level\": \"warn\"}\n}"

	baseDigest := mustDigest(t, base)
	if mustDigest(t, changedRuntimePolicy) != baseDigest {
		t.Fatal("runtime-only metadata changed the operational digest")
	}
	if mustDigest(t, reformatted) != baseDigest {
		t.Fatal("formatting or key order changed the operational digest")
	}
	if mustDigest(t, `{"log":{"level":"error"},"_oboard":{"rate_limits":{}}}`) == baseDigest {
		t.Fatal("an operational change did not change the digest")
	}
}

// Removing the last runtime-only member must also remove the now-empty
// `_oboard` block, so a config with and without it hash the same.
func TestOperationalConfigDigestDropsEmptyMetadataBlock(t *testing.T) {
	withBlock := `{"log":{"level":"warn"},"_oboard":{"rate_limits":{}}}`
	without := `{"log":{"level":"warn"}}`
	if mustDigest(t, withBlock) != mustDigest(t, without) {
		t.Fatal("an empty runtime metadata block changed the operational digest")
	}
}

func TestOperationalConfigDigestRejectsInvalidConfig(t *testing.T) {
	for _, invalid := range []string{"", "   ", "[]", `{"log":{}} {"log":{}}`, `{"log":`} {
		if _, err := OperationalConfigDigest([]byte(invalid)); err == nil {
			t.Fatalf("invalid configuration %q produced a digest", invalid)
		}
	}
}

func TestOperationalConfigDigestFileMatchesBytes(t *testing.T) {
	config := `{"log":{"level":"warn"},"_oboard":{"rate_limits":{"users":{}}}}`
	path := filepath.Join(t.TempDir(), "sing-box.json")
	if err := os.WriteFile(path, []byte(config), 0o600); err != nil {
		t.Fatal(err)
	}
	fromFile, err := OperationalConfigDigestFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if fromFile != mustDigest(t, config) {
		t.Fatal("file and byte digests differ")
	}
}

func mustDigest(t *testing.T, config string) string {
	t.Helper()
	digest, err := OperationalConfigDigest([]byte(config))
	if err != nil {
		t.Fatal(err)
	}
	return digest
}
