package stealth

import (
	"bytes"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
)

// The vectors below are a wire contract with the agent's
// internal/stealth package: both implementations must derive the same
// physical names for the same key. The agent package pins the same vectors;
// changing the derivation requires changing both sides in one release.

var (
	contractKey, _  = hex.DecodeString("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
	contractLogical = "sing-box.json"
)

func TestPhysicalNameContractVector(t *testing.T) {
	// Pinned vector; regenerate deliberately (together with the agent
	// package's identical vector) if the derivation ever changes on purpose.
	const want = "4ff2c95637ba990b"
	if got := PhysicalName(contractKey, contractLogical); got != want {
		t.Fatalf("PhysicalName = %s, want %s", got, want)
	}
}

func TestEnvelopeRoundTrip(t *testing.T) {
	plaintext := []byte(`{"inbounds":[{"type":"shadowsocks"}]}`)
	envelope, err := Encrypt(contractKey, plaintext)
	if err != nil {
		t.Fatal(err)
	}
	if !IsEncrypted(envelope) {
		t.Fatal("envelope should carry the magic prefix")
	}
	if bytes.Contains(envelope, plaintext) {
		t.Fatal("envelope leaks plaintext")
	}
	decrypted, err := Decrypt(contractKey, envelope)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(decrypted, plaintext) {
		t.Fatalf("round trip mismatch: %q", decrypted)
	}
	if _, err := Decrypt(contractKey, []byte(`{"plain":true}`)); err != ErrNotEncrypted {
		t.Fatalf("plaintext input: got %v", err)
	}
}

func TestLoadKeyRejectsWrongSize(t *testing.T) {
	path := filepath.Join(t.TempDir(), "key")
	if err := os.WriteFile(path, []byte("short"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadKey(path); err == nil {
		t.Fatal("short key must be rejected")
	}
	if err := os.WriteFile(path, contractKey, 0o600); err != nil {
		t.Fatal(err)
	}
	key, err := LoadKey(path)
	if err != nil || len(key) != KeyLen {
		t.Fatalf("LoadKey = %v, %v", key, err)
	}
}
