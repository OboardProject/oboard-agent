package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestRuntimeSecurityPolicyRejectsUnsafeState(t *testing.T) {
	dir := t.TempDir()
	config := filepath.Join(dir, "sing-box.json")
	policy := filepath.Join(dir, "runtime-security.json")
	if err := applyRuntimeSecurityPolicy(config, nil); err != nil {
		t.Fatal("default standard", err)
	}
	for _, raw := range []string{"broken", "{\"mode\":\"invalid\"}"} {
		if err := os.WriteFile(policy, []byte(raw), 0600); err != nil {
			t.Fatal(err)
		}
		if err := applyRuntimeSecurityPolicy(config, nil); err == nil {
			t.Fatal("invalid policy accepted")
		}
	}
	if err := os.WriteFile(policy, []byte("{\"mode\":\"standard\"}"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := applyRuntimeSecurityPolicy(config, nil); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(policy, 0644); err != nil {
		t.Fatal(err)
	}
	if err := applyRuntimeSecurityPolicy(config, nil); err == nil {
		t.Fatal("public policy accepted")
	}
	if err := os.Remove(policy); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(dir, "target")
	if err := os.WriteFile(target, []byte("{\"mode\":\"standard\"}"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, policy); err != nil {
		t.Fatal(err)
	}
	if err := applyRuntimeSecurityPolicy(config, nil); err == nil {
		t.Fatal("symlink policy accepted")
	}
}
