package runtimeguard

import (
	"os"
	"os/exec"
	"testing"
)

func TestRuntimeSecurityLinuxProcessProfile(t *testing.T) {
	if os.Getenv("OBOARD_RUNTIME_GUARD_TEST") == "1" {
		if err := Apply("enhanced"); err != nil {
			t.Fatal(err)
		}
		state := Snapshot()
		if !state.Supported || state.Mode != "enhanced" || !state.NoNewPrivileges || state.Dumpable || !state.CoreDumpsDisabled {
			t.Fatalf("profile not applied: %+v", state)
		}
		if err := Apply("enhanced"); err != nil {
			t.Fatal("idempotent apply", err)
		}
		return
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestRuntimeSecurityLinuxProcessProfile$")
	cmd.Env = append(os.Environ(), "OBOARD_RUNTIME_GUARD_TEST=1")
	if raw, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("isolated guard: %v %s", err, raw)
	}
}
