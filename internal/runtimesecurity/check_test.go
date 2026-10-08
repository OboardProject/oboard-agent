package runtimesecurity

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestBoundedInspection(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "state")
	if err := os.WriteFile(path, []byte("never-upload-this"), 0600); err != nil {
		t.Fatal(err)
	}
	if got := CheckManagedTree(context.Background(), dir); got != "passed" {
		t.Fatal(got)
	}
	if err := os.Chmod(path, 0644); err != nil {
		t.Fatal(err)
	}
	if got := CheckManagedTree(context.Background(), dir); got != "failed" {
		t.Fatal(got)
	}
	report := Inspect(context.Background(), Input{Mode: "enhanced", Encrypted: true, Targets: []Target{{ID: "state", Path: path}}, Kernel: &Kernel{Mode: "enhanced", Supported: true, NoNewPrivileges: true, CoreDumpsDisabled: true}})
	if report.State != "partial" && report.State != "unsupported" {
		t.Fatal(report.State)
	}
	raw, _ := json.Marshal(report)
	if strings.Contains(string(raw), "never-upload-this") || strings.Contains(string(raw), path) {
		t.Fatal("private contents or paths escaped")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if got := CheckManagedTree(ctx, dir); got != "unknown" {
		t.Fatal(got)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/etc", path); err != nil {
		t.Fatal(err)
	}
	if got := CheckManagedTree(context.Background(), dir); got != "failed" {
		t.Fatal(got)
	}
}
