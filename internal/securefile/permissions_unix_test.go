//go:build !windows

package securefile

import (
	"os"
	"path/filepath"
	"testing"
)

func TestRestrictManagedPermissions(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "secret")
	if err := os.WriteFile(path, []byte("private"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := Restrict(path, false); err != nil {
		t.Fatal(err)
	}
	if info, err := os.Stat(path); err != nil || info.Mode().Perm() != 0600 {
		t.Fatal(info, err)
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	if err := Restrict(link, false); err == nil {
		t.Fatal("symlink accepted")
	}
	hard := filepath.Join(dir, "hard")
	if err := os.Link(path, hard); err != nil {
		t.Fatal(err)
	}
	if err := Restrict(path, false); err == nil {
		t.Fatal("hardlink accepted")
	}
	if err := Restrict(dir, false); err == nil {
		t.Fatal("directory accepted as file")
	}
}
