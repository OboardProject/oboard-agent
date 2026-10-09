package securefile

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestAtomicPrivateState(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state")
	for _, value := range []string{"old", "replacement"} {
		if err := Write(path, []byte(value), 0600, true); err != nil {
			t.Fatal(err)
		}
		raw, err := Read(path, 1024)
		if err != nil || string(raw) != value {
			t.Fatalf("read: %q %v", raw, err)
		}
		info, _ := os.Stat(path)
		if info.Mode().Perm() != 0600 {
			t.Fatal(info.Mode())
		}
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 1 {
		t.Fatal("temporary file leaked")
	}
	if _, err := Read(path, 2); err == nil {
		t.Fatal("oversized read accepted")
	}
}
func TestRejectSymlinkAndPreserveDestination(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	link := filepath.Join(dir, "link")
	if err := os.WriteFile(target, []byte("secret"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if err := Write(link, []byte("overwrite"), 0600, true); err == nil {
		t.Fatal("link write accepted")
	}
	if _, err := Read(link, 1024); err == nil {
		t.Fatal("link read accepted")
	}
	raw, _ := os.ReadFile(target)
	if string(raw) != "secret" {
		t.Fatal("destination changed")
	}
	if err := Write(dir, []byte("overwrite"), 0600, true); err == nil {
		t.Fatal("directory write accepted")
	}
}

func TestPrivateLogRejectsLinksAndRepairsMode(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "log")
	if err := os.WriteFile(path, []byte("previous"), 0644); err != nil {
		t.Fatal(err)
	}
	file, err := OpenAppend(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := file.WriteString("next"); err != nil {
		t.Fatal(err)
	}
	file.Close()
	info, _ := os.Stat(path)
	if info.Mode().Perm() != 0600 {
		t.Fatal("log remained public")
	}
	raw, _ := os.ReadFile(path)
	if string(raw) != "previousnext" {
		t.Fatal("log truncated")
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	if file, err := OpenAppend(link); err == nil {
		file.Close()
		t.Fatal("log symlink accepted")
	}
}

func TestDigestRejectsLinksAndHonorsBudget(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "binary")
	if err := os.WriteFile(path, []byte("payload"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := Digest(context.Background(), path, 3); err == nil {
		t.Fatal("byte budget ignored")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, _, err := Digest(ctx, path, 64); err == nil {
		t.Fatal("cancellation ignored")
	}
	if _, n, err := Digest(context.Background(), path, 64); err != nil || n != 7 {
		t.Fatal(n, err)
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	if _, _, err := Digest(context.Background(), link, 64); err == nil {
		t.Fatal("symlink followed")
	}
}
