package terminal

import (
	"os"
	"path/filepath"
	"testing"
)

func TestParsePasswdLine(t *testing.T) {
	account, ok := parsePasswdLine("root:x:0:0:root:/root:/bin/bash")
	if !ok {
		t.Fatal("expected passwd line to parse")
	}
	if account.Username != "root" || account.UID != 0 || account.GID != 0 || account.HomeDir != "/root" || account.Shell != "/bin/bash" {
		t.Fatalf("account = %#v", account)
	}
}

func TestParsePasswdFileAlpineAsh(t *testing.T) {
	path := filepath.Join(t.TempDir(), "passwd")
	if err := os.WriteFile(path, []byte("root:x:0:0:root:/root:/bin/ash\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	accounts, err := parsePasswdFile(path)
	if err != nil || len(accounts) != 1 || accounts[0].Shell != "/bin/ash" {
		t.Fatalf("accounts=%#v err=%v", accounts, err)
	}
}

func TestResolveLoginShellNologin(t *testing.T) {
	for _, shell := range []string{"/usr/sbin/nologin", "/sbin/nologin", "/bin/false", "/usr/bin/false"} {
		_, err := ResolveLoginShell(shell)
		if !IsLoginDisabled(err) {
			t.Fatalf("shell %s: err=%v", shell, err)
		}
		if err.Error() != "terminal login disabled for this account" {
			t.Fatalf("shell %s: message=%q", shell, err.Error())
		}
	}
}

func TestResolveLoginShellMissing(t *testing.T) {
	_, err := ResolveLoginShell("/no/such/oboard-shell")
	if !IsShellMissing(err) {
		t.Fatalf("err=%v", err)
	}
	if err.Error() != "configured login shell does not exist: /no/such/oboard-shell" {
		t.Fatalf("message=%q", err.Error())
	}
}

func TestResolveLoginShellEmptyFallsBackToSh(t *testing.T) {
	shell, err := ResolveLoginShell("")
	if err != nil {
		t.Fatal(err)
	}
	if shell != "/bin/sh" && !shellExecutable(shell) {
		t.Fatalf("fallback shell=%q", shell)
	}
}

func TestLoginShellArgs(t *testing.T) {
	if got := LoginShellArgs("/bin/bash", ModeLogin); len(got) != 1 || got[0] != "-l" {
		t.Fatalf("bash login args = %#v", got)
	}
	if got := LoginShellArgs("/bin/ash", ModeLogin); len(got) != 1 || got[0] != "-l" {
		t.Fatalf("ash login args = %#v", got)
	}
	if got := LoginShellArgs("/usr/bin/fish", ModeLogin); len(got) != 1 || got[0] != "-l" {
		t.Fatalf("fish login args = %#v", got)
	}
	if got := LoginShellArgs("/bin/bash", ModeMinimal); got != nil {
		t.Fatalf("minimal args = %#v", got)
	}
}

func TestWorkingDirectoryFallback(t *testing.T) {
	if got := ResolveWorkingDirectory(filepath.Join(t.TempDir(), "missing-home")); got != "/" {
		t.Fatalf("fallback = %q", got)
	}
	home := t.TempDir()
	if got := ResolveWorkingDirectory(home); got != home {
		t.Fatalf("home = %q got %q", home, got)
	}
}

func TestParseMode(t *testing.T) {
	mode, err := ParseMode("")
	if err != nil || mode != ModeLogin {
		t.Fatalf("empty mode = %q err=%v", mode, err)
	}
	mode, err = ParseMode("minimal")
	if err != nil || mode != ModeMinimal {
		t.Fatalf("minimal = %q err=%v", mode, err)
	}
	if _, err := ParseMode("ssh"); err == nil {
		t.Fatal("expected invalid mode")
	}
}
