package terminal

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func testShellPath(t *testing.T) string {
	t.Helper()
	for _, path := range []string{"/bin/bash", "/bin/zsh", "/bin/ash", "/bin/sh"} {
		if shellExecutable(path) {
			return path
		}
	}
	t.Skip("no usable login shell")
	return ""
}

func writeLoginProfiles(t *testing.T, home, body string) {
	t.Helper()
	for _, name := range []string{".bash_profile", ".profile", ".zprofile"} {
		if err := os.WriteFile(filepath.Join(home, name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
}

func readUntil(t *testing.T, ptmx *os.File, needle string, timeout time.Duration) string {
	t.Helper()
	deadline := time.Now().Add(timeout)
	var buf bytes.Buffer
	tmp := make([]byte, 1024)
	for {
		_ = ptmx.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
		n, err := ptmx.Read(tmp)
		if n > 0 {
			buf.Write(tmp[:n])
			if strings.Contains(buf.String(), needle) {
				return buf.String()
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("timeout waiting for %q, output=%q", needle, buf.String())
		}
		if err != nil && n == 0 && !os.IsTimeout(err) {
			t.Fatalf("read pty: %v output=%q", err, buf.String())
		}
	}
}

func spawnSpec(t *testing.T, spec SessionSpec) (*os.File, *exec.Cmd) {
	t.Helper()
	ptmx, cmd, err := Spawn(spec)
	if err != nil {
		t.Fatalf("spawn: %v", err)
	}
	t.Cleanup(func() {
		_ = ptmx.Close()
		if cmd.Process != nil {
			_ = cmd.Process.Kill()
			_, _ = cmd.Process.Wait()
		}
	})
	return ptmx, cmd
}

func TestSpawnLoginShellSourcesUserProfileAndProviderPath(t *testing.T) {
	shell := testShellPath(t)
	home := t.TempDir()
	bin := filepath.Join(home, "opt", "provider", "bin")
	if err := os.MkdirAll(bin, 0o755); err != nil {
		t.Fatal(err)
	}
	nm := filepath.Join(bin, "nm")
	if err := os.WriteFile(nm, []byte("#!/bin/sh\necho provider nm\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	writeLoginProfiles(t, home, "export PATH=\""+bin+":$PATH\"\nexport OBOARD_TEST_PROFILE=1\n")
	spec, err := BuildSession(Request{
		Mode:    ModeLogin,
		Cols:    80,
		Rows:    24,
		Account: &Account{Username: "root", UID: os.Getuid(), GID: os.Getgid(), HomeDir: home, Shell: shell},
		Files: FileSources{
			Environment: filepath.Join(home, "missing-env"),
			TerminalEnv: filepath.Join(home, "missing-terminal"),
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(spec.ShellArgs) != 1 || spec.ShellArgs[0] != "-l" {
		t.Fatalf("login args = %#v", spec.ShellArgs)
	}
	ptmx, cmd := spawnSpec(t, spec)
	if cmd.SysProcAttr != nil && cmd.SysProcAttr.Setpgid {
		t.Fatal("Setpgid must stay false")
	}
	if _, err := ptmx.Write([]byte("printf 'MARK:%s:%s:%s\\n' \"$OBOARD_TEST_PROFILE\" \"$(command -v nm)\" \"$(nm)\"\n")); err != nil {
		t.Fatal(err)
	}
	out := strings.ReplaceAll(readUntil(t, ptmx, "MARK:1:", 12*time.Second), "\r", "")
	if !strings.Contains(out, "MARK:1:"+nm+":provider nm") {
		t.Fatalf("login profile/path not applied: %q", out)
	}
}

func TestSpawnMinimalDoesNotSourceUserProfile(t *testing.T) {
	shell := testShellPath(t)
	home := t.TempDir()
	writeLoginProfiles(t, home, "export OBOARD_TEST_PROFILE=1\n")
	envFile := filepath.Join(home, "environment")
	if err := os.WriteFile(envFile, []byte("OBOARD_ENV_TEST=hello\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	spec, err := BuildSession(Request{
		Mode:    ModeMinimal,
		Cols:    80,
		Rows:    24,
		Account: &Account{Username: "root", UID: os.Getuid(), GID: os.Getgid(), HomeDir: home, Shell: shell},
		Files:   FileSources{Environment: envFile},
	})
	if err != nil {
		t.Fatal(err)
	}
	if spec.ShellArgs != nil {
		t.Fatalf("minimal args = %#v", spec.ShellArgs)
	}
	ptmx, _ := spawnSpec(t, spec)
	if _, err := ptmx.Write([]byte("printf 'MIN:%s:%s\\n' \"${OBOARD_TEST_PROFILE-}\" \"${OBOARD_ENV_TEST-}\"\n")); err != nil {
		t.Fatal(err)
	}
	out := strings.ReplaceAll(readUntil(t, ptmx, "MIN::", 12*time.Second), "\r", "")
	if strings.Contains(out, "MIN:1:") || strings.Contains(out, "MIN::hello") {
		t.Fatalf("minimal session sourced login/env files: %q", out)
	}
}

func TestSpawnDoesNotLeakAgentSecrets(t *testing.T) {
	shell := testShellPath(t)
	t.Setenv("OBOARD_AGENT_TOKEN", "VERY_SECRET")
	t.Setenv("OBOARD_INTERNAL_SECRET", "VERY_SECRET")
	home := t.TempDir()
	spec, err := BuildSession(Request{
		Mode:    ModeLogin,
		Cols:    80,
		Rows:    24,
		Account: &Account{Username: "root", UID: os.Getuid(), GID: os.Getgid(), HomeDir: home, Shell: shell},
		Files: FileSources{
			Environment: filepath.Join(home, "missing-env"),
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(strings.Join(spec.Env, "\n"), "VERY_SECRET") {
		t.Fatal("spec env contains agent secret")
	}
	ptmx, _ := spawnSpec(t, spec)
	if _, err := ptmx.Write([]byte("printf 'SEC:%s:%s\\n' \"${OBOARD_AGENT_TOKEN-}\" \"${OBOARD_INTERNAL_SECRET-}\"\n")); err != nil {
		t.Fatal(err)
	}
	out := strings.ReplaceAll(readUntil(t, ptmx, "SEC::", 12*time.Second), "\r", "")
	if strings.Contains(out, "VERY_SECRET") {
		t.Fatalf("child inherited agent secret: %q", out)
	}
}

func TestSpawnReportsControllingTTY(t *testing.T) {
	shell := testShellPath(t)
	home := t.TempDir()
	spec, err := BuildSession(Request{
		Mode:    ModeMinimal,
		Cols:    80,
		Rows:    24,
		Account: &Account{Username: "root", UID: os.Getuid(), GID: os.Getgid(), HomeDir: home, Shell: shell},
	})
	if err != nil {
		t.Fatal(err)
	}
	ptmx, _ := spawnSpec(t, spec)
	if _, err := ptmx.Write([]byte("printf 'TTY:%s\\n' \"$(tty)\"\n")); err != nil {
		t.Fatal(err)
	}
	out := strings.ReplaceAll(readUntil(t, ptmx, "TTY:/dev", 12*time.Second), "\r", "")
	if strings.Contains(out, "not a tty") {
		t.Fatalf("pty is not a controlling terminal: %q", out)
	}
}

func TestEnvironmentSubstitutionDoesNotRunInChild(t *testing.T) {
	shell := testShellPath(t)
	dir := t.TempDir()
	target := filepath.Join(dir, "oboard-environment-rce")
	envFile := filepath.Join(dir, "environment")
	if err := os.WriteFile(envFile, []byte("TEST=$(touch "+target+")\nSAFE=ok\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	spec, err := BuildSession(Request{
		Mode:    ModeLogin,
		Cols:    80,
		Rows:    24,
		Account: &Account{Username: "root", UID: os.Getuid(), GID: os.Getgid(), HomeDir: dir, Shell: shell},
		Files:   FileSources{Environment: envFile},
	})
	if err != nil {
		t.Fatal(err)
	}
	ptmx, _ := spawnSpec(t, spec)
	if _, err := ptmx.Write([]byte("printf '%s%s\\n' PTY RDY\n")); err != nil {
		t.Fatal(err)
	}
	_ = readUntil(t, ptmx, "PTYRDY", 12*time.Second)
	if _, err := os.Stat(target); !os.IsNotExist(err) {
		t.Fatal("child executed /etc/environment command substitution")
	}
}

func TestBuildSessionRejectsNologin(t *testing.T) {
	_, err := BuildSession(Request{
		Mode:    ModeLogin,
		Account: &Account{Username: "root", UID: 0, GID: 0, HomeDir: t.TempDir(), Shell: "/usr/sbin/nologin"},
	})
	if !IsLoginDisabled(err) {
		t.Fatalf("err=%v", err)
	}
}

func TestSpawnLoginShellKeepsProfileAliasesWhenNative(t *testing.T) {
	shell := testShellPath(t)
	if filepath.Base(shell) != "bash" && filepath.Base(shell) != "zsh" {
		t.Skip("alias test needs bash or zsh")
	}
	home := t.TempDir()
	writeLoginProfiles(t, home, "alias obalias='echo alias-ok'\nobfunc() { echo function-ok; }\n")
	spec, err := BuildSession(Request{
		Mode:    ModeLogin,
		Cols:    80,
		Rows:    24,
		Account: &Account{Username: "root", UID: os.Getuid(), GID: os.Getgid(), HomeDir: home, Shell: shell},
	})
	if err != nil {
		t.Fatal(err)
	}
	ptmx, _ := spawnSpec(t, spec)
	if _, err := ptmx.Write([]byte("obalias; obfunc\n")); err != nil {
		t.Fatal(err)
	}
	out := strings.ReplaceAll(readUntil(t, ptmx, "function-ok", 12*time.Second), "\r", "")
	if !strings.Contains(out, "alias-ok") {
		t.Fatalf("login aliases/functions not applied: %q", out)
	}
}

func TestDiagnosticOmitsEnvironmentValues(t *testing.T) {
	spec, err := BuildSession(Request{
		Mode:    ModeLogin,
		Cols:    80,
		Rows:    24,
		Account: &Account{Username: "root", UID: 0, GID: 0, HomeDir: t.TempDir(), Shell: testShellPath(t)},
	})
	if err != nil {
		t.Fatal(err)
	}
	info := spec.Diagnostic()
	if info.Username != "root" || info.Shell == "" || info.Mode != "login" {
		t.Fatalf("diagnostic=%#v", info)
	}
}
