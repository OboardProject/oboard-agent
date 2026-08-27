package terminal

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func envLookup(env []string, key string) (string, bool) {
	prefix := key + "="
	for _, item := range env {
		if strings.HasPrefix(item, prefix) {
			return strings.TrimPrefix(item, prefix), true
		}
	}
	return "", false
}

func TestBuildTerminalEnvironmentDoesNotInheritProcess(t *testing.T) {
	t.Setenv("OBOARD_AGENT_TOKEN", "VERY_SECRET")
	t.Setenv("OBOARD_INTERNAL_SECRET", "VERY_SECRET")
	t.Setenv("AGENT_TOKEN", "VERY_SECRET")
	home := t.TempDir()
	env, _, _ := BuildTerminalEnvironment(EnvironmentInput{
		Mode: ModeLogin,
		Account: Account{
			Username: "root",
			UID:      0,
			GID:      0,
			HomeDir:  home,
		},
		Shell: "/bin/bash",
		Files: FileSources{
			Environment: filepath.Join(home, "missing-environment"),
			TerminalEnv: filepath.Join(home, "missing-terminal.env"),
		},
	})
	joined := strings.Join(env, "\n")
	if strings.Contains(joined, "VERY_SECRET") {
		t.Fatalf("process secret leaked into spec env: %s", joined)
	}
	if _, ok := envLookup(env, "OBOARD_AGENT_TOKEN"); ok {
		t.Fatal("OBOARD_AGENT_TOKEN must not be copied from the Agent process")
	}
	if homeVal, _ := envLookup(env, "HOME"); homeVal != home {
		t.Fatalf("HOME=%q", homeVal)
	}
	if user, _ := envLookup(env, "USER"); user != "root" {
		t.Fatalf("USER=%q", user)
	}
	if path, _ := envLookup(env, "PATH"); path != DefaultPATH {
		t.Fatalf("PATH=%q", path)
	}
	if _, ok := envLookup(env, "SSH_CONNECTION"); ok {
		t.Fatal("SSH_CONNECTION must not be set")
	}
}

func TestEnvironmentFileLoadedOnlyInLogin(t *testing.T) {
	dir := t.TempDir()
	envFile := filepath.Join(dir, "environment")
	if err := os.WriteFile(envFile, []byte("OBOARD_ENV_TEST=hello\nPATH=/opt/provider/bin:/usr/bin\nHOME=/tmp\nUSER=nobody\nSSH_CONNECTION=1.2.3.4 22\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	account := Account{Username: "root", UID: 0, GID: 0, HomeDir: dir}
	login, sysLoaded, _ := BuildTerminalEnvironment(EnvironmentInput{
		Mode: ModeLogin, Account: account, Shell: "/bin/bash",
		Files: FileSources{Environment: envFile},
	})
	if !sysLoaded {
		t.Fatal("expected system environment loaded")
	}
	if value, _ := envLookup(login, "OBOARD_ENV_TEST"); value != "hello" {
		t.Fatalf("login OBOARD_ENV_TEST=%q", value)
	}
	if value, _ := envLookup(login, "PATH"); value != "/opt/provider/bin:/usr/bin" {
		t.Fatalf("login PATH=%q", value)
	}
	if value, _ := envLookup(login, "HOME"); value != dir {
		t.Fatalf("identity HOME overwritten: %q", value)
	}
	if value, _ := envLookup(login, "USER"); value != "root" {
		t.Fatalf("identity USER overwritten: %q", value)
	}
	if _, ok := envLookup(login, "SSH_CONNECTION"); ok {
		t.Fatal("SSH_CONNECTION leaked from environment file")
	}

	minimal, sysLoaded, termLoaded := BuildTerminalEnvironment(EnvironmentInput{
		Mode: ModeMinimal, Account: account, Shell: "/bin/bash",
		Files: FileSources{Environment: envFile, TerminalEnv: envFile},
	})
	if sysLoaded || termLoaded {
		t.Fatal("minimal mode must not load environment files")
	}
	if _, ok := envLookup(minimal, "OBOARD_ENV_TEST"); ok {
		t.Fatal("minimal mode loaded OBOARD_ENV_TEST")
	}
}

func TestEnvironmentFileSkipsCommandSubstitution(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "oboard-environment-rce")
	envFile := filepath.Join(dir, "environment")
	content := "SAFE=ok\nTEST=$(touch " + target + ")\nALSO=`touch " + target + "`\n"
	if err := os.WriteFile(envFile, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	values, loaded := LoadEnvironmentFile(envFile)
	if !loaded {
		t.Fatal("expected file to load")
	}
	if values["SAFE"] != "ok" {
		t.Fatalf("values=%#v", values)
	}
	if _, ok := values["TEST"]; ok {
		t.Fatalf("command substitution line was accepted: %#v", values)
	}
	if _, err := os.Stat(target); !os.IsNotExist(err) {
		t.Fatal("environment parser executed command substitution")
	}
}

func TestEnvironmentFileSkipsMalformedLines(t *testing.T) {
	dir := t.TempDir()
	envFile := filepath.Join(dir, "environment")
	if err := os.WriteFile(envFile, []byte("# comment\nexport FOO=bar\nnot-a-key\nBAD KEY=1\nOK=value\nLANG=\"en_US.UTF-8\"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	values, loaded := LoadEnvironmentFile(envFile)
	if !loaded {
		t.Fatal("expected file to load")
	}
	if values["OK"] != "value" || values["LANG"] != "en_US.UTF-8" {
		t.Fatalf("values=%#v", values)
	}
	if _, ok := values["FOO"]; ok {
		t.Fatal("export command was accepted")
	}
}

func TestLocaleFilesOnlyApplyLocaleKeys(t *testing.T) {
	dir := t.TempDir()
	locale := filepath.Join(dir, "locale")
	if err := os.WriteFile(locale, []byte("LANG=C.UTF-8\nPATH=/tmp\nLC_TIME=C\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	values := loadLocaleFiles(FileSources{LocaleDebian: locale})
	if values["LANG"] != "C.UTF-8" || values["LC_TIME"] != "C" {
		t.Fatalf("locale=%#v", values)
	}
	if _, ok := values["PATH"]; ok {
		t.Fatal("locale file must not set PATH")
	}
}

func TestSanitizeTERM(t *testing.T) {
	if got := SanitizeTERM("xterm-256color"); got != "xterm-256color" {
		t.Fatalf("got %q", got)
	}
	if got := SanitizeTERM("rm -rf /"); got != DefaultTERM {
		t.Fatalf("unsafe TERM accepted: %q", got)
	}
	if got := SanitizeCOLORTERM("truecolor"); got != "truecolor" {
		t.Fatalf("got %q", got)
	}
	if got := SanitizeCOLORTERM("$(id)"); got != DefaultCOLORTERM {
		t.Fatalf("unsafe COLORTERM accepted: %q", got)
	}
}
