package scripts_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestUserFacingInstallScripts(t *testing.T) {
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("unable to locate test file")
	}
	dir := filepath.Dir(file)
	for _, name := range []string{"install.sh", "update.sh"} {
		path := filepath.Join(dir, name)
		content, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		for _, shellName := range []string{"bash", "dash"} {
			if shell, err := exec.LookPath(shellName); err == nil {
				cmd := exec.Command(shell, "-n", path)
				if output, err := cmd.CombinedOutput(); err != nil {
					t.Fatalf("%s %s syntax error: %v\n%s", name, shellName, err, output)
				}
			}
		}
		text := string(content)
		if !strings.HasPrefix(text, "#!/bin/sh\n") {
			t.Fatalf("%s does not use the portable system shell", name)
		}
		if !strings.Contains(text, "OBOARD_CONTROLLER_URL") || !strings.Contains(text, "OBOARD_ACTION") {
			t.Fatalf("%s does not preserve the controller-based install contract", name)
		}
	}

	install, err := os.ReadFile(filepath.Join(dir, "install.sh"))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"/install/agent.sh",
		"OBOARD_ENROLL_TOKEN",
		"无法从主控下载安装程序",
		`sh "$SCRIPT_TMP"`,
	} {
		if !strings.Contains(string(install), want) {
			t.Fatalf("installer missing %q", want)
		}
	}
	if strings.Contains(string(install), "OBoard Agent 安装程序") {
		t.Fatal("bootstrap installer duplicates the controller-provided install UI")
	}
}

func TestDevelopmentReleasePreservesExactBuildBeforeMutableChannel(t *testing.T) {
	_, file, _, _ := runtime.Caller(0)
	workflow, err := os.ReadFile(filepath.Join(filepath.Dir(file), "..", ".github", "workflows", "dev-release.yml"))
	if err != nil {
		t.Fatal(err)
	}
	start := strings.Index(string(workflow), "          assets=()")
	if start < 0 {
		t.Fatal("release publication script missing")
	}
	lines := strings.Split(string(workflow)[start:], "\n")
	for i := range lines {
		lines[i] = strings.TrimPrefix(lines[i], "          ")
	}
	script := "set -eu\n" + strings.Join(lines, "\n")
	for _, build := range []string{"20260909010101", "20260909020202"} {
		root := t.TempDir()
		releaseDir := filepath.Join(root, "dist", "release")
		bin := filepath.Join(root, "bin")
		if err := os.MkdirAll(releaseDir, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.MkdirAll(bin, 0o700); err != nil {
			t.Fatal(err)
		}
		manifest := `{"version":"dev-012345abcdef","build":"` + build + `","files":[{"name":"oboard-agent-linux-amd64"}]}`
		for name, body := range map[string]string{"release-manifest.json": manifest, "release-manifest.json.sig": "signature", "sha256sums.txt": "hash", "oboard-agent-linux-amd64": "binary"} {
			if err := os.WriteFile(filepath.Join(releaseDir, name), []byte(body), 0o600); err != nil {
				t.Fatal(err)
			}
		}
		fakeGH := "#!/bin/sh\nprintf '%s\\n' \"$*\" >> \"$RELEASE_LOG\"\n[ \"$2\" != view ]\n"
		if err := os.WriteFile(filepath.Join(bin, "gh"), []byte(fakeGH), 0o700); err != nil {
			t.Fatal(err)
		}
		logPath := filepath.Join(root, "release.log")
		cmd := exec.Command("bash", "-c", script)
		cmd.Dir = root
		cmd.Env = append(os.Environ(), "PATH="+bin+":"+os.Getenv("PATH"), "GITHUB_SHA=012345abcdef012345abcdef012345abcdef01234567", "RELEASE_LOG="+logPath)
		if output, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("publish fixture: %v\n%s", err, output)
		}
		log, err := os.ReadFile(logPath)
		if err != nil {
			t.Fatal(err)
		}
		calls := strings.Split(strings.TrimSpace(string(log)), "\n")
		if len(calls) != 3 || !strings.HasPrefix(calls[0], "release create dev-012345abcdef-"+build+" ") || strings.Contains(calls[0], "--clobber") || !strings.Contains(calls[0], "release-manifest.json.sig") || !strings.HasPrefix(calls[2], "release create dev ") {
			t.Fatalf("incorrect release publication order: %s", log)
		}
	}
}
