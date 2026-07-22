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
		if bash, err := exec.LookPath("bash"); err == nil {
			cmd := exec.Command(bash, "-n", path)
			if output, err := cmd.CombinedOutput(); err != nil {
				t.Fatalf("%s syntax error: %v\n%s", name, err, output)
			}
		}
		text := string(content)
		if !strings.Contains(text, "OBOARD_CONTROLLER_URL") || !strings.Contains(text, "OBOARD_ACTION") {
			t.Fatalf("%s does not preserve the controller-based install contract", name)
		}
	}

	install, err := os.ReadFile(filepath.Join(dir, "install.sh"))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"Controller 和 Agent 相互独立，可以安装在同一台服务器上",
		"不会覆盖 oboard-controller",
		"/install/agent.sh",
		"OBOARD_ENROLL_TOKEN",
	} {
		if !strings.Contains(string(install), want) {
			t.Fatalf("installer missing %q", want)
		}
	}
}
