package agent

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestManagementConsoleMenuExit(t *testing.T) {
	var out bytes.Buffer
	code := RunManagementConsole("/missing/config.json", nil, strings.NewReader("0\n"), &out, &out)
	if code != 0 {
		t.Fatalf("exit code = %d", code)
	}
	text := out.String()
	if !strings.Contains(text, "OBoard Agent 管理") || !strings.Contains(text, "检查与主控的连接") {
		t.Fatalf("unexpected menu output: %s", text)
	}
}

func TestManagementConsoleCommandHelpAndUnknown(t *testing.T) {
	var out bytes.Buffer
	code := RunManagementConsole("/missing/config.json", []string{"help"}, nil, &out, &out)
	if code != 0 {
		t.Fatalf("help exit code = %d", code)
	}
	if !strings.Contains(out.String(), "obag status") {
		t.Fatalf("help output does not list obag commands: %s", out.String())
	}
	out.Reset()
	code = RunManagementConsole("/missing/config.json", []string{"bogus-command"}, nil, &out, &out)
	if code != 2 {
		t.Fatalf("unknown command exit code = %d", code)
	}
}

func TestManagementControllerCheck(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/healthz" {
			http.NotFound(w, r)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	result := checkManagementController(Config{ControllerURL: server.URL})
	if !result.OK {
		t.Fatalf("check failed: %#v", result)
	}
	if len(result.Items) != 4 || !result.Items[3].OK {
		t.Fatalf("unexpected check items: %#v", result.Items)
	}
}

func TestDisplayControllerURLRemovesSensitiveParts(t *testing.T) {
	got := displayControllerURL("https://user:pass@example.com:8443/path?token=secret")
	if got != "https://example.com:8443/path" {
		t.Fatalf("display URL = %q", got)
	}
}

func TestManagementControllerCheckKeepsBasePath(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Controller answers 404 for every path outside its base path.
		if r.URL.Path != "/qzq/healthz" {
			http.NotFound(w, r)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	result := checkManagementController(Config{ControllerURL: server.URL + "/qzq"})
	if !result.OK {
		t.Fatalf("base path health check failed: %#v", result.Items)
	}
}
