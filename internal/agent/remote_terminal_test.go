package agent

import (
	"errors"
	"os"
	"os/exec"
	"runtime"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/creack/pty"

	"github.com/OboardProject/oboard-agent/internal/model"
	"github.com/OboardProject/oboard-agent/internal/security"
)

func TestStartInteractivePTYDoesNotSetPgid(t *testing.T) {
	ptmx, cmd, err := startInteractivePTY(80, 24)
	if err != nil {
		t.Fatalf("start interactive pty: %v", err)
	}
	defer func() {
		_ = ptmx.Close()
		killProcessGroup(cmd)
	}()
	if cmd.SysProcAttr != nil && cmd.SysProcAttr.Setpgid {
		t.Fatal("Setpgid must stay false; pty.StartWithSize already sets Setsid and Setctty")
	}
	if cmd.Process == nil || cmd.Process.Pid <= 0 {
		t.Fatal("pty process was not started")
	}
	if _, err := ptmx.Write([]byte("printf ready\\n\n")); err != nil {
		t.Fatalf("write pty: %v", err)
	}
	_ = ptmx.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 256)
	n, err := ptmx.Read(buf)
	if err != nil && n == 0 {
		t.Fatalf("read pty: %v", err)
	}
}

func TestStartInteractivePTYConflictsWithSetpgidOnLinux(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("setpgid after setsid returns EPERM on Linux agents")
	}
	cmd := exec.Command("/bin/sh")
	cmd.Dir = "/"
	cmd.Env = append(remoteExecEnv(), "TERM=xterm-256color")
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	ptmx, err := pty.StartWithSize(cmd, &pty.Winsize{Cols: 80, Rows: 24})
	if ptmx != nil {
		_ = ptmx.Close()
		killProcessGroup(cmd)
	}
	if err == nil {
		t.Fatal("Setpgid + pty.StartWithSize unexpectedly succeeded")
	}
	if !errors.Is(err, syscall.EPERM) && !os.IsPermission(err) {
		t.Fatalf("conflict error = %v, want EPERM", err)
	}
}

func TestInteractivePrepareReportsControlFailure(t *testing.T) {
	dir := t.TempDir()
	runner := New(Config{StateDir: dir, CommandTimeoutSeconds: 20, ResourceProfile: "small", TimeCorrectionMode: "off", LogMaxMB: 8, CoreLogMaxMB: 8, AgentToken: "agent-token"})
	var mu sync.Mutex
	var messages []map[string]any
	runner.setControlSend(func(payload any, _ bool) error {
		mu.Lock()
		defer mu.Unlock()
		messages = append(messages, payload.(map[string]any))
		return nil
	})
	err := runner.handleInteractivePrepare(model.InteractivePrepareEnvelope{
		Type: "interactive_prepare", SignatureVersion: 1, SessionID: "sess-denied", Kind: "terminal",
	})
	if err == nil {
		t.Fatal("expected prepare rejection")
	}
	mu.Lock()
	defer mu.Unlock()
	if len(messages) != 1 {
		t.Fatalf("control messages = %#v", messages)
	}
	if messages[0]["type"] != "interactive_failed" || messages[0]["session_id"] != "sess-denied" || messages[0]["reason"] != interactiveReasonPrepareInvalid {
		t.Fatalf("failed payload = %#v", messages[0])
	}
}

func TestInteractiveSessionReportsURLFailure(t *testing.T) {
	dir := t.TempDir()
	runner := New(Config{
		StateDir: dir, CommandTimeoutSeconds: 20, ResourceProfile: "small", TimeCorrectionMode: "off",
		LogMaxMB: 8, CoreLogMaxMB: 8, AgentToken: "agent-token", ControllerURL: "not-a-controller",
	})
	var mu sync.Mutex
	got := make(chan map[string]any, 1)
	runner.setControlSend(func(payload any, _ bool) error {
		mu.Lock()
		defer mu.Unlock()
		select {
		case got <- payload.(map[string]any):
		default:
		}
		return nil
	})
	now := time.Now().UTC()
	env := model.InteractivePrepareEnvelope{
		Type: "interactive_prepare", SignatureVersion: 1, ServerID: 0, SessionID: "sess-url",
		Nonce: "nonce-url", IssuedAt: now.Format(time.RFC3339Nano), ExpiresAt: now.Add(time.Minute).Format(time.RFC3339Nano),
		Kind: "terminal", Cols: 80, Rows: 24,
	}
	env.Signature = security.SignInteractiveEnvelope(security.HashSecret("agent-token"), security.InteractiveEnvelope{
		Type: env.Type, ServerID: env.ServerID, SessionID: env.SessionID, Nonce: env.Nonce,
		IssuedAt: env.IssuedAt, ExpiresAt: env.ExpiresAt, Kind: env.Kind, Cols: env.Cols, Rows: env.Rows,
	})
	if err := runner.handleInteractivePrepare(env); err != nil {
		t.Fatal(err)
	}
	select {
	case payload := <-got:
		if payload["type"] != "interactive_failed" || payload["reason"] != interactiveReasonURLFailed {
			t.Fatalf("url failure payload = %#v", payload)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for interactive_failed")
	}
}

func TestInteractiveSessionLimitReportsFailure(t *testing.T) {
	dir := t.TempDir()
	runner := New(Config{StateDir: dir, CommandTimeoutSeconds: 20, ResourceProfile: "small", TimeCorrectionMode: "off", LogMaxMB: 8, CoreLogMaxMB: 8})
	runner.terminalSessions = map[string]*terminalSession{
		"one": {id: "one"},
		"two": {id: "two"},
	}
	got := make(chan map[string]any, 1)
	runner.setControlSend(func(payload any, _ bool) error {
		select {
		case got <- payload.(map[string]any):
		default:
		}
		return nil
	})
	now := time.Now().UTC()
	runner.runTerminalSession(model.InteractivePrepareEnvelope{
		SessionID: "sess-limit", IssuedAt: now.Format(time.RFC3339Nano), ExpiresAt: now.Add(time.Minute).Format(time.RFC3339Nano),
	}, 80, 24, "secret")
	select {
	case payload := <-got:
		if payload["type"] != "interactive_failed" || payload["reason"] != interactiveReasonSessionLimit {
			t.Fatalf("limit payload = %#v", payload)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for session_limit failure")
	}
}
