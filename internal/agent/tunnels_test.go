package agent

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/OboardProject/oboard-agent/internal/model"
)

func TestApplySSHTunnelRejectsImmediateProcessFailure(t *testing.T) {
	binDir := t.TempDir()
	sshPath := filepath.Join(binDir, "ssh")
	if err := os.WriteFile(sshPath, []byte("#!/bin/sh\nexit 23\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", binDir+string(os.PathListSeparator)+os.Getenv("PATH"))
	runner := &Runner{}
	runner.storeConfig(Config{StateDir: t.TempDir()})
	dir := filepath.Join(runner.stateDir(), tunnelsDir)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	err := runner.applySSHTunnel(dir, model.Tunnel{ID: 1, Name: "broken", Type: model.TunnelTypeSSH, TargetEndpoint: "203.0.113.10", TargetPort: 22, ConfigJSON: `{"user":"root","key_path":"/tmp/test-key","local_forward":"127.0.0.1:30001:127.0.0.1:31001"}`})
	if err == nil || !strings.Contains(err.Error(), "before forwarding became ready") {
		t.Fatalf("error = %v, want immediate SSH failure", err)
	}
	if _, statErr := os.Stat(filepath.Join(dir, "ssh-1.pid")); !os.IsNotExist(statErr) {
		t.Fatalf("failed tunnel must not leave pid file: %v", statErr)
	}
}

func TestApplySSHTunnelKeepsLongRunningForward(t *testing.T) {
	binDir := t.TempDir()
	sshPath := filepath.Join(binDir, "ssh")
	if err := os.WriteFile(sshPath, []byte("#!/bin/sh\ntrap 'exit 0' TERM\nwhile :; do sleep 1; done\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", binDir+string(os.PathListSeparator)+os.Getenv("PATH"))
	runner := &Runner{}
	runner.storeConfig(Config{StateDir: t.TempDir()})
	dir := filepath.Join(runner.stateDir(), tunnelsDir)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := runner.applySSHTunnel(dir, model.Tunnel{ID: 2, Name: "ready", Type: model.TunnelTypeSSH, TargetEndpoint: "203.0.113.10", TargetPort: 22, ConfigJSON: `{"user":"root","key_path":"/tmp/test-key","local_forward":"127.0.0.1:30002:127.0.0.1:31002"}`}); err != nil {
		t.Fatal(err)
	}
	pidPath := filepath.Join(dir, "ssh-2.pid")
	if _, err := os.Stat(pidPath); err != nil {
		t.Fatalf("ready tunnel pid file: %v", err)
	}
	if err := stopManagedProcess(pidPath); err != nil {
		t.Fatal(err)
	}
}

func TestTunnelPackageInstallCommands(t *testing.T) {
	tests := []struct {
		manager string
		kind    string
		binary  string
		pkg     string
	}{
		{"apk", "wireguard", "apk", "wireguard-tools"},
		{"apt", "ssh_client", "apt-get", "openssh-client"},
		{"dnf", "ssh_server", "dnf", "openssh-server"},
		{"yum", "wireguard", "yum", "wireguard-tools"},
		{"pacman", "ssh_client", "pacman", "openssh"},
		{"zypper", "ssh_server", "zypper", "openssh"},
	}
	for _, tt := range tests {
		name, args, _, err := tunnelPackageInstallCommand(tt.manager, tt.kind)
		if err != nil {
			t.Fatalf("%s/%s: %v", tt.manager, tt.kind, err)
		}
		if name != tt.binary || !strings.Contains(strings.Join(args, " "), tt.pkg) {
			t.Fatalf("%s/%s command = %s %v", tt.manager, tt.kind, name, args)
		}
	}
	if _, _, _, err := tunnelPackageInstallCommand("unknown", "wireguard"); err == nil {
		t.Fatal("unknown package manager must fail")
	}
}

func TestStopManagedProcessRefusesMismatchedPIDRecord(t *testing.T) {
	pidPath := filepath.Join(t.TempDir(), "ssh-9.pid")
	record := `{"pid":` + fmt.Sprint(os.Getpid()) + `,"command":"ssh","start_token":"wrong"}`
	if err := os.WriteFile(pidPath, []byte(record), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := stopManagedProcess(pidPath); err == nil || !strings.Contains(err.Error(), "refusing to stop") {
		t.Fatalf("mismatched PID record error = %v", err)
	}
}

func TestRestoreManagedTunnelsOnStartupRestartsSSH(t *testing.T) {
	binDir := t.TempDir()
	sshPath := filepath.Join(binDir, "ssh")
	if err := os.WriteFile(sshPath, []byte("#!/bin/sh\ntrap 'exit 0' TERM\nwhile :; do sleep 1; done\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", binDir+string(os.PathListSeparator)+os.Getenv("PATH"))
	stateDir := t.TempDir()
	runner := &Runner{}
	runner.storeConfig(Config{StateDir: stateDir})
	plan := model.TunnelPlan{Version: 7, Tunnels: []model.Tunnel{{ID: 7, Name: "restore", Type: model.TunnelTypeSSH, TargetEndpoint: "203.0.113.7", TargetPort: 22, ConfigJSON: `{"user":"restore","key_path":"/tmp/test-key","local_forward":"127.0.0.1:23007:127.0.0.1:33007"}`, Enabled: true}}}
	b, err := json.Marshal(plan)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(stateDir, tunnelsCurrent), b, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := runner.restoreManagedTunnelsOnStartup(); err != nil {
		t.Fatal(err)
	}
	pidPath := filepath.Join(stateDir, tunnelsDir, "ssh-7.pid")
	if _, err := os.Stat(pidPath); err != nil {
		t.Fatalf("restored SSH PID file: %v", err)
	}
	if err := stopManagedProcess(pidPath); err != nil {
		t.Fatal(err)
	}
}

func TestWaitForWireGuardHandshakeRequiresNonzeroTimestamp(t *testing.T) {
	binDir := t.TempDir()
	wgPath := filepath.Join(binDir, "wg")
	if err := os.WriteFile(wgPath, []byte("#!/bin/sh\nprintf 'peer-key\\t1784224082\\n'\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", binDir+string(os.PathListSeparator)+os.Getenv("PATH"))
	if err := waitForWireGuardHandshake("obw1", "172.16.1.2/32", time.Second); err != nil {
		t.Fatal(err)
	}
	if err := waitForWireGuardHandshake("obw1", "not-an-ip", time.Second); err == nil {
		t.Fatal("invalid peer address must fail")
	}
}

func TestSetManagedSSHPasswordHashUsesNonLockedInvalidHash(t *testing.T) {
	binDir := t.TempDir()
	capture := filepath.Join(t.TempDir(), "input")
	chpasswd := filepath.Join(binDir, "chpasswd")
	if err := os.WriteFile(chpasswd, []byte("#!/bin/sh\ncat > \"$CAPTURE\"\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("CAPTURE", capture)
	t.Setenv("PATH", binDir+string(os.PathListSeparator)+os.Getenv("PATH"))
	if err := setManagedSSHPasswordHash(); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(capture)
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != managedSSHUser+":x\n" {
		t.Fatalf("chpasswd input = %q", b)
	}
}

func TestLocalSSHServerListening(t *testing.T) {
	sshListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer sshListener.Close()
	go func() {
		conn, acceptErr := sshListener.Accept()
		if acceptErr == nil {
			_, _ = conn.Write([]byte("SSH-2.0-OpenSSH_test\r\n"))
			_ = conn.Close()
		}
	}()
	sshPort := sshListener.Addr().(*net.TCPAddr).Port
	listening, err := localSSHServerListening(sshPort)
	if err != nil || !listening {
		t.Fatalf("SSH banner probe listening=%v error=%v", listening, err)
	}

	nonSSHListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer nonSSHListener.Close()
	go func() {
		conn, acceptErr := nonSSHListener.Accept()
		if acceptErr == nil {
			_, _ = conn.Write([]byte("HTTP/1.1 200 OK\r\n\r\n"))
			_ = conn.Close()
		}
	}()
	nonSSHPort := nonSSHListener.Addr().(*net.TCPAddr).Port
	if listening, err = localSSHServerListening(nonSSHPort); err == nil || listening || !strings.Contains(err.Error(), "非 SSH 服务") {
		t.Fatalf("non-SSH probe listening=%v error=%v", listening, err)
	}

	available, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	availablePort := available.Addr().(*net.TCPAddr).Port
	_ = available.Close()
	if listening, err = localSSHServerListening(availablePort); err != nil || listening {
		t.Fatalf("unused port probe listening=%v error=%v", listening, err)
	}
}
