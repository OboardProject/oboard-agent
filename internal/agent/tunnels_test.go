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

func TestManagedSSHServerPortRequiresExclusiveOwnership(t *testing.T) {
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
	if err := managedSSHServerPortAvailable(sshPort); err == nil || !strings.Contains(err.Error(), "已被其他进程占用") {
		t.Fatalf("SSH listener must not be reused: %v", err)
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
	if err := managedSSHServerPortAvailable(nonSSHPort); err == nil || !strings.Contains(err.Error(), "已被其他进程占用") {
		t.Fatalf("non-SSH listener must be rejected: %v", err)
	}

	available, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	availablePort := available.Addr().(*net.TCPAddr).Port
	_ = available.Close()
	if err := managedSSHServerPortAvailable(availablePort); err != nil {
		t.Fatalf("unused port probe error=%v", err)
	}
}

func TestManagedSSHServerPortValidationIgnoresClientTunnels(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	port := listener.Addr().(*net.TCPAddr).Port
	tunnels := []model.Tunnel{{
		Type:       model.TunnelTypeSSH,
		ConfigJSON: fmt.Sprintf(`{"managed_pair":false,"role":"client","server_port":%d}`, port),
	}}
	if err := validateManagedSSHServerPortsAvailable(tunnels); err != nil {
		t.Fatalf("manual SSH client tunnel was treated as a managed server: %v", err)
	}
}

// installFakeSSHDBinary places a fake sshd on PATH so the managed symlink
// resolution can be exercised without a real OpenSSH installation.
func installFakeSSHDBinary(t *testing.T, script string) string {
	t.Helper()
	binDir := t.TempDir()
	sshdPath := filepath.Join(binDir, "sshd")
	if err := os.WriteFile(sshdPath, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", binDir+string(os.PathListSeparator)+os.Getenv("PATH"))
	return binDir
}

func TestManagedSSHExecPathRunsThroughOboardSSHSymlink(t *testing.T) {
	binDir := installFakeSSHDBinary(t, "#!/bin/sh\nexit 0\n")
	sshdPath := filepath.Join(binDir, "sshd")
	dir := t.TempDir()
	linkPath, err := managedSSHExecPath(dir)
	if err != nil {
		t.Fatal(err)
	}
	if filepath.Base(linkPath) != managedSSHProcessName {
		t.Fatalf("exec path base = %q, want %q", filepath.Base(linkPath), managedSSHProcessName)
	}
	if resolved, err := os.Readlink(linkPath); err != nil || resolved != sshdPath {
		t.Fatalf("symlink = %q (%v), want %q", resolved, err, sshdPath)
	}
	// A second call with the same host binary is idempotent.
	if again, err := managedSSHExecPath(dir); err != nil || again != linkPath {
		t.Fatalf("idempotent exec path = %q (%v)", again, err)
	}
}

func TestManagedSSHExecPathFollowsHostSSHDMove(t *testing.T) {
	firstDir := t.TempDir()
	firstPath := filepath.Join(firstDir, "sshd")
	if err := os.WriteFile(firstPath, []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", firstDir+string(os.PathListSeparator)+t.TempDir())
	dir := t.TempDir()
	if _, err := managedSSHExecPath(dir); err != nil {
		t.Fatal(err)
	}
	secondDir := t.TempDir()
	secondPath := filepath.Join(secondDir, "sshd")
	if err := os.Rename(firstPath, secondPath); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", secondDir+string(os.PathListSeparator)+t.TempDir())
	linkPath, err := managedSSHExecPath(dir)
	if err != nil {
		t.Fatal(err)
	}
	if resolved, err := os.Readlink(linkPath); err != nil || resolved != secondPath {
		t.Fatalf("symlink = %q (%v), want %q", resolved, err, secondPath)
	}
}

func TestManagedSSHExecPathRefusesUnexpectedRegularFile(t *testing.T) {
	installFakeSSHDBinary(t, "#!/bin/sh\nexit 0\n")
	dir := t.TempDir()
	linkPath := filepath.Join(dir, managedSSHProcessName)
	if err := os.WriteFile(linkPath, []byte("#!/bin/sh\nexit 42\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	got, err := managedSSHExecPath(dir)
	if err != nil {
		t.Fatalf("regular file must be replaced by the symlink: %v", err)
	}
	if _, err := os.Readlink(got); err != nil {
		t.Fatalf("exec path is not a symlink: %v", err)
	}
}

func TestManagedSSHExecPathRequiresHostBinary(t *testing.T) {
	if sshServerBinary() != "" {
		t.Skip("host provides a fixed-path sshd that cannot be hidden for this test")
	}
	emptyDir := t.TempDir()
	t.Setenv("PATH", emptyDir)
	if _, err := managedSSHExecPath(t.TempDir()); err == nil || !strings.Contains(err.Error(), "sshd is unavailable") {
		t.Fatalf("error = %v, want sshd unavailable", err)
	}
}

// A host sshd whose `sshd -T` dump reports sshdsessionpath/sshdauthpath must
// get OBoard-named symlinks so the per-connection re-exec processes are also
// identifiable. A host without the directives must get none.
func TestManagedSSHSessionBinaryCreatesNamedSymlinkWhenDirectiveExists(t *testing.T) {
	binDir := t.TempDir()
	helperPath := filepath.Join(binDir, "sshd-session")
	if err := os.WriteFile(helperPath, []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	script := "#!/bin/sh\nif [ \"$1\" = \"-T\" ]; then echo 'port 22\\nsshdsessionpath " + helperPath + "'; exit 0; fi\nexit 0\n"
	installFakeSSHDBinary(t, script)
	dir := t.TempDir()
	linkPath := managedSSHSessionBinary(dir, "sshdsessionpath", managedSSHProcessName+"-session")
	if linkPath == "" {
		t.Fatal("session symlink must be created when the directive is reported")
	}
	if resolved, err := os.Readlink(linkPath); err != nil || resolved != helperPath {
		t.Fatalf("symlink = %q (%v), want %q", resolved, err, helperPath)
	}
}

func TestManagedSSHSessionBinarySkipsUnknownDirective(t *testing.T) {
	installFakeSSHDBinary(t, "#!/bin/sh\nif [ \"$1\" = \"-T\" ]; then echo 'port 22'; exit 0; fi\nexit 0\n")
	dir := t.TempDir()
	if got := managedSSHSessionBinary(dir, "sshdauthpath", managedSSHProcessName+"-auth"); got != "" {
		t.Fatalf("auth symlink = %q, want none without the directive", got)
	}
	if _, err := os.Stat(filepath.Join(dir, managedSSHProcessName+"-auth")); !os.IsNotExist(err) {
		t.Fatalf("no symlink must be left behind: %v", err)
	}
}

// The generated config must carry the OBoard identity end to end: the
// listener is started through the oboard-sshd symlink, and on OpenSSH
// 9.8+/10.0+ hosts the per-connection re-exec binaries are redirected through
// OBoard-named symlinks. The fake sshd reports a sshdsessionpath directive so
// the config rendering can be asserted without a real daemon.
func TestManagedSSHServerConfigUsesOboardProcessIdentity(t *testing.T) {
	binDir := t.TempDir()
	dir := t.TempDir()
	helperPath := filepath.Join(binDir, "sshd-session")
	if err := os.WriteFile(helperPath, []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	sshdScript := "#!/bin/sh\nif [ \"$1\" = \"-T\" ]; then echo 'port 22\nsshdsessionpath " + helperPath + "'; exit 0; fi\nexit 0\n"
	installFakeSSHDBinary(t, sshdScript)
	config, err := managedSSHServerConfig(dir, 2222, filepath.Join(dir, "sshd-host-ed25519"))
	if err != nil {
		t.Fatal(err)
	}
	// The listener symlink must exist and point at the host sshd.
	listenerLink := filepath.Join(dir, managedSSHProcessName)
	resolved, err := os.Readlink(listenerLink)
	if err != nil {
		t.Fatalf("listener symlink missing: %v", err)
	}
	if filepath.Base(resolved) != "sshd" {
		t.Fatalf("listener symlink = %q, want the host sshd", resolved)
	}
	// The per-connection helper must be redirected through an OBoard-named
	// symlink in the generated config.
	sessionLink := filepath.Join(dir, managedSSHProcessName+"-session")
	if resolved, err := os.Readlink(sessionLink); err != nil || resolved != helperPath {
		t.Fatalf("session symlink = %q (%v), want %q", resolved, err, helperPath)
	}
	if !strings.Contains(config, "SshdSessionPath "+sessionLink+"\n") {
		t.Fatalf("generated config missing SshdSessionPath:\n%s", config)
	}
	if strings.Contains(config, "SshdAuthPath") {
		t.Fatalf("SshdAuthPath emitted for a host sshd without the directive:\n%s", config)
	}
}

// On an sshd without sshdsessionpath (OpenSSH <= 9.7) the config must not
// carry any re-exec directive: that sshd re-execs argv[0], which is already
// the oboard-sshd symlink, and an unknown directive would fail `sshd -t`.
func TestManagedSSHServerConfigOmitsDirectivesOnLegacySSHD(t *testing.T) {
	installFakeSSHDBinary(t, "#!/bin/sh\nif [ \"$1\" = \"-T\" ]; then echo 'port 22'; exit 0; fi\nexit 0\n")
	dir := t.TempDir()
	config, err := managedSSHServerConfig(dir, 2222, filepath.Join(dir, "sshd-host-ed25519"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(config, "SshdSessionPath") || strings.Contains(config, "SshdAuthPath") {
		t.Fatalf("legacy sshd config must not carry re-exec directives:\n%s", config)
	}
	if _, err := os.Stat(filepath.Join(dir, managedSSHProcessName+"-session")); !os.IsNotExist(err) {
		t.Fatalf("no session symlink must be left behind: %v", err)
	}
}
