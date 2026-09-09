package agent

import (
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/OboardProject/oboard-agent/internal/model"
)

func authenticationTestPlan(t *testing.T) model.SSHInboundPlan {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	_ = listener.Close()
	return model.SSHInboundPlan{Version: 1, Inbounds: []model.SSHInbound{{
		InboundID: 71, ServerID: 1, ListenIP: "127.0.0.1", Port: port, Enabled: true,
		Users: []model.SSHInboundUser{testSSHInboundUser(19, "alice", "test-password")},
	}}}
}

func TestSSHAuthenticationVerificationChecksLiveListenerOnReplay(t *testing.T) {
	runner := newTestSSHRunner(t, Config{StateDir: t.TempDir()})
	plan := authenticationTestPlan(t)
	plan.Inbounds[0].Users[0].CredentialStatus = "active"
	t.Cleanup(func() { _, _ = runner.applySSHInbounds(model.SSHInboundPlan{Version: 2}) })
	result, err := runner.applySSHInbounds(plan)
	if err != nil || !result.AuthenticationVerified || result.AuthenticatedUsers != 1 {
		t.Fatalf("initial verification: %+v, %v", result, err)
	}
	result, err = runner.applySSHInbounds(plan)
	if err != nil || !result.Unchanged || !result.AuthenticationVerified || result.AuthenticatedUsers != 1 {
		t.Fatalf("replay verification: %+v, %v", result, err)
	}
	live := runner.sshInboundManager.listeners[71]
	_ = live.listener.Close()
	result, err = runner.applySSHInbounds(plan)
	if err == nil || !strings.Contains(err.Error(), "dial tcp") || result.AuthenticationVerified || result.Unchanged {
		t.Fatalf("dead listener reported success: %+v, %v", result, err)
	}
	if _, _, err := runner.verifySSHAuthentication(plan); err != nil {
		t.Fatalf("previous listener not restored: %v", err)
	}
}

func TestSSHAuthenticationVerificationRejectsMissingAuthorization(t *testing.T) {
	runner := newTestSSHRunner(t, Config{StateDir: t.TempDir()})
	plan := authenticationTestPlan(t)
	plan.Inbounds[0].Users[0].AuthorizationKey = "abcdef0123456789abcdef0123456789"
	result, err := runner.applySSHInbounds(plan)
	if err == nil || result.AuthenticationVerified {
		t.Fatalf("unauthorized credential reported success: %+v, %v", result, err)
	}
	if _, err := os.Stat(filepath.Join(runner.stateDir(), sshInboundsCurrent)); !os.IsNotExist(err) {
		t.Fatalf("failed plan persisted: %v", err)
	}
	if runner.sshInboundManager != nil {
		t.Fatal("failed runtime not removed")
	}
}

func TestSSHAuthenticationVerificationChecksRejectionAndCredentialDrift(t *testing.T) {
	runner := newTestSSHRunner(t, Config{StateDir: t.TempDir()})
	plan := authenticationTestPlan(t)
	plan.Inbounds[0].Users[0].CredentialStatus = "reject_new"
	plan.Inbounds[0].Users[0].DeviceIDHash = "0123456789abcdef"
	plan.Inbounds[0].Users[0].CredentialEpoch = 1
	t.Cleanup(func() { _, _ = runner.applySSHInbounds(model.SSHInboundPlan{Version: 3}) })
	result, err := runner.applySSHInbounds(plan)
	if err != nil || !result.AuthenticationVerified || result.RejectedUsers != 1 || result.AuthenticatedUsers != 0 {
		t.Fatalf("rejection verification: %+v, %v", result, err)
	}
	live := runner.sshInboundManager.listeners[71]
	user := plan.Inbounds[0].Users[0]
	live.authMu.Lock()
	credential := live.auth[user.Username]
	credential.password = "stale-password"
	live.auth[user.Username] = credential
	live.authMu.Unlock()
	if _, _, err := runner.verifySSHAuthentication(plan); err == nil {
		t.Fatal("credential drift accepted")
	}
	result, err = runner.applySSHInbounds(plan)
	if err != nil || !result.AuthenticationVerified || result.RejectedUsers != 1 {
		t.Fatalf("reconciled rejection: %+v, %v", result, err)
	}
	plan.Version++
	plan.Inbounds[0].Users[0].CredentialStatus = "active"
	result, err = runner.applySSHInbounds(plan)
	if err != nil || !result.AuthenticationVerified || result.AuthenticatedUsers != 1 {
		t.Fatalf("regrant verification: %+v, %v", result, err)
	}
	if live.counterFor(user.UserID).upload.Load() != 0 || live.counterFor(user.UserID).download.Load() != 0 {
		t.Fatal("authentication probe billed traffic")
	}
}

func TestSSHAuthenticationVerificationChecksExhaustedQuota(t *testing.T) {
	runner := newTestSSHRunner(t, Config{StateDir: t.TempDir()})
	plan := authenticationTestPlan(t)
	t.Cleanup(func() { _, _ = runner.applySSHInbounds(model.SSHInboundPlan{Version: 2}) })
	if _, err := runner.applySSHInbounds(plan); err != nil {
		t.Fatal(err)
	}
	live := runner.sshInboundManager.listeners[71]
	live.counterFor(19).setPolicy(model.TrafficRuntimePolicy{UserID: 19, QuotaState: "quota_exceeded"})
	authenticated, rejected, err := runner.verifySSHAuthentication(plan)
	if err != nil || authenticated != 0 || rejected != 1 {
		t.Fatalf("quota rejection not verified: authenticated=%d rejected=%d err=%v", authenticated, rejected, err)
	}
}

type sshProbeAddressListener struct {
	net.Listener
	address net.Addr
}

func (l sshProbeAddressListener) Addr() net.Addr { return l.address }

func TestSSHAuthenticationVerificationWildcardAddressFamilies(t *testing.T) {
	for _, test := range []struct{ name, network, host string }{
		{"IPv4 with dual-stack reported address", "tcp4", "127.0.0.1"},
		{"IPv6 only", "tcp6", "::1"},
	} {
		t.Run(test.name, func(t *testing.T) {
			listener, err := net.Listen(test.network, net.JoinHostPort(test.host, "0"))
			if err != nil {
				if test.network == "tcp6" {
					t.Skipf("IPv6 unavailable: %v", err)
				}
				t.Fatal(err)
			}
			defer listener.Close()
			runner := newTestSSHRunner(t, Config{StateDir: t.TempDir()})
			plan := authenticationTestPlan(t)
			plan.Inbounds[0].ListenIP = "0.0.0.0"
			plan.Inbounds[0].Port = listener.Addr().(*net.TCPAddr).Port
			manager, err := runner.newSSHInboundManager(plan)
			if err != nil {
				t.Fatal(err)
			}
			runner.sshInboundManager = manager
			defer manager.close()
			live := manager.listeners[71]
			live.listener = sshProbeAddressListener{Listener: listener, address: &net.TCPAddr{IP: net.IPv6unspecified, Port: plan.Inbounds[0].Port}}
			done := make(chan struct{})
			go func() { defer close(done); live.serve(listener, manager.signer) }()
			defer func() { listener.Close(); <-done }()
			authenticated, rejected, err := runner.verifySSHAuthentication(plan)
			if err != nil || authenticated != 1 || rejected != 0 {
				t.Fatalf("wildcard authentication: authenticated=%d rejected=%d err=%v", authenticated, rejected, err)
			}
		})
	}
}
