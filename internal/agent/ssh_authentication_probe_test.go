package agent

import (
	"net"
	"os"
	"path/filepath"
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
	if err == nil || result.AuthenticationVerified || result.Unchanged {
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
