package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/OboardProject/oboard-agent/internal/model"
	"github.com/OboardProject/oboard-agent/internal/security"
)

func signedTestUsersEnvelope(t *testing.T, token string, serverID int64, messageID string, req model.UsersInstallRequest) model.UsersEnvelope {
	t.Helper()
	usersJSON, err := json.Marshal(req)
	if err != nil {
		t.Fatal(err)
	}
	envelope := model.UsersEnvelope{Type: model.AgentControlUsersUpdate, MessageID: messageID, ServerID: serverID, UsersJSON: string(usersJSON)}
	envelope.Signature = security.SignUsersEnvelope(security.HashSecret(token), security.UsersEnvelopeFields{ServerID: serverID, MessageID: messageID, Revision: req.UsersRevision, Digest: req.UsersDigest, UsersJSON: envelope.UsersJSON})
	return envelope
}

func TestUsersEnvelopeLaneAppliesVerifiesAndRejectsForgeries(t *testing.T) {
	dir := t.TempDir()
	core := writeFakeCoreBinaryWithCapabilities(t, dir, "build-users", []string{kernelCapabilityRuntimeUsers, coreRuntimeDigestCapability})
	writeCoreConfig(t, dir, `{"log":{"level":"warn"},"inbounds":[{"tag":"in-a","type":"vless"}],"outbounds":[{"tag":"direct","type":"direct"}]}`)
	kernel := newFakeCoreKernel(t, filepath.Join(dir, "sing-box.json"), true)
	kernel.runtimeUsers = true
	r := newRuntimeTestRunnerWithCore(t, dir, kernel, core)
	cfg := r.Config()
	cfg.AgentToken = "users-token"
	cfg.AgentID = "users-agent"
	cfg.ServerID = 8
	r.storeConfig(cfg)

	req := model.UsersInstallRequest{
		Scope: []string{"in-a"}, UsersRevision: 1, UsersDigest: "digest-1", Mode: "full",
		Entries: []model.UsersInstallEntry{{InboundTag: "in-a", AuthUser: "alice", AuthorizationKey: "k-alice", Credential: model.UsersCredential{UUID: "11111111-1111-1111-1111-111111111111"}, RouteOutbound: "direct"}},
	}
	ack := r.applyUsersEnvelope(context.Background(), signedTestUsersEnvelope(t, "users-token", 8, "u1", req))
	if !ack.Confirmed || ack.Error != "" || ack.Revision != 1 || ack.Runtimes["kernel"] != "verified" {
		t.Fatalf("valid users envelope not confirmed: %+v", ack)
	}
	if applied := r.appliedUsers(); applied == nil || applied.Revision != 1 || applied.BootID != "users-boot" {
		t.Fatalf("applied users not reported: %+v", applied)
	}

	forged := signedTestUsersEnvelope(t, "other-token", 8, "u2", model.UsersInstallRequest{Scope: []string{"in-a"}, UsersRevision: 2, UsersDigest: "digest-2", Mode: "full"})
	ack = r.applyUsersEnvelope(context.Background(), forged)
	if ack.Confirmed || ack.Error == "" || ack.Applied == nil || ack.Applied.Revision != 1 {
		t.Fatalf("forged users envelope accepted: %+v", ack)
	}
	foreign := signedTestUsersEnvelope(t, "users-token", 9, "u3", req)
	if ack := r.applyUsersEnvelope(context.Background(), foreign); ack.Confirmed || ack.Error == "" {
		t.Fatalf("foreign server users envelope accepted: %+v", ack)
	}

	revoke := model.UsersInstallRequest{Scope: []string{"in-a"}, UsersRevision: 2, UsersDigest: "digest-2", Mode: "full", Entries: []model.UsersInstallEntry{}}
	ack = r.applyUsersEnvelope(context.Background(), signedTestUsersEnvelope(t, "users-token", 8, "u4", revoke))
	if !ack.Confirmed || ack.Revision != 2 {
		t.Fatalf("users revoke not confirmed: %+v", ack)
	}
}

func TestUsersRevokeBypassesBusyTaskLocks(t *testing.T) {
	dir := t.TempDir()
	core := writeFakeCoreBinaryWithCapabilities(t, dir, "build-users", []string{kernelCapabilityRuntimeUsers, coreRuntimeDigestCapability})
	writeCoreConfig(t, dir, `{"log":{"level":"warn"},"inbounds":[{"tag":"in-a","type":"vless"}]}`)
	kernel := newFakeCoreKernel(t, filepath.Join(dir, "sing-box.json"), true)
	kernel.runtimeUsers = true
	r := newRuntimeTestRunnerWithCore(t, dir, kernel, core)
	cfg := r.Config()
	cfg.AgentToken = "users-token"
	cfg.ServerID = 8
	r.storeConfig(cfg)

	r.deploymentMu.Lock()
	r.coreLifecycleMu.Lock()
	r.trafficMu.Lock()
	defer func() {
		r.trafficMu.Unlock()
		r.coreLifecycleMu.Unlock()
		r.deploymentMu.Unlock()
	}()

	revoke := model.UsersInstallRequest{Scope: []string{"in-a"}, UsersRevision: 3, UsersDigest: "digest-3", Mode: "full"}
	done := make(chan model.UsersAck, 1)
	go func() {
		done <- r.applyUsersEnvelope(context.Background(), signedTestUsersEnvelope(t, "users-token", 8, "busy-u", revoke))
	}()
	select {
	case ack := <-done:
		if !ack.Confirmed || ack.Revision != 3 {
			t.Fatalf("users revoke blocked by task locks: %+v", ack)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("users revoke did not finish while task locks were held")
	}
}

func TestNormalizeOperationalCoreConfigStripsRuntimeUsers(t *testing.T) {
	raw := []byte(fmt.Sprintf(`{"inbounds":[{"tag":"in-a","type":"vless","users":[{"name":"alice","uuid":"u"}]}],"outbounds":[{"tag":"direct","type":"direct"},{"tag":"userselector-in-a","type":"user-selector","users":{"alice":"direct"}}],"_oboard":{"runtime_users":{"inbounds":["in-a"]},"rate_limits":{"users":{"alice":{"user_id":7,"authorization_key":"k"}}},"authorization":{"revision":1,"issued_at":"t","grants":{}}}}`))
	normalized, err := normalizeOperationalCoreConfig(raw)
	if err != nil {
		t.Fatal(err)
	}
	var object map[string]any
	if err := json.Unmarshal(normalized, &object); err != nil {
		t.Fatal(err)
	}
	if _, ok := object["inbounds"].([]any)[0].(map[string]any)["users"]; ok {
		t.Fatalf("inbound users not stripped: %s", normalized)
	}
}

func TestReapplyPersistedRuntimeUsersDropsScopeTheConfigNoLongerDeclares(t *testing.T) {
	dir := t.TempDir()
	core := writeFakeCoreBinaryWithCapabilities(t, dir, "build-users", []string{kernelCapabilityRuntimeUsers, coreRuntimeDigestCapability})
	writeCoreConfig(t, dir, `{"log":{"level":"warn"},"inbounds":[{"tag":"in-a","type":"vless"}],"outbounds":[{"tag":"direct","type":"direct"}]}`)
	kernel := newFakeCoreKernel(t, filepath.Join(dir, "sing-box.json"), true)
	kernel.runtimeUsers = true
	r := newRuntimeTestRunnerWithCore(t, dir, kernel, core)
	cfg := r.Config()
	cfg.AgentToken = "users-token"
	cfg.ServerID = 8
	r.storeConfig(cfg)

	req := model.UsersInstallRequest{
		Scope: []string{"in-a"}, UsersRevision: 5, UsersDigest: "digest-5", Mode: "full",
		Entries: []model.UsersInstallEntry{{InboundTag: "in-a", AuthUser: "alice", AuthorizationKey: "k-alice", Credential: model.UsersCredential{UUID: "11111111-1111-1111-1111-111111111111"}, RouteOutbound: "direct"}},
	}
	if ack := r.applyUsersEnvelope(context.Background(), signedTestUsersEnvelope(t, "users-token", 8, "u1", req)); !ack.Confirmed {
		t.Fatalf("users envelope not confirmed: %+v", ack)
	}

	withScope := `{"inbounds":[{"tag":"in-a","type":"vless"}],"_oboard":{"runtime_users":{"inbounds":["in-a"]}}}`
	if err := r.reapplyPersistedRuntimeUsers(context.Background(), []byte(withScope)); err != nil {
		t.Fatalf("live snapshot was not replayed: %v", err)
	}
	if applied := r.appliedUsers(); applied == nil || applied.Revision != 5 {
		t.Fatalf("live snapshot was dropped: %+v", applied)
	}

	// The SSH-only configuration declares no runtime-user inbound, so the
	// snapshot installed against the previous configuration is stale.
	sshOnly := `{"inbounds":[],"outbounds":[{"tag":"direct","type":"direct"}]}`
	if err := r.reapplyPersistedRuntimeUsers(context.Background(), []byte(sshOnly)); err != nil {
		t.Fatalf("stale snapshot replay reported an error: %v", err)
	}
	if applied := r.appliedUsers(); applied != nil {
		t.Fatalf("stale snapshot was kept: %+v", applied)
	}
	if _, err := os.Stat(r.runtimeUsersPath()); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("stale runtime users state was not removed: %v", err)
	}
	req.Mode, req.BaseRevision = "delta", 4
	previousState, err := json.Marshal(persistedRuntimeUsers{Current: &req, Commit: "current", BootID: "old-boot"})
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(r.runtimeUsersPath(), previousState, 0600); err != nil {
		t.Fatal(err)
	}
	r.loadPersistedRuntimeUsers()
	if r.runtimeUsersCurrent != nil || r.appliedUsers() != nil {
		t.Fatal("old delta was treated as a complete installed snapshot")
	}
}
