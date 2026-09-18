package minibox

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	box "github.com/sagernet/sing-box"
)

func TestRuntimeUsersRestoreAfterRemovingInbound(t *testing.T) {
	for _, scope := range [][]string{{"in-1"}, {}} {
		t.Run(fmt.Sprint(scope), func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "kernel-users.json")
			start := func(scope []string) *RuntimeUsers {
				t.Helper()
				inbounds := []map[string]any{}
				for _, tag := range scope {
					in := map[string]any{"tag": tag, "listen": "127.0.0.1", "listen_port": 0, "users": []any{}}
					if tag == "in-1" {
						in["type"], in["version"], in["auth_mode"] = "snell", 6, "multi_psk"
					} else {
						in["type"], in["method"] = "shadowsocks", "aes-128-gcm"
					}
					inbounds = append(inbounds, in)
				}
				raw, err := json.Marshal(map[string]any{"inbounds": inbounds, "outbounds": []map[string]any{{"type": "direct", "tag": "direct"}}, "_oboard": map[string]any{"runtime_users": map[string]any{"inbounds": scope}}})
				if err != nil {
					t.Fatal(err)
				}
				configPath := filepath.Join(t.TempDir(), "config.json")
				if err := os.WriteFile(configPath, raw, 0600); err != nil {
					t.Fatal(err)
				}
				opts, metadata, err := LoadConfig(configPath, nil, HY2Tuning{})
				if err != nil {
					t.Fatal(err)
				}
				ctx := Context(context.Background())
				b, err := box.New(box.Options{Context: ctx, Options: opts})
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = b.Close() })
				tracker := AttachRuntimeTrackers(ctx, metadata)
				if err := b.Start(); err != nil {
					t.Fatal(err)
				}
				return NewRuntimeUsers(path, nil, b, tracker, scope)
			}
			oldScope := []string{"in-1", "in-56"}
			old := start(oldScope)
			ss := testUserEntry("in-56", "bob", "ss-key")
			ss.Credential = UserCredential{Password: "test-password"}
			entries := []UserInstallEntry{snellTestEntry("alice", "snell-key", "test-snell-psk-123456", 1), ss}
			digest, err := UsersDigest(10, oldScope, entries)
			if err != nil {
				t.Fatal(err)
			}
			req := UserInstallRequest{Scope: oldScope, UsersRevision: 10, UsersDigest: digest, Mode: "full", Entries: entries}
			if _, err := old.Install(req); err != nil {
				t.Fatal(err)
			}
			before, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			restarted := start(scope)
			if err := restarted.Restore(); err != nil {
				t.Fatalf("restart after removing Shadowsocks: %v", err)
			}
			after, err := os.ReadFile(path)
			if err != nil || !bytes.Equal(before, after) {
				t.Fatal("restore changed durable snapshot")
			}
			if restarted.current.Revision != 10 || restarted.current.Digest != digest {
				t.Fatal("restore lost revision protection")
			}
			if restarted.tracker.stateForKey("user:bob") != nil {
				t.Fatal("removed inbound user was restored")
			}
			if len(scope) > 0 && restarted.tracker.stateForKey("user:alice") == nil {
				t.Fatal("Snell user was not restored")
			}
			if _, err := restarted.Install(req); !errors.Is(err, ErrUserInstallCapability) {
				t.Fatalf("live replay accepted removed scope: %v", err)
			}
			stale := req
			stale.UsersRevision = 9
			stale.UsersDigest, _ = UsersDigest(9, oldScope, entries)
			if _, err := restarted.Install(stale); !errors.Is(err, ErrUserInstallBase) {
				t.Fatalf("older snapshot accepted: %v", err)
			}
			rollback := start(oldScope)
			if err := rollback.Restore(); err != nil {
				t.Fatalf("rollback: %v", err)
			}
			if rollback.tracker.stateForKey("user:bob") == nil {
				t.Fatal("rollback lost old inbound user")
			}
			if len(scope) > 0 {
				installSnellTest(t, restarted, 11, entries[:1])
				if restarted.Status().UsersRevision != 11 {
					t.Fatal("new full snapshot did not converge")
				}
			}
			var corrupt persistedUsers
			if err := json.Unmarshal(before, &corrupt); err != nil {
				t.Fatal(err)
			}
			corrupt.Current.Digest = "invalid"
			raw, err := json.Marshal(corrupt)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, raw, 0600); err != nil {
				t.Fatal(err)
			}
			if err := start(scope).Restore(); !errors.Is(err, ErrUserInstallDigest) {
				t.Fatalf("removed scope bypassed integrity check: %v", err)
			}
		})
	}
}

func testUserEntry(tag, user, key string) UserInstallEntry {
	return UserInstallEntry{
		InboundTag:       tag,
		AuthUser:         user,
		AuthorizationKey: key,
		Credential:       UserCredential{UUID: "11111111-1111-1111-1111-111111111111"},
		Identity:         UserIdentity{UserID: 7, InboundID: 1, CredentialStatus: "active"},
		RouteOutbound:    "direct",
		Policy:           RuntimeUserLimit{Billable: true, UserID: 7},
	}
}

func TestUsersDigestIsStableAcrossEntryOrder(t *testing.T) {
	first, err := UsersDigest(3, []string{"in-b", "in-a"}, []UserInstallEntry{
		testUserEntry("in-b", "bob", "k-b"),
		testUserEntry("in-a", "alice", "k-a"),
	})
	if err != nil || first == "" {
		t.Fatalf("digest=%q err=%v", first, err)
	}
	second, err := UsersDigest(3, []string{"in-a", "in-b"}, []UserInstallEntry{
		testUserEntry("in-a", "alice", "k-a"),
		testUserEntry("in-b", "bob", "k-b"),
	})
	if err != nil || second != first {
		t.Fatalf("order changed digest: %q vs %q err=%v", first, second, err)
	}
	other, err := UsersDigest(4, []string{"in-a", "in-b"}, []UserInstallEntry{
		testUserEntry("in-a", "alice", "k-a"),
		testUserEntry("in-b", "bob", "k-b"),
	})
	if err != nil || other == first {
		t.Fatal("revision is not part of the digest")
	}
}

func TestRuntimeUsersFullInstallRejectsBadDigestAndPersistsCommit(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "kernel-users.json")
	users := NewRuntimeUsers(path, nil, nil, nil, []string{"in-a"})
	entry := testUserEntry("in-a", "alice", "k-a")
	digest, err := UsersDigest(1, []string{"in-a"}, []UserInstallEntry{entry})
	if err != nil {
		t.Fatal(err)
	}
	_, err = users.Install(UserInstallRequest{Scope: []string{"in-a"}, UsersRevision: 1, UsersDigest: "deadbeef", Mode: "full", Entries: []UserInstallEntry{entry}})
	if !errors.Is(err, ErrUserInstallDigest) {
		t.Fatalf("wanted digest error, got %v", err)
	}
	// A missing runtime is rejected before writing a recoverable candidate.
	_, err = users.Install(UserInstallRequest{Scope: []string{"in-a"}, UsersRevision: 1, UsersDigest: digest, Mode: "full", Entries: []UserInstallEntry{entry}})
	if !errors.Is(err, ErrUserInstallCapability) {
		t.Fatalf("expected capability rejection, got %v", err)
	}
	if _, err = os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("invalid candidate persisted: %v", err)
	}

}

func TestRuntimeUsersDeltaDeleteDoesNotRequireAuthorizationKey(t *testing.T) {
	users := NewRuntimeUsers("", nil, nil, nil, []string{"in-a"})
	entry := testUserEntry("in-a", "alice", "k-a")
	digest, err := UsersDigest(1, []string{"in-a"}, []UserInstallEntry{entry})
	if err != nil {
		t.Fatal(err)
	}
	users.current = &UserSnapshot{Revision: 1, Digest: digest, Scope: []string{"in-a"}, Entries: []UserInstallEntry{entry}}
	deleted := UserInstallEntry{InboundTag: "in-a", AuthUser: "alice"}
	next, err := UsersDigest(2, []string{"in-a"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := users.buildSnapshot(UserInstallRequest{Scope: []string{"in-a"}, UsersRevision: 2, UsersDigest: next, Mode: "delta", BaseRevision: 1, Entries: []UserInstallEntry{deleted}}, []UserInstallEntry{deleted})
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.Revision != 2 || len(snapshot.Entries) != 0 || snapshot.Digest != next {
		t.Fatalf("delete snapshot: %+v", snapshot)
	}
}

func TestRuntimeUsersIllegalInstallRejected(t *testing.T) {
	users := NewRuntimeUsers("", nil, nil, nil, []string{"in-a"})
	if _, err := users.Install(UserInstallRequest{}); !errors.Is(err, ErrUserInstallIllegal) {
		t.Fatalf("empty request: %v", err)
	}
	if _, err := users.Install(UserInstallRequest{Scope: []string{"in-a"}, UsersRevision: 1, UsersDigest: "x", Mode: "replace"}); !errors.Is(err, ErrUserInstallIllegal) {
		t.Fatalf("bad mode: %v", err)
	}
	if _, err := users.buildSnapshot(UserInstallRequest{Scope: []string{"in-a"}, UsersRevision: 1, UsersDigest: "x", Mode: "full"}, []UserInstallEntry{{InboundTag: "in-a", AuthUser: "alice"}}); !errors.Is(err, ErrUserInstallIllegal) {
		t.Fatalf("full delete marker: %v", err)
	}
	if _, err := users.buildSnapshot(UserInstallRequest{Scope: []string{"in-a"}, UsersRevision: 1, UsersDigest: "x", Mode: "full"}, []UserInstallEntry{{InboundTag: "other", AuthUser: "alice", AuthorizationKey: "k", Credential: UserCredential{UUID: "u"}}}); !errors.Is(err, ErrUserInstallIllegal) {
		t.Fatalf("out of scope: %v", err)
	}
}

func TestNormalizeOperationalConfigStripsRuntimeUsers(t *testing.T) {
	raw := []byte(`{
		"inbounds": [{"tag":"in-a","type":"vless","users":[{"name":"alice","uuid":"11111111-1111-1111-1111-111111111111"}]}],
		"outbounds": [{"tag":"direct","type":"direct"},{"tag":"userselector-in-a","type":"user-selector","users":{"alice":"direct"}}],
		"_oboard": {
			"runtime_users": {"inbounds":["in-a"]},
			"rate_limits": {"users":{"alice":{"user_id":7,"authorization_key":"k-alice","billable":true},"other":{"user_id":8,"authorization_key":"k-other","billable":true}}},
			"authorization": {"revision":1,"issued_at":"2026-09-07T00:00:00Z","grants":{"k-alice":"2026-09-07T00:05:00Z"}}
		}
	}`)
	normalized, err := NormalizeOperationalConfig(raw)
	if err != nil {
		t.Fatal(err)
	}
	var object map[string]any
	if err := json.Unmarshal(normalized, &object); err != nil {
		t.Fatal(err)
	}
	inbound := object["inbounds"].([]any)[0].(map[string]any)
	if _, ok := inbound["users"]; ok {
		t.Fatalf("inbound users were not stripped: %s", normalized)
	}
	foundSelector := false
	for _, rawOutbound := range object["outbounds"].([]any) {
		outbound := rawOutbound.(map[string]any)
		if outbound["tag"] == "userselector-in-a" {
			foundSelector = true
			if _, ok := outbound["users"]; ok {
				t.Fatalf("user-selector users were not stripped: %s", normalized)
			}
		}
	}
	if !foundSelector {
		t.Fatal("user-selector outbound missing after normalize")
	}
	metadata := object["_oboard"].(map[string]any)
	if _, ok := metadata["authorization"]; ok {
		t.Fatal("authorization metadata should stay outside the operational digest")
	}
	limits := metadata["rate_limits"].(map[string]any)
	users := limits["users"].(map[string]any)
	if _, ok := users["alice"]; ok {
		t.Fatal("runtime user rate-limit entry was not stripped")
	}
	if _, ok := users["other"]; !ok {
		t.Fatal("unrelated rate-limit user was stripped")
	}
}

func TestReplaceScopedUsersKeepsRemovedUserCounters(t *testing.T) {
	tracker := NewRateLimitTracker(RuntimeMetadata{})
	entry := UserInstallEntry{
		AuthUser: "alice",
		Identity: UserIdentity{UserID: 7, InboundID: 1},
		Policy:   RuntimeUserLimit{Billable: true, UserID: 7, InboundID: 1},
	}
	tracker.ReplaceScopedUsers([]string{"in-a"}, []UserInstallEntry{entry})
	state := tracker.stateForKey("user:alice")
	if state == nil {
		t.Fatal("installed user has no tracker state")
	}
	state.addTraffic(128, 256)
	tracker.ReplaceScopedUsers([]string{"in-a"}, nil)
	kept := tracker.stateForKey("user:alice")
	if kept == nil {
		t.Fatal("removed user counters were dropped")
	}
	counter, ok := kept.snapshot()
	if !ok || counter.Upload != 128 || counter.Download != 256 {
		t.Fatalf("tail traffic lost: ok=%v %+v", ok, counter)
	}
}

func TestRuntimeUsersChunkRecoveryRetainsPreparedParts(t *testing.T) {
	path := filepath.Join(t.TempDir(), "users.json")
	users := NewRuntimeUsers(path, nil, nil, nil, []string{"in-a"})
	entry := testUserEntry("in-a", "alice", "key-a")
	entries := []UserInstallEntry{entry}
	payload, _ := json.Marshal(entries)
	sum := sha256.Sum256(payload)
	req := UserInstallRequest{Scope: []string{"in-a"}, UsersRevision: 1, UsersDigest: "pending-digest", Mode: "full", Entries: entries, Chunk: &UserInstallChunk{Index: 0, Total: 2, SHA256: hex.EncodeToString(sum[:])}}
	if _, err := users.Install(req); !errors.Is(err, ErrUserInstallIncomplete) {
		t.Fatal(err)
	}
	restored := NewRuntimeUsers(path, nil, nil, nil, []string{"in-a"})
	if err := restored.Restore(); err != nil {
		t.Fatal(err)
	}
	if restored.current != nil || restored.chunks == nil || len(restored.chunks.Parts[0]) == 0 {
		t.Fatal("prepared part was lost or activated")
	}
	req.Mode = "delta"
	if _, _, err := restored.acceptChunk(req); !errors.Is(err, ErrUserInstallIllegal) {
		t.Fatal("mixed chunk mode accepted")
	}
	req.Mode = "full"
	if _, err := restored.buildSnapshot(req, []UserInstallEntry{entry, entry}); !errors.Is(err, ErrUserInstallIllegal) {
		t.Fatal("duplicate entry accepted")
	}
}
