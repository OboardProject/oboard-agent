package minibox

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

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
	users := NewRuntimeUsers(path, nil, nil, []string{"in-a"})
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
	users := NewRuntimeUsers("", nil, nil, []string{"in-a"})
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
	users := NewRuntimeUsers("", nil, nil, []string{"in-a"})
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
	users := NewRuntimeUsers(path, nil, nil, []string{"in-a"})
	entry := testUserEntry("in-a", "alice", "key-a")
	entries := []UserInstallEntry{entry}
	payload, _ := json.Marshal(entries)
	sum := sha256.Sum256(payload)
	req := UserInstallRequest{Scope: []string{"in-a"}, UsersRevision: 1, UsersDigest: "pending-digest", Mode: "full", Entries: entries, Chunk: &UserInstallChunk{Index: 0, Total: 2, SHA256: hex.EncodeToString(sum[:])}}
	if _, err := users.Install(req); !errors.Is(err, ErrUserInstallIncomplete) {
		t.Fatal(err)
	}
	restored := NewRuntimeUsers(path, nil, nil, []string{"in-a"})
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
