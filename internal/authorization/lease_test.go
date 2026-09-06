package authorization

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestLeasePersistsRevocationAcrossRenewalReplayAndRestart(t *testing.T) {
	now := time.Now().UTC()
	path := filepath.Join(t.TempDir(), "authorization.json")
	grant := &Lease{Revision: 1, IssuedAt: now.Format(time.RFC3339Nano), Grants: map[string]string{"old": now.Add(MaxLifetime).Format(time.RFC3339Nano)}}
	store := NewStore(path)
	if err := store.Update(grant); err != nil {
		t.Fatal(err)
	}
	if !store.Allows("old", now) || store.Allows("missing", now) {
		t.Fatal("incorrect admission")
	}
	renewed := clone(grant)
	renewed.IssuedAt = now.Add(time.Second).Format(time.RFC3339Nano)
	renewed.Grants["old"] = now.Add(MaxLifetime + time.Second).Format(time.RFC3339Nano)
	if err := store.Update(renewed); err != nil {
		t.Fatal(err)
	}
	revoked := &Lease{Revision: 2, IssuedAt: now.Add(2 * time.Second).Format(time.RFC3339Nano), Grants: map[string]string{}}
	if err := store.Update(revoked); err != nil {
		t.Fatal(err)
	}
	store = NewStore(path)
	for _, old := range []*Lease{grant, renewed, nil} {
		if err := store.Update(old); err != nil {
			t.Fatal(err)
		}
	}
	if store.Allows("old", now.Add(3*time.Second)) {
		t.Fatal("replay restored revoked authorization")
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0600 {
		t.Fatalf("mode=%v", info.Mode())
	}
	conflict := clone(revoked)
	conflict.Grants["old"] = now.Add(MaxLifetime).Format(time.RFC3339Nano)
	if store.Update(conflict) == nil {
		t.Fatal("accepted conflicting snapshot identity")
	}
}

func TestLeaseAbsoluteDeadlineAndCorruptStateFailClosed(t *testing.T) {
	now := time.Now().UTC()
	lease := &Lease{Revision: 1, IssuedAt: now.Format(time.RFC3339Nano), Grants: map[string]string{"key": now.Add(MaxLifetime).Format(time.RFC3339Nano)}}
	for _, at := range []time.Time{now.Add(-time.Nanosecond), now.Add(MaxLifetime), now.Add(time.Hour)} {
		if lease.Allows("key", at) {
			t.Fatalf("allowed at %v", at)
		}
	}
	lease.Grants["key"] = now.Add(MaxLifetime + time.Nanosecond).Format(time.RFC3339Nano)
	if lease.Validate() == nil {
		t.Fatal("accepted excessive lifetime")
	}
	path := filepath.Join(t.TempDir(), "authorization.json")
	if err := os.WriteFile(path, []byte("invalid-json"), 0600); err != nil {
		t.Fatal(err)
	}
	store := NewStore(path)
	if store.Allows("key", now) {
		t.Fatal("corrupt state authorized")
	}
	if store.Update(nil) == nil {
		t.Fatal("corrupt state silently reset")
	}
}

func TestLeaseSequenceOrdersRenewalsAndDenyWatermarkSurvivesRestart(t *testing.T) {
	now := time.Now().UTC()
	path := filepath.Join(t.TempDir(), "authorization.json")
	store := NewStore(path)
	first := &Lease{Revision: 3, Sequence: 1, Digest: "d3", IssuedAt: now.Format(time.RFC3339Nano), ExpiresAt: now.Add(MaxLifetime).Format(time.RFC3339Nano), Grants: map[string]string{"a": now.Add(MaxLifetime).Format(time.RFC3339Nano), "b": now.Add(MaxLifetime).Format(time.RFC3339Nano)}}
	if _, err := store.UpdateWithResult(first); err != nil {
		t.Fatal(err)
	}
	// A renewal with a higher sequence but an earlier issued_at still wins by
	// sequence; the same sequence with the same content is a no-op.
	renewal := clone(first)
	renewal.Sequence = 2
	renewal.IssuedAt = now.Add(-time.Second).Format(time.RFC3339Nano)
	renewal.ExpiresAt = now.Add(MaxLifetime - time.Second).Format(time.RFC3339Nano)
	renewal.Grants["a"] = renewal.ExpiresAt
	renewal.Grants["b"] = renewal.ExpiresAt
	if res, err := store.UpdateWithResult(renewal); err != nil || !res.Installed {
		t.Fatalf("higher sequence not installed: %+v err=%v", res, err)
	}
	if res, err := store.UpdateWithResult(first); err != nil || !res.Superseded {
		t.Fatalf("lower sequence replay was not superseded: %+v err=%v", res, err)
	}
	// Revision 4 revokes b explicitly and lists it in the deny watermark.
	revoke := &Lease{Revision: 4, Sequence: 1, Digest: "d4", IssuedAt: now.Add(time.Second).Format(time.RFC3339Nano), Grants: map[string]string{"a": now.Add(MaxLifetime).Format(time.RFC3339Nano)}, Denied: []string{"b"}}
	res, err := store.UpdateWithResult(revoke)
	if err != nil || len(res.Revoked) != 1 || res.Revoked[0] != "b" {
		t.Fatalf("revoke result: %+v err=%v", res, err)
	}
	if store.Allows("b", now.Add(2*time.Second)) || !store.Allows("a", now.Add(2*time.Second)) {
		t.Fatal("deny watermark or grant not honored")
	}
	if store.Status().Revision != 4 || store.Status().DeniedCount != 1 {
		t.Fatalf("status: %+v", store.Status())
	}
	// Restart: the watermark is persisted next to the lease.
	restarted := NewStore(path)
	if !restarted.Denied("b") || restarted.Allows("b", now.Add(2*time.Second)) {
		t.Fatal("deny watermark lost across restart")
	}
	// A same-revision snapshot with a different digest is a conflict.
	conflict := clone(revoke)
	conflict.Digest = "other"
	conflict.Grants["c"] = now.Add(MaxLifetime).Format(time.RFC3339Nano)
	if _, err := restarted.UpdateWithResult(conflict); err == nil {
		t.Fatal("same revision with different digest accepted")
	}
	// A fresh lease issued after the installed one fully expired is accepted
	// even with a lower revision (Controller counters reset).
	reset := &Lease{Revision: 1, Sequence: 1, Digest: "r1", IssuedAt: now.Add(MaxLifetime + 2*time.Second).Format(time.RFC3339Nano), Grants: map[string]string{"a": now.Add(2*MaxLifetime + 2*time.Second).Format(time.RFC3339Nano)}}
	if res, err := restarted.UpdateWithResult(reset); err != nil || !res.Installed {
		t.Fatalf("post-expiry reset lease rejected: %+v err=%v", res, err)
	}
	// Denied b stays denied even if a later snapshot never mentions it.
	if restarted.Allows("b", now.Add(MaxLifetime+3*time.Second)) {
		t.Fatal("denied key re-admitted after counter reset")
	}
}

func TestAuthorizationPersistenceFailureDeniesExistingGrants(t *testing.T) {
	now := time.Now().UTC()
	store := NewStore("")
	if err := store.Update(&Lease{Revision: 1, IssuedAt: now.Format(time.RFC3339Nano), Grants: map[string]string{"key": now.Add(time.Minute).Format(time.RFC3339Nano)}}); err != nil {
		t.Fatal(err)
	}
	store.path = t.TempDir()
	if err := store.Update(&Lease{Revision: 2, IssuedAt: now.Format(time.RFC3339Nano), Grants: map[string]string{}}); err == nil {
		t.Fatal("expected persistence failure")
	}
	if store.Allows("key", now) {
		t.Fatal("persistence failure retained old authorization")
	}
}
