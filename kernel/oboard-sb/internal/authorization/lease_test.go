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
