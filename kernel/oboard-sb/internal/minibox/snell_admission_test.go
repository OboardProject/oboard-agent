package minibox

import (
	"context"
	"crypto/sha256"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/OboardProject/oboard-agent/kernel/oboard-sb/internal/authorization"
	"github.com/sagernet/sing-snell/multipsk"
)

func TestSnellIdleParentRevokeRotateDeleteAndRejectNew(t *testing.T) {
	for _, operation := range []string{"revoke", "rotate", "delete", "expire", "quota", "reject_new"} {
		t.Run(operation, func(t *testing.T) {
			now := time.Now()
			clockNow := now
			tr := newRateLimitTracker(RuntimeMetadata{}, func() time.Time { return clockNow })
			entry := snellTestEntry("alice", "grant", "independent-psk-for-test", 7)
			tr.ReplaceScopedUsers([]string{"in-1"}, []UserInstallEntry{entry})
			tr.publishSnellUsers(&UserSnapshot{Scope: []string{"in-1"}, Entries: []UserInstallEntry{entry}})
			if err := tr.UpdateAuthorization(&authorization.Lease{Revision: 1, IssuedAt: now.Format(time.RFC3339Nano), Grants: map[string]string{"grant": now.Add(time.Minute).Format(time.RFC3339Nano)}}); err != nil {
				t.Fatal(err)
			}
			peer, raw := net.Pipe()
			defer peer.Close()
			parent := tr.WrapParent(raw)
			defer parent.Close()
			ctx := tr.ParentContext(context.Background(), parent)
			if _, err := tr.Admit(ctx, "in-other", "alice", parent); err == nil {
				t.Fatal("cross-listener policy admitted")
			}
			admitted, err := tr.Admit(ctx, "in-1", "alice", parent)
			if err != nil {
				t.Fatal(err)
			}
			multipsk.Release(admitted)
			state := tr.stateForKey("user:alice")
			switch operation {
			case "revoke":
				_, err = tr.DenyAuthorization([]string{"grant"}, 2)
			case "rotate":
				entry.Credential.PSK = "new-independent-key"
				tr.publishSnellUsers(&UserSnapshot{Scope: []string{"in-1"}, Entries: []UserInstallEntry{entry}})
			case "delete":
				tr.publishSnellUsers(&UserSnapshot{Scope: []string{"in-1"}})
			case "expire":
				clockNow = now.Add(2 * time.Minute)
			case "quota":
				p := state.loadedPolicy()
				p.TrafficLimitBytes = 1
				state.updatePolicy(p)
				state.addTraffic(2, 0)
			case "reject_new":
				p := state.loadedPolicy()
				p.CredentialStatus = "reject_new"
				state.updatePolicy(p)
			}
			if err != nil {
				t.Fatal(err)
			}
			tr.ReapAuthorization()
			tr.reapSnellParents(false)
			tr.mu.RLock()
			remaining := len(tr.snellParents)
			tr.mu.RUnlock()
			if operation == "reject_new" {
				if remaining != 1 {
					t.Fatal("reject_new disconnected admitted flow")
				}
				if next, e := tr.Admit(ctx, "in-1", "alice", parent); e == nil {
					multipsk.Release(next)
					t.Fatal("reuse bypassed reject_new")
				}
				return
			}
			if remaining != 0 {
				t.Fatal("idle parent survived credential invalidation")
			}
			peer.SetReadDeadline(time.Now().Add(time.Second))
			if _, err = peer.Read(make([]byte, 1)); err != io.EOF {
				t.Fatalf("peer was not closed: %v", err)
			}
		})
	}
}
func TestSnellRegisterAndRevokeRace(t *testing.T) {
	for i := 0; i < 100; i++ {
		tr := NewRateLimitTracker(RuntimeMetadata{})
		entry := snellTestEntry("user", "grant", "independent-key", 1)
		tr.ReplaceScopedUsers([]string{"in-1"}, []UserInstallEntry{entry})
		tr.publishSnellUsers(&UserSnapshot{Scope: []string{"in-1"}, Entries: []UserInstallEntry{entry}})
		now := time.Now()
		if err := tr.UpdateAuthorization(&authorization.Lease{Revision: 1, IssuedAt: now.Format(time.RFC3339Nano), Grants: map[string]string{"grant": now.Add(time.Minute).Format(time.RFC3339Nano)}}); err != nil {
			t.Fatal(err)
		}
		a, b := net.Pipe()
		p := tr.WrapParent(b)
		ctx := tr.ParentContext(context.Background(), p)
		var wg sync.WaitGroup
		wg.Add(2)
		go func() {
			defer wg.Done()
			if admitted, err := tr.Admit(ctx, "in-1", "user", p); err == nil {
				multipsk.Release(admitted)
			}
		}()
		go func() {
			defer wg.Done()
			tr.usersBarrier.Lock()
			tr.publishSnellUsers(&UserSnapshot{Scope: []string{"in-1"}})
			tr.reapSnellParents(false)
			tr.usersBarrier.Unlock()
		}()
		wg.Wait()
		tr.mu.RLock()
		n := len(tr.snellParents)
		tr.mu.RUnlock()
		a.Close()
		p.Close()
		if n != 0 {
			t.Fatal("registered after revoke")
		}
	}
}
func TestSnellIdentityDigestIndependentOfArrayOrder(t *testing.T) {
	tr := NewRateLimitTracker(RuntimeMetadata{})
	a := snellTestEntry("a", "grant-a", "key-a-123456", 1)
	b := snellTestEntry("b", "grant-b", "key-b-123456", 2)
	tr.publishSnellUsers(&UserSnapshot{Scope: []string{"in-1"}, Entries: []UserInstallEntry{b, a}})
	if tr.snellUsers["in-1\x00a"].credential != sha256.Sum256([]byte(a.Credential.PSK)) {
		t.Fatal("credential identity changed with order")
	}
}
