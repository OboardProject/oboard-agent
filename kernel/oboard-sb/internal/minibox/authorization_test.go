package minibox

import (
	"context"
	"net"
	"path/filepath"
	"testing"
	"time"

	"github.com/OboardProject/oboard-agent/kernel/oboard-sb/internal/authorization"
	"github.com/sagernet/sing-box/adapter"
)

func authorizedQuotaFixture(metadata RuntimeMetadata) *RateLimitTracker {
	now := time.Now().UTC()
	lease := &authorization.Lease{Revision: 1, IssuedAt: now.Format(time.RFC3339Nano), Grants: map[string]string{}}
	for _, entries := range []map[string]RuntimeUserLimit{metadata.RateLimits.Users, metadata.RateLimits.Inbounds} {
		for name, policy := range entries {
			if policy.UserID <= 0 {
				continue
			}
			policy.AuthorizationKey = "quota-fixture-" + name
			entries[name] = policy
			lease.Grants[policy.AuthorizationKey] = now.Add(5 * time.Minute).Format(time.RFC3339Nano)
		}
	}
	metadata.Authorization = lease
	return NewRateLimitTracker(metadata)
}

func TestAuthorizationExpiryClosesConnectionsAndPolicyCannotRegrant(t *testing.T) {
	now := time.Now().UTC()
	lease := &authorization.Lease{Revision: 1, IssuedAt: now.Format(time.RFC3339Nano), Grants: map[string]string{"installed": now.Add(time.Second).Format(time.RFC3339Nano)}}
	tracker := newRateLimitTracker(RuntimeMetadata{Authorization: lease, RateLimits: RuntimeRateLimits{Users: map[string]RuntimeUserLimit{"opaque": {UserID: 7, AuthorizationKey: "installed"}}}}, func() time.Time { return now })
	client, server := net.Pipe()
	defer client.Close()
	wrapped := tracker.RoutedConnection(context.Background(), server, adapter.InboundContext{User: "opaque"}, nil, nil)
	defer wrapped.Close()
	packet := &testPacketConn{}
	udp := tracker.RoutedPacketConnection(context.Background(), packet, adapter.InboundContext{User: "opaque"}, nil, nil)
	defer udp.Close()
	state := tracker.stateForKey("user:opaque")
	if state.deniedForConnection(false) {
		t.Fatal("valid authorization rejected")
	}
	now = now.Add(time.Second)
	tracker.ReapAuthorization()
	if !packet.closed.Load() {
		t.Fatal("expired UDP association remained open")
	}
	if _, err := client.Write([]byte("x")); err == nil {
		t.Fatal("expired TCP connection remained open")
	}
	tracker.UpdatePolicies(map[string]RuntimeUserLimit{"user:7": {UserID: 7, AuthorizationKey: "replacement", CredentialStatus: "active"}})
	if state.loadedPolicy().AuthorizationKey != "installed" || !state.deniedForConnection(true) {
		t.Fatal("quota renewal changed installed authorization")
	}
	if err := tracker.UpdateAuthorization(&authorization.Lease{Revision: 2, IssuedAt: now.Format(time.RFC3339Nano), Grants: map[string]string{"replacement": now.Add(time.Minute).Format(time.RFC3339Nano)}}); err != nil {
		t.Fatal(err)
	}
	if !state.deniedForConnection(false) {
		t.Fatal("lease installed a new credential")
	}
}

func TestMissingAuthorizationFailsClosed(t *testing.T) {
	tracker := NewRateLimitTracker(RuntimeMetadata{RateLimits: RuntimeRateLimits{Users: map[string]RuntimeUserLimit{"old": {UserID: 7}}}})
	if !tracker.stateForKey("user:old").deniedForConnection(false) {
		t.Fatal("legacy credential admitted without authorization")
	}
}

func TestPersistedLeaseDoesNotPermitConfigToOmitAuthorization(t *testing.T) {
	now := time.Now().UTC()
	lease := &authorization.Lease{Revision: 1, IssuedAt: now.Format(time.RFC3339Nano), Grants: map[string]string{"installed": now.Add(time.Minute).Format(time.RFC3339Nano)}}
	path := filepath.Join(t.TempDir(), "kernel-authorization.json")
	if err := authorization.NewStore(path).Update(lease); err != nil {
		t.Fatal(err)
	}
	tracker := NewRateLimitTracker(RuntimeMetadata{RateLimits: RuntimeRateLimits{Users: map[string]RuntimeUserLimit{"opaque": {UserID: 7, AuthorizationKey: "installed"}}}})
	if err := tracker.InitializeAuthorization(path, nil); err == nil {
		t.Fatal("config without authorization reused persisted grants")
	}
}
