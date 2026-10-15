package vpngatepool

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/OboardProject/oboard-agent/kernel/oboard-sb/internal/protocol/openvpn"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

type fakeSession struct {
	server  string
	done    chan struct{}
	once    sync.Once
	mu      sync.Mutex
	dialErr error
	dials   int
}

func newFakeSession(server string) *fakeSession {
	return &fakeSession{server: server, done: make(chan struct{})}
}

func (s *fakeSession) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.dials++
	if !s.Alive() {
		return nil, openvpn.ErrTunnelClosed
	}
	if s.dialErr != nil {
		return nil, s.dialErr
	}
	client, server := net.Pipe()
	_ = server.Close()
	return client, nil
}

func (s *fakeSession) ListenPacket(context.Context, M.Socksaddr) (net.PacketConn, error) {
	return nil, errors.New("not implemented")
}

func (s *fakeSession) Done() <-chan struct{} { return s.done }

func (s *fakeSession) Alive() bool {
	select {
	case <-s.done:
		return false
	default:
		return true
	}
}

func (s *fakeSession) Close() error {
	s.once.Do(func() { close(s.done) })
	return nil
}

func (s *fakeSession) HandshakeDuration() time.Duration { return 10 * time.Millisecond }

type fakeConnector struct {
	mu       sync.Mutex
	sessions map[string][]*fakeSession
	refuse   map[string]bool
}

func newFakeConnector() *fakeConnector {
	return &fakeConnector{sessions: map[string][]*fakeSession{}, refuse: map[string]bool{}}
}

func (c *fakeConnector) connect(_ context.Context, spec openvpn.Spec) (session, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.refuse[spec.Server] {
		return nil, errors.New("openvpn handshake error: server says: bad auth")
	}
	sess := newFakeSession(spec.Server)
	c.sessions[spec.Server] = append(c.sessions[spec.Server], sess)
	return sess, nil
}

func (c *fakeConnector) latest(server string) *fakeSession {
	c.mu.Lock()
	defer c.mu.Unlock()
	list := c.sessions[server]
	if len(list) == 0 {
		return nil
	}
	return list[len(list)-1]
}

func testMember(t *testing.T, id, server string) Member {
	t.Helper()
	return Member{ID: id, Spec: testSpec(t, server)}
}

func testSpec(t *testing.T, server string) openvpn.Spec {
	t.Helper()
	cert, key := testCertificate(t)
	return openvpn.Spec{Server: server, ServerPort: 443, Network: "tcp", Cipher: "AES-128-CBC", Auth: "SHA1", CA: cert, Cert: cert, Key: key}
}

func testPool(t *testing.T, connector *fakeConnector, hot int) *Pool {
	t.Helper()
	pool := newPool("vpngate-7", OutboundOptions{PoolID: 7, HotStandby: &hot, HealthIntervalSeconds: 60}, nil, connector.connect)
	t.Cleanup(func() { _ = pool.Close() })
	return pool
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

var target = M.ParseSocksaddrHostPort("93.184.216.34", 443)

func TestPoolWithoutMembersRefusesToDial(t *testing.T) {
	pool := testPool(t, newFakeConnector(), 1)
	_, err := pool.DialContext(context.Background(), N.NetworkTCP, target)
	if !errors.Is(err, ErrNoHealthyMember) {
		t.Fatalf("expected ErrNoHealthyMember, got %v", err)
	}
	if _, err := pool.ListenPacket(context.Background(), target); !errors.Is(err, ErrNoHealthyMember) {
		t.Fatalf("expected ErrNoHealthyMember for UDP, got %v", err)
	}
}

func TestPoolKeepsHotStandbyAndFailsOverInOrder(t *testing.T) {
	connector := newFakeConnector()
	pool := testPool(t, connector, 1)
	members := []Member{testMember(t, "a", "1.0.0.1"), testMember(t, "b", "1.0.0.2"), testMember(t, "c", "1.0.0.3")}
	if err := pool.SetMembers(MembersUpdate{Revision: 1, Members: members}); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "two healthy members", func() bool { return pool.Status().Healthy == 2 })
	if connector.latest("1.0.0.3") != nil {
		t.Fatal("third member must stay cold while active plus one standby are up")
	}
	conn, err := pool.DialContext(context.Background(), N.NetworkTCP, target)
	if err != nil {
		t.Fatal(err)
	}
	_ = conn.Close()
	if status := pool.Status(); status.ActiveMember != "a" {
		t.Fatalf("active member = %q, want a", status.ActiveMember)
	}
	_ = connector.latest("1.0.0.1").Close()
	waitFor(t, "failover to b", func() bool { return pool.Status().ActiveMember == "b" })
	conn, err = pool.DialContext(context.Background(), N.NetworkTCP, target)
	if err != nil {
		t.Fatalf("dial after failover: %v", err)
	}
	_ = conn.Close()
	waitFor(t, "cold member promoted to standby", func() bool { return connector.latest("1.0.0.3") != nil })
}

func TestPoolStaysOnRecoveredActiveMember(t *testing.T) {
	connector := newFakeConnector()
	pool := testPool(t, connector, 1)
	if err := pool.SetMembers(MembersUpdate{Revision: 1, Members: []Member{testMember(t, "a", "1.0.0.1"), testMember(t, "b", "1.0.0.2")}}); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "both up", func() bool { return pool.Status().Healthy == 2 })
	pool.Status()
	_ = connector.latest("1.0.0.1").Close()
	waitFor(t, "b active", func() bool { return pool.Status().ActiveMember == "b" })
	pool.mu.Lock()
	for _, member := range pool.members {
		member.nextAttempt = time.Time{}
	}
	pool.mu.Unlock()
	pool.kick()
	waitFor(t, "a reconnected", func() bool { return pool.Status().Healthy == 2 })
	if active := pool.Status().ActiveMember; active != "b" {
		t.Fatalf("active member moved back to %q; it must stay on b while b is healthy", active)
	}
}

func TestPoolRefusesWhenEveryMemberFails(t *testing.T) {
	connector := newFakeConnector()
	connector.refuse["1.0.0.1"] = true
	connector.refuse["1.0.0.2"] = true
	pool := testPool(t, connector, 1)
	if err := pool.SetMembers(MembersUpdate{Revision: 1, Members: []Member{testMember(t, "a", "1.0.0.1"), testMember(t, "b", "1.0.0.2")}}); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "both in cooldown", func() bool {
		status := pool.Status()
		return status.Members[0].State == stateCooldown && status.Members[1].State == stateCooldown
	})
	if _, err := pool.DialContext(context.Background(), N.NetworkTCP, target); !errors.Is(err, ErrNoHealthyMember) {
		t.Fatalf("expected refusal, got %v", err)
	}
	if status := pool.Status(); !strings.Contains(status.Members[0].LastError, "bad auth") {
		t.Fatalf("member error not recorded: %+v", status.Members[0])
	}
}

func TestPoolPassiveTimeoutsMarkMemberDown(t *testing.T) {
	connector := newFakeConnector()
	pool := testPool(t, connector, 1)
	if err := pool.SetMembers(MembersUpdate{Revision: 1, Members: []Member{testMember(t, "a", "1.0.0.1"), testMember(t, "b", "1.0.0.2")}}); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "both up", func() bool { return pool.Status().Healthy == 2 })
	first := connector.latest("1.0.0.1")
	first.mu.Lock()
	first.dialErr = context.DeadlineExceeded
	first.mu.Unlock()
	for i := 0; i < passiveFailureLimit; i++ {
		_, _ = pool.DialContext(context.Background(), N.NetworkTCP, target)
	}
	if first.Alive() {
		t.Fatal("member with repeated dial timeouts must be closed")
	}
	if active := pool.Status().ActiveMember; active != "b" {
		t.Fatalf("active member = %q, want b", active)
	}
}

func TestPoolDestinationErrorsDoNotCountAgainstMember(t *testing.T) {
	connector := newFakeConnector()
	pool := testPool(t, connector, 0)
	if err := pool.SetMembers(MembersUpdate{Revision: 1, Members: []Member{testMember(t, "a", "1.0.0.1")}}); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "up", func() bool { return pool.Status().Healthy == 1 })
	sess := connector.latest("1.0.0.1")
	sess.mu.Lock()
	sess.dialErr = errors.New("connection refused")
	sess.mu.Unlock()
	for i := 0; i < passiveFailureLimit+2; i++ {
		_, _ = pool.DialContext(context.Background(), N.NetworkTCP, target)
	}
	if !sess.Alive() {
		t.Fatal("a refused destination must not take the member down")
	}
}

func TestPoolMembersRevisionGate(t *testing.T) {
	pool := testPool(t, newFakeConnector(), 0)
	members := []Member{testMember(t, "a", "1.0.0.1")}
	if err := pool.SetMembers(MembersUpdate{Revision: 2, Members: members}); err != nil {
		t.Fatal(err)
	}
	if err := pool.SetMembers(MembersUpdate{Revision: 2, Members: members}); err != nil {
		t.Fatalf("identical replay must be idempotent: %v", err)
	}
	if err := pool.SetMembers(MembersUpdate{Revision: 2, Members: []Member{testMember(t, "b", "1.0.0.2")}}); !errors.Is(err, ErrRevisionConflict) {
		t.Fatalf("expected conflict, got %v", err)
	}
	if err := pool.SetMembers(MembersUpdate{Revision: 1, Members: members}); !errors.Is(err, ErrStaleRevision) {
		t.Fatalf("expected stale revision, got %v", err)
	}
	if err := pool.SetMembers(MembersUpdate{Revision: 3, Digest: "controller-identity", Members: members}); err != nil {
		t.Fatal(err)
	}
	if err := pool.SetMembers(MembersUpdate{Revision: 3, Digest: "other-identity", Members: members}); !errors.Is(err, ErrRevisionConflict) {
		t.Fatalf("same revision with another identity must conflict, got %v", err)
	}
}

func TestPoolRemovedMemberDrainsInsteadOfClosing(t *testing.T) {
	connector := newFakeConnector()
	pool := testPool(t, connector, 0)
	if err := pool.SetMembers(MembersUpdate{Revision: 1, Members: []Member{testMember(t, "a", "1.0.0.1")}}); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "a up", func() bool { return pool.Status().Healthy == 1 })
	old := connector.latest("1.0.0.1")
	if err := pool.SetMembers(MembersUpdate{Revision: 2, Members: []Member{testMember(t, "b", "1.0.0.2")}}); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "b active", func() bool { return pool.Status().ActiveMember == "b" })
	if !old.Alive() {
		t.Fatal("removed member's session must drain, not close immediately")
	}
}

func TestPoolStatusNeverCarriesSecrets(t *testing.T) {
	connector := newFakeConnector()
	pool := testPool(t, connector, 0)
	member := testMember(t, "a", "1.0.0.1")
	member.Password = "secret-password"
	if err := pool.SetMembers(MembersUpdate{Revision: 1, Members: []Member{member}}); err != nil {
		t.Fatal(err)
	}
	encoded, _ := json.Marshal(pool.Status())
	for _, forbidden := range []string{"BEGIN", "secret-password", "1.0.0.1"} {
		if strings.Contains(string(encoded), forbidden) {
			t.Fatalf("status leaks %q: %s", forbidden, encoded)
		}
	}
}

func TestOptionsRequireMatchingTag(t *testing.T) {
	options := OutboundOptions{PoolID: 3}
	if err := options.normalize("vpngate-4"); err == nil {
		t.Fatal("pool_id must match the tag")
	}
	options = OutboundOptions{PoolID: 3}
	if err := options.normalize("vpngate-3"); err != nil || *options.HotStandby != defaultHotStandby {
		t.Fatalf("defaults not applied: %v", err)
	}
	options = OutboundOptions{PoolID: 3}
	options.Detour = "direct"
	if err := options.normalize("vpngate-3"); err == nil {
		t.Fatal("detour must be rejected: the pool may not route through another outbound")
	}
}
