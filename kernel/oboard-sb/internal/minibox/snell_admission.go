package minibox

import (
	"context"
	"crypto/sha256"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-snell/multipsk"
)

// parentConn is indexed independently of optional connection audit. It remains
// indexed while a Snell reuse session is idle between logical requests.
type parentConn struct {
	net.Conn
	tracker    *RateLimitTracker
	once       sync.Once
	state      *runtimeState
	identity   connectionIdentity
	closed     bool
	authScope  string
	credential [32]byte
}

func (p *parentConn) Close() error {
	err := p.Conn.Close()
	p.once.Do(func() { p.tracker.mu.Lock(); p.closed = true; delete(p.tracker.snellParents, p); p.tracker.mu.Unlock() })
	return err
}
func (t *RateLimitTracker) WrapParent(conn net.Conn) net.Conn {
	return &parentConn{Conn: conn, tracker: t}
}
func (t *RateLimitTracker) Admit(ctx context.Context, inbound, user string, conn net.Conn) (context.Context, error) {
	deadline := time.Now().Add(multipsk.HandshakeTimeout)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	for !t.usersBarrier.TryRLock() {
		remaining := time.Until(deadline)
		if remaining <= 0 {
			return nil, context.DeadlineExceeded
		}
		timer := time.NewTimer(min(5*time.Millisecond, remaining))
		select {
		case <-ctx.Done():
			timer.Stop()
			return nil, ctx.Err()
		case <-timer.C:
		}
	}
	if err := ctx.Err(); err != nil {
		t.usersBarrier.RUnlock()
		return nil, err
	}
	deny := func() (context.Context, error) { t.usersBarrier.RUnlock(); return nil, os.ErrPermission }
	if t.usersFailed.Load() {
		return deny()
	}
	state := t.runtimeFor(adapter.InboundContext{Inbound: inbound, User: user})
	if state == nil || state.loadedPolicy().AuthorizationKey == "" || state.denied() {
		return deny()
	}
	// Obfuscation may wrap the transport; the parent is also carried in context.
	p, _ := ctx.Value(snellParentKey{}).(*parentConn)
	if p == nil {
		p, _ = conn.(*parentConn)
	}
	if p == nil {
		return deny()
	}
	t.mu.Lock()
	scope := inbound + "\x00" + user
	installed, exists := t.snellUsers[scope]
	if !exists || installed.authorizationKey != state.loadedPolicy().AuthorizationKey || p.closed || state.denied() {
		t.mu.Unlock()
		return deny()
	}
	if p.state != nil && (p.state != state || state.authorizationRevokedFor(p.identity)) {
		t.mu.Unlock()
		return deny()
	}
	if p.state != nil && p.credential != installed.credential {
		t.mu.Unlock()
		return deny()
	}
	p.state, p.identity = state, state.identity()
	p.authScope, p.credential = scope, installed.credential
	if t.snellParents == nil {
		t.snellParents = map[*parentConn]struct{}{}
	}
	t.snellParents[p] = struct{}{}
	t.mu.Unlock()
	return multipsk.WithRelease(ctx, t.usersBarrier.RUnlock), nil
}

type snellParentKey struct{}

func (t *RateLimitTracker) ParentContext(ctx context.Context, conn net.Conn) context.Context {
	if p, ok := conn.(*parentConn); ok {
		return context.WithValue(ctx, snellParentKey{}, p)
	}
	return ctx
}
func (t *RateLimitTracker) reapSnellParents(force bool) int {
	t.mu.RLock()
	var closing []*parentConn
	for p := range t.snellParents {
		installed, exists := t.snellUsers[p.authScope]
		if force || !exists || installed.credential != p.credential || p.state.authorizationRevokedFor(p.identity) || p.state.quotaDeniedFor(true) {
			closing = append(closing, p)
		}
	}
	t.mu.RUnlock()
	for _, p := range closing {
		_ = p.Close()
	}
	t.pruneSnellCounters()
	return len(closing)
}

// The published table scopes credential admission to its listener. Counters may
// outlive this table for acknowledged tail traffic; they never confer access.
type snellIdentity struct {
	authorizationKey string
	credential       [32]byte
}

func (t *RateLimitTracker) publishSnellUsers(snapshot *UserSnapshot) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.snellRetired == nil {
		t.snellRetired = map[string]bool{}
	}
	if t.snellUsers == nil {
		t.snellUsers = map[string]snellIdentity{}
	}
	for key := range t.snellUsers {
		for _, tag := range snapshot.Scope {
			if len(key) > len(tag) && key[:len(tag)+1] == tag+"\x00" {
				_, name, _ := strings.Cut(key, "\x00")
				t.snellRetired["user:"+name] = true
				delete(t.snellUsers, key)
				break
			}
		}
	}
	for _, entry := range snapshot.Entries {
		if entry.Credential.PSK != "" {
			delete(t.snellRetired, "user:"+entry.AuthUser)
			t.snellUsers[entry.InboundTag+"\x00"+entry.AuthUser] = snellIdentity{entry.AuthorizationKey, sha256.Sum256([]byte(entry.Credential.PSK))}
		}
	}
}

func (t *RateLimitTracker) pruneSnellCounters() {
	t.mu.Lock()
	defer t.mu.Unlock()
	for key := range t.snellRetired {
		state := t.states[key]
		if state == nil {
			delete(t.snellRetired, key)
			continue
		}
		if len(t.active[key]) > 0 || len(t.activePacket[key]) > 0 {
			continue
		}
		hasParent := false
		for p := range t.snellParents {
			if p.state == state {
				hasParent = true
				break
			}
		}
		if hasParent {
			continue
		}
		c := state.loadedConfig().counters
		if c.upload.Load() != c.acknowledgedUpload.Load() || c.download.Load() != c.acknowledgedDownload.Load() {
			continue
		}
		delete(t.states, key)
		delete(t.snellRetired, key)
	}
}

func (t *RateLimitTracker) CloseSnellInbound(tag string) {
	t.mu.RLock()
	var parents []*parentConn
	for p := range t.snellParents {
		if strings.HasPrefix(p.authScope, tag+"\x00") {
			parents = append(parents, p)
		}
	}
	t.mu.RUnlock()
	for _, p := range parents {
		_ = p.Close()
	}
}
