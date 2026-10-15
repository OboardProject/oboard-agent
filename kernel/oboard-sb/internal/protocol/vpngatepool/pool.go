// SPDX-License-Identifier: GPL-3.0-or-later

package vpngatepool

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/OboardProject/oboard-agent/kernel/oboard-sb/internal/boxnet/common/dialer"
	"github.com/OboardProject/oboard-agent/kernel/oboard-sb/internal/protocol/openvpn"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/log"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

// ErrNoHealthyMember is returned when the pool cannot carry traffic. The
// connection fails; it is never sent through another path.
var ErrNoHealthyMember = errors.New("vpngate exit has no healthy server; refusing to route outside the pool")

const (
	connectTimeout      = 20 * time.Second
	healthProbeTimeout  = 5 * time.Second
	healthFailureLimit  = 2
	passiveFailureLimit = 3
	passiveWindow       = 10 * time.Second
	activeWaitTimeout   = 5 * time.Second
	drainPeriod         = 5 * time.Minute
	minBackoff          = 15 * time.Second
	maxBackoff          = 10 * time.Minute
	maxErrorLength      = 256
)

var memberIDPattern = regexp.MustCompile(`^[A-Za-z0-9._:-]{1,64}$`)

// healthTargets are fixed anycast endpoints reached through the tunnel; a
// successful TCP handshake proves the session forwards traffic end to end.
var healthTargets = []M.Socksaddr{
	M.ParseSocksaddrHostPort("1.1.1.1", 443),
	M.ParseSocksaddrHostPort("8.8.8.8", 443),
}

// Member is one OpenVPN server in the pool.
type Member struct {
	ID string `json:"member_id"`
	openvpn.Spec
}

type session interface {
	DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error)
	ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error)
	Done() <-chan struct{}
	Alive() bool
	Close() error
	HandshakeDuration() time.Duration
}

type connectFunc func(ctx context.Context, spec openvpn.Spec) (session, error)

const (
	stateIdle       = "idle"
	stateConnecting = "connecting"
	stateUp         = "up"
	stateCooldown   = "cooldown"
)

type memberState struct {
	member         Member
	digest         string
	state          string
	session        session
	failures       int
	healthFailures int
	passive        []time.Time
	nextAttempt    time.Time
	lastError      string
	handshake      time.Duration
	rtt            time.Duration
	lastChange     time.Time
}

type drainingSession struct {
	session session
	until   time.Time
}

// Pool is the vpngate-pool outbound.
type Pool struct {
	outbound.Adapter
	logger         log.ContextLogger
	connect        connectFunc
	poolID         int64
	hotStandby     int
	healthInterval time.Duration

	mu       sync.Mutex
	revision int64
	digest   string
	members  []*memberState
	activeID string
	draining []drainingSession
	changed  chan struct{}
	wake     chan struct{}

	ctx    context.Context
	cancel context.CancelFunc
	closed sync.Once
}

var _ adapter.Outbound = (*Pool)(nil)

func RegisterOutbound(registry *outbound.Registry) {
	outbound.Register[OutboundOptions](registry, Type, NewOutbound)
}

func NewOutbound(ctx context.Context, _ adapter.Router, logger log.ContextLogger, tag string, options OutboundOptions) (adapter.Outbound, error) {
	if err := options.normalize(tag); err != nil {
		return nil, err
	}
	underlay, err := dialer.New(ctx, options.DialerOptions, false)
	if err != nil {
		return nil, err
	}
	connect := func(ctx context.Context, spec openvpn.Spec) (session, error) {
		return openvpn.Connect(ctx, underlay, spec, logger)
	}
	pool := newPool(tag, options, logger, connect)
	register(pool)
	return pool, nil
}

func newPool(tag string, options OutboundOptions, logger log.ContextLogger, connect connectFunc) *Pool {
	ctx, cancel := context.WithCancel(context.Background())
	pool := &Pool{
		Adapter:        outbound.NewAdapter(Type, tag, []string{N.NetworkTCP, N.NetworkUDP}, nil),
		logger:         logger,
		connect:        connect,
		poolID:         options.PoolID,
		hotStandby:     *options.HotStandby,
		healthInterval: time.Duration(options.HealthIntervalSeconds) * time.Second,
		changed:        make(chan struct{}),
		wake:           make(chan struct{}, 1),
		ctx:            ctx,
		cancel:         cancel,
	}
	go pool.maintain()
	go pool.healthLoop()
	return pool
}

// Close stops every session the pool owns.
func (p *Pool) Close() error {
	p.closed.Do(func() {
		unregister(p)
		p.cancel()
		p.mu.Lock()
		for _, member := range p.members {
			if member.session != nil {
				_ = member.session.Close()
				member.session = nil
			}
		}
		for _, drain := range p.draining {
			_ = drain.session.Close()
		}
		p.draining = nil
		p.mu.Unlock()
	})
	return nil
}

// DialContext dials through the active member. It never falls back to a
// path outside the pool.
func (p *Pool) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	network = N.NetworkName(network)
	if network != N.NetworkTCP && network != N.NetworkUDP {
		return nil, os.ErrInvalid
	}
	var lastErr error
	for attempt := 0; attempt < 2; attempt++ {
		id, sess, err := p.activeSession(ctx)
		if err != nil {
			return nil, err
		}
		conn, err := sess.DialContext(ctx, network, destination)
		if err == nil {
			return conn, nil
		}
		lastErr = err
		if !p.recordDialFailure(id, sess, err) {
			return nil, err
		}
	}
	return nil, lastErr
}

func (p *Pool) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	_, sess, err := p.activeSession(ctx)
	if err != nil {
		return nil, err
	}
	return sess.ListenPacket(ctx, destination)
}

// activeSession returns the session new connections should use. The current
// active member is kept while it stays up, so a recovered higher-priority
// member does not move traffic around.
func (p *Pool) activeSession(ctx context.Context) (string, session, error) {
	deadline := time.NewTimer(activeWaitTimeout)
	defer deadline.Stop()
	for {
		p.mu.Lock()
		id, sess := p.selectActiveLocked()
		changed := p.changed
		connecting := p.anyConnectingLocked()
		p.mu.Unlock()
		if sess != nil {
			return id, sess, nil
		}
		p.kick()
		if !connecting {
			return "", nil, ErrNoHealthyMember
		}
		select {
		case <-changed:
		case <-deadline.C:
			return "", nil, ErrNoHealthyMember
		case <-ctx.Done():
			return "", nil, ctx.Err()
		}
	}
}

func (p *Pool) selectActiveLocked() (string, session) {
	if p.activeID != "" {
		for _, member := range p.members {
			if member.member.ID == p.activeID && member.state == stateUp && member.session != nil && member.session.Alive() {
				return member.member.ID, member.session
			}
		}
	}
	for _, member := range p.members {
		if member.state == stateUp && member.session != nil && member.session.Alive() {
			if p.activeID != member.member.ID {
				p.activeID = member.member.ID
				p.logInfo("vpngate pool ", p.Tag(), " active member is now ", member.member.ID)
			}
			return member.member.ID, member.session
		}
	}
	p.activeID = ""
	return "", nil
}

func (p *Pool) anyConnectingLocked() bool {
	for _, member := range p.members {
		if member.state == stateConnecting {
			return true
		}
	}
	return false
}

// recordDialFailure counts failures that point at the tunnel rather than the
// destination and reports whether the dial should be retried on another member.
func (p *Pool) recordDialFailure(id string, sess session, err error) bool {
	if errors.Is(err, openvpn.ErrIPv6Unsupported) {
		return false
	}
	tunnelFault := !sess.Alive() || errors.Is(err, openvpn.ErrTunnelClosed) || errors.Is(err, context.DeadlineExceeded) || isTimeout(err)
	if !tunnelFault {
		return false
	}
	now := time.Now()
	p.mu.Lock()
	defer p.mu.Unlock()
	member := p.memberLocked(id)
	if member == nil || member.session != sess {
		return true
	}
	if !sess.Alive() {
		p.markDownLocked(member, "tunnel closed")
		return true
	}
	kept := member.passive[:0]
	for _, at := range member.passive {
		if now.Sub(at) <= passiveWindow {
			kept = append(kept, at)
		}
	}
	member.passive = append(kept, now)
	if len(member.passive) >= passiveFailureLimit {
		p.markDownLocked(member, "repeated dial timeouts")
		return true
	}
	return false
}

func isTimeout(err error) bool {
	var netErr net.Error
	return errors.As(err, &netErr) && netErr.Timeout()
}

func (p *Pool) memberLocked(id string) *memberState {
	for _, member := range p.members {
		if member.member.ID == id {
			return member
		}
	}
	return nil
}

func (p *Pool) markDownLocked(member *memberState, reason string) {
	if member.session != nil {
		_ = member.session.Close()
		member.session = nil
	}
	member.failures++
	member.healthFailures = 0
	member.passive = nil
	member.state = stateCooldown
	member.lastError = boundError(reason)
	member.nextAttempt = time.Now().Add(backoff(member.failures))
	member.lastChange = time.Now()
	if p.activeID == member.member.ID {
		p.activeID = ""
	}
	p.logInfo("vpngate pool ", p.Tag(), " member ", member.member.ID, " is down: ", reason)
	p.broadcastLocked()
	p.kick()
}

func backoff(failures int) time.Duration {
	if failures <= 0 {
		return minBackoff
	}
	delay := minBackoff
	for i := 1; i < failures && delay < maxBackoff; i++ {
		delay *= 2
	}
	if delay > maxBackoff {
		delay = maxBackoff
	}
	return delay
}

func (p *Pool) broadcastLocked() {
	close(p.changed)
	p.changed = make(chan struct{})
}

func (p *Pool) kick() {
	select {
	case p.wake <- struct{}{}:
	default:
	}
}

// maintain keeps the active member plus hot standbys connected, in order.
func (p *Pool) maintain() {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		p.reconcile()
		select {
		case <-p.ctx.Done():
			return
		case <-ticker.C:
		case <-p.wake:
		}
	}
}

func (p *Pool) reconcile() {
	now := time.Now()
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.ctx.Err() != nil {
		return
	}
	kept := p.draining[:0]
	for _, drain := range p.draining {
		if now.After(drain.until) || !drain.session.Alive() {
			_ = drain.session.Close()
			continue
		}
		kept = append(kept, drain)
	}
	p.draining = kept

	desired := 1 + p.hotStandby
	if desired > len(p.members) {
		desired = len(p.members)
	}
	live := 0
	for _, member := range p.members {
		if member.state == stateUp && member.session != nil && !member.session.Alive() {
			p.markDownLocked(member, "tunnel closed")
		}
		if member.state == stateUp || member.state == stateConnecting {
			live++
		}
	}
	for _, member := range p.members {
		if live >= desired {
			break
		}
		if member.state == stateUp || member.state == stateConnecting {
			continue
		}
		if member.state == stateCooldown && now.Before(member.nextAttempt) {
			continue
		}
		member.state = stateConnecting
		member.lastChange = now
		live++
		go p.connectMember(member.member.ID, member.digest, member.member.Spec)
	}
	// Trim surplus sessions from the bottom of the order, never the active one.
	if live > desired {
		for i := len(p.members) - 1; i >= 0 && live > desired; i-- {
			member := p.members[i]
			if member.state != stateUp || member.member.ID == p.activeID {
				continue
			}
			_ = member.session.Close()
			member.session = nil
			member.state = stateIdle
			member.lastChange = now
			live--
		}
	}
}

func (p *Pool) connectMember(id, digest string, spec openvpn.Spec) {
	ctx, cancel := context.WithTimeout(p.ctx, connectTimeout)
	sess, err := p.connect(ctx, spec)
	cancel()
	p.mu.Lock()
	defer p.mu.Unlock()
	member := p.memberLocked(id)
	if member == nil || member.digest != digest || member.state != stateConnecting || p.ctx.Err() != nil {
		if sess != nil {
			_ = sess.Close()
		}
		return
	}
	if err != nil {
		member.failures++
		member.state = stateCooldown
		member.lastError = boundError(err.Error())
		member.nextAttempt = time.Now().Add(backoff(member.failures))
		member.lastChange = time.Now()
		p.broadcastLocked()
		p.kick()
		return
	}
	member.session = sess
	member.state = stateUp
	member.handshake = sess.HandshakeDuration()
	member.healthFailures = 0
	member.passive = nil
	member.lastError = ""
	member.lastChange = time.Now()
	p.broadcastLocked()
	go func() {
		select {
		case <-sess.Done():
			p.mu.Lock()
			if current := p.memberLocked(id); current != nil && current.session == sess {
				p.markDownLocked(current, "tunnel closed")
			}
			p.mu.Unlock()
		case <-p.ctx.Done():
		}
	}()
}

func (p *Pool) healthLoop() {
	ticker := time.NewTicker(p.healthInterval)
	defer ticker.Stop()
	for {
		select {
		case <-p.ctx.Done():
			return
		case <-ticker.C:
		}
		type probe struct {
			id      string
			session session
		}
		var probes []probe
		p.mu.Lock()
		for _, member := range p.members {
			if member.state == stateUp && member.session != nil {
				probes = append(probes, probe{member.member.ID, member.session})
			}
		}
		p.mu.Unlock()
		var wg sync.WaitGroup
		for _, item := range probes {
			wg.Add(1)
			go func(item probe) {
				defer wg.Done()
				rtt, err := checkSession(p.ctx, item.session)
				p.mu.Lock()
				defer p.mu.Unlock()
				member := p.memberLocked(item.id)
				if member == nil || member.session != item.session {
					return
				}
				if err == nil {
					member.healthFailures = 0
					member.rtt = rtt
					return
				}
				member.healthFailures++
				member.lastError = boundError(err.Error())
				if member.healthFailures >= healthFailureLimit {
					p.markDownLocked(member, "health check failed")
				}
			}(item)
		}
		wg.Wait()
	}
}

func checkSession(ctx context.Context, sess session) (time.Duration, error) {
	var lastErr error
	for _, target := range healthTargets {
		probeCtx, cancel := context.WithTimeout(ctx, healthProbeTimeout)
		started := time.Now()
		conn, err := sess.DialContext(probeCtx, N.NetworkTCP, target)
		cancel()
		if err == nil {
			_ = conn.Close()
			return time.Since(started), nil
		}
		lastErr = err
	}
	return 0, lastErr
}

// MembersUpdate replaces the pool membership.
type MembersUpdate struct {
	Revision   int64    `json:"revision"`
	Digest     string   `json:"content_digest"`
	HotStandby *int     `json:"hot_standby,omitempty"`
	Members    []Member `json:"members"`
}

// ErrRevisionConflict reports a same-revision update with different content.
var ErrRevisionConflict = errors.New("vpngate pool revision conflict")

// ErrStaleRevision reports an update older than the applied one.
var ErrStaleRevision = errors.New("vpngate pool revision is older than the applied revision")

// MembersDigest is the canonical content identity of a member list.
func MembersDigest(members []Member) string {
	encoded, _ := json.Marshal(members)
	sum := sha256.Sum256(encoded)
	return hex.EncodeToString(sum[:])
}

// SetMembers validates and applies a membership update. Members that keep the
// same ID and content keep their sessions; removed sessions drain for a while
// so existing connections are not cut.
func (p *Pool) SetMembers(update MembersUpdate) error {
	if update.Revision <= 0 {
		return fmt.Errorf("revision must be positive")
	}
	if len(update.Members) > MaxMembers {
		return fmt.Errorf("a pool accepts at most %d members", MaxMembers)
	}
	if update.HotStandby != nil && (*update.HotStandby < 0 || *update.HotStandby > maxHotStandby) {
		return fmt.Errorf("hot_standby must be between 0 and %d", maxHotStandby)
	}
	seen := map[string]bool{}
	digests := make([]string, len(update.Members))
	for i := range update.Members {
		member := &update.Members[i]
		if !memberIDPattern.MatchString(member.ID) {
			return fmt.Errorf("member %d has an invalid member_id", i)
		}
		if seen[member.ID] {
			return fmt.Errorf("duplicate member_id %s", member.ID)
		}
		seen[member.ID] = true
		if err := member.Spec.Normalize(); err != nil {
			return fmt.Errorf("member %s: %w", member.ID, err)
		}
		digests[i] = MembersDigest([]Member{*member})
	}
	// Controller assigns the content identity that binds this revision; the
	// local digest is only used when none is supplied.
	digest := strings.TrimSpace(update.Digest)
	if digest == "" {
		digest = MembersDigest(update.Members)
	}
	if len(digest) > 128 {
		return fmt.Errorf("content_digest is too long")
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if update.Revision < p.revision {
		return ErrStaleRevision
	}
	if update.Revision == p.revision {
		if digest == p.digest {
			return nil
		}
		return ErrRevisionConflict
	}
	existing := map[string]*memberState{}
	for _, member := range p.members {
		existing[member.member.ID] = member
	}
	next := make([]*memberState, 0, len(update.Members))
	now := time.Now()
	for i, member := range update.Members {
		if current, ok := existing[member.ID]; ok && current.digest == digests[i] {
			next = append(next, current)
			delete(existing, member.ID)
			continue
		}
		next = append(next, &memberState{member: member, digest: digests[i], state: stateIdle, lastChange: now})
	}
	for _, removed := range existing {
		if removed.session != nil {
			p.draining = append(p.draining, drainingSession{session: removed.session, until: now.Add(drainPeriod)})
			removed.session = nil
		}
		removed.state = stateIdle
		if p.activeID == removed.member.ID {
			p.activeID = ""
		}
	}
	p.members = next
	if update.HotStandby != nil {
		p.hotStandby = *update.HotStandby
	}
	p.revision = update.Revision
	p.digest = digest
	p.broadcastLocked()
	p.kick()
	return nil
}

// MemberStatus is the externally visible state of one member.
type MemberStatus struct {
	ID          string `json:"member_id"`
	State       string `json:"state"`
	Active      bool   `json:"active"`
	Failures    int    `json:"failures"`
	LastError   string `json:"last_error,omitempty"`
	HandshakeMS int64  `json:"handshake_ms,omitempty"`
	RTTMS       int64  `json:"rtt_ms,omitempty"`
	LastChange  string `json:"last_change,omitempty"`
}

// Status is the externally visible state of the pool. It never contains
// certificates, keys, or credentials.
type Status struct {
	Tag          string         `json:"tag"`
	PoolID       int64          `json:"pool_id"`
	Revision     int64          `json:"revision"`
	Digest       string         `json:"content_digest"`
	ActiveMember string         `json:"active_member,omitempty"`
	Healthy      int            `json:"healthy"`
	Members      []MemberStatus `json:"members"`
}

func (p *Pool) Status() Status {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.selectActiveLocked()
	status := Status{Tag: p.Tag(), PoolID: p.poolID, Revision: p.revision, Digest: p.digest, ActiveMember: p.activeID, Members: []MemberStatus{}}
	for _, member := range p.members {
		item := MemberStatus{
			ID:          member.member.ID,
			State:       member.state,
			Active:      member.member.ID == p.activeID,
			Failures:    member.failures,
			LastError:   member.lastError,
			HandshakeMS: member.handshake.Milliseconds(),
			RTTMS:       member.rtt.Milliseconds(),
		}
		if !member.lastChange.IsZero() {
			item.LastChange = member.lastChange.UTC().Format(time.RFC3339)
		}
		if member.state == stateUp {
			status.Healthy++
		}
		status.Members = append(status.Members, item)
	}
	return status
}

func (p *Pool) logInfo(args ...any) {
	if p.logger != nil {
		p.logger.Info(args...)
	}
}

func boundError(message string) string {
	if len(message) > maxErrorLength {
		return message[:maxErrorLength]
	}
	return message
}

var (
	registryMu sync.Mutex
	registry   = map[string]*Pool{}
)

func register(pool *Pool) {
	registryMu.Lock()
	registry[pool.Tag()] = pool
	registryMu.Unlock()
}

func unregister(pool *Pool) {
	registryMu.Lock()
	if registry[pool.Tag()] == pool {
		delete(registry, pool.Tag())
	}
	registryMu.Unlock()
}

// Lookup returns the running pool with this tag.
func Lookup(tag string) (*Pool, bool) {
	registryMu.Lock()
	defer registryMu.Unlock()
	pool, ok := registry[tag]
	return pool, ok
}

// Snapshot returns the status of every running pool, ordered by tag.
func Snapshot() []Status {
	registryMu.Lock()
	pools := make([]*Pool, 0, len(registry))
	for _, pool := range registry {
		pools = append(pools, pool)
	}
	registryMu.Unlock()
	sort.Slice(pools, func(i, j int) bool { return pools[i].Tag() < pools[j].Tag() })
	result := make([]Status, 0, len(pools))
	for _, pool := range pools {
		result = append(result, pool.Status())
	}
	return result
}
