// SPDX-License-Identifier: GPL-3.0-or-later

// Package multipsk owns bounded authentication resources shared by all Snell
// listeners. It never resolves or connects to a proxy destination.
package multipsk

import (
	"context"
	"crypto/cipher"
	"crypto/sha256"
	"errors"
	"net"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	snell "github.com/sagernet/sing-snell"
)

const (
	MaxCredentials     = 64
	HandshakeTimeout   = 5 * time.Second
	MaxPending         = 512
	MaxListenerPending = 256
	MaxFirstHeader     = 16 + 128 + 128 + snell.HeaderCipherLen
)

var (
	ErrBudget     = errors.New("snell authentication budget exhausted")
	ErrCredential = errors.New("snell credential rejected")
	ErrDuplicate  = errors.New("snell_duplicate_psk")
	ErrCapacity   = errors.New("snell_credential_limit_exceeded")
	ErrReplay     = errors.New("snell replay rejected")
)

type User struct {
	Name string
	PSK  []byte
}
type Credential struct {
	User
	ID [32]byte
}
type Snapshot struct{ Users []*Credential }
type AdmitFunc func(context.Context, string, net.Conn) (context.Context, error)
type releaseKey struct{}

func WithRelease(ctx context.Context, release func()) context.Context {
	var once sync.Once
	return context.WithValue(ctx, releaseKey{}, func() { once.Do(release) })
}
func Release(ctx context.Context) {
	if fn, ok := ctx.Value(releaseKey{}).(func()); ok {
		fn()
	}
}

type Metrics struct {
	Success, Failure, Timeout, BudgetRejected, Attempts, CacheHit, QueueNanos atomic.Uint64
	ActiveCredentials, Pending                                                atomic.Int64
}
type hint struct {
	ids     [][32]byte
	expires time.Time
}
type scheduler struct {
	pending chan struct{}
	work    chan struct{}
	once    sync.Once
}

// Go 1.26's default GOMAXPROCS follows the effective cgroup CPU quota.
var process = scheduler{pending: make(chan struct{}, MaxPending)}
var replay = struct {
	sync.Mutex
	entries map[[32]byte]time.Time
}{entries: make(map[[32]byte]time.Time)}

type Manager struct {
	snapshot  atomic.Pointer[Snapshot]
	mu        sync.Mutex
	hints     map[string]hint
	pending   chan struct{}
	admit     AdmitFunc
	namespace string
	Metrics   Metrics
}

func New(namespace string, admit AdmitFunc) *Manager {
	m := &Manager{namespace: namespace, admit: admit, hints: map[string]hint{}, pending: make(chan struct{}, MaxListenerPending)}
	m.snapshot.Store(&Snapshot{})
	return m
}
func (m *Manager) Update(users []User, minLength int) error {
	if len(users) > MaxCredentials {
		return ErrCapacity
	}
	s := &Snapshot{}
	names, keys := map[string]bool{}, map[string]bool{}
	for _, u := range users {
		if u.Name == "" || strings.TrimSpace(u.Name) != u.Name || len(u.Name) > 256 || len(u.PSK) < minLength || len(u.PSK) > 255 || names[u.Name] {
			return ErrCredential
		}
		if keys[string(u.PSK)] {
			return ErrDuplicate
		}
		names[u.Name], keys[string(u.PSK)] = true, true
		u.PSK = append([]byte(nil), u.PSK...)
		s.Users = append(s.Users, &Credential{User: u, ID: sha256.Sum256([]byte(m.namespace + "\x00" + u.Name + "\x00" + string(u.PSK)))})
	}
	m.snapshot.Store(s)
	m.Metrics.ActiveCredentials.Store(int64(len(users)))
	return nil
}
func (m *Manager) Current(c *Credential) bool {
	for _, u := range m.snapshot.Load().Users {
		if u.ID == c.ID {
			return true
		}
	}
	return false
}
func (m *Manager) Admit(ctx context.Context, c *Credential, conn net.Conn) (context.Context, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if !m.Current(c) {
		return nil, ErrCredential
	}
	if m.admit == nil {
		return ctx, nil
	}
	admitted, err := m.admit(ctx, c.Name, conn)
	if err != nil {
		return nil, err
	}
	if !m.Current(c) {
		Release(admitted)
		return nil, ErrCredential
	}
	return admitted, nil
}
func (m *Manager) Candidates(source string) []*Credential {
	users := append([]*Credential(nil), m.snapshot.Load().Users...)
	m.mu.Lock()
	h := m.hints[source]
	m.mu.Unlock()
	if time.Now().Before(h.expires) {
		ordered := make([]*Credential, 0, len(users))
		for _, id := range h.ids {
			for _, u := range users {
				if u.ID == id {
					ordered = append(ordered, u)
				}
			}
		}
		if len(ordered) > 0 {
			m.Metrics.CacheHit.Add(1)
		}
		for _, u := range users {
			found := false
			for _, v := range ordered {
				if u.ID == v.ID {
					found = true
					break
				}
			}
			if !found {
				ordered = append(ordered, u)
			}
		}
		return ordered
	}
	return users
}
func (m *Manager) Remember(source string, c *Credential) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.hints) >= 1024 {
		for k, h := range m.hints {
			if time.Now().After(h.expires) {
				delete(m.hints, k)
			}
		}
		if len(m.hints) >= 1024 {
			for k := range m.hints {
				delete(m.hints, k)
				break
			}
		}
	}
	h := m.hints[source]
	ids := [][32]byte{c.ID}
	for _, id := range h.ids {
		if id != c.ID && len(ids) < 4 {
			ids = append(ids, id)
		}
	}
	m.hints[source] = hint{ids: ids, expires: time.Now().Add(5 * time.Minute)}
}
func (m *Manager) Begin(ctx context.Context, conn net.Conn) (context.Context, func(bool), error) {
	if err := ctx.Err(); err != nil {
		return nil, nil, err
	}
	reject := func() (context.Context, func(bool), error) {
		m.Metrics.BudgetRejected.Add(1)
		return nil, nil, ErrBudget
	}
	select {
	case process.pending <- struct{}{}:
	default:
		return reject()
	}
	select {
	case m.pending <- struct{}{}:
	default:
		<-process.pending
		return reject()
	}
	ctx, cancel := context.WithTimeout(ctx, HandshakeTimeout)
	deadline, _ := ctx.Deadline()
	if err := conn.SetDeadline(deadline); err != nil {
		cancel()
		<-m.pending
		<-process.pending
		return nil, nil, err
	}
	// Interrupt socket reads on parent cancellation as well as on the deadline.
	interrupted := make(chan struct{})
	stop := context.AfterFunc(ctx, func() {
		_ = conn.SetDeadline(time.Now())
		close(interrupted)
	})
	m.Metrics.Pending.Add(1)
	var once sync.Once
	return ctx, func(success bool) {
		once.Do(func() {
			if success {
				m.Metrics.Success.Add(1)
			} else if ctx.Err() != nil || !time.Now().Before(deadline) {
				m.Metrics.Timeout.Add(1)
			} else {
				m.Metrics.Failure.Add(1)
			}
			if !stop() {
				<-interrupted
			}
			cancel()
			_ = conn.SetDeadline(time.Time{})
			m.Metrics.Pending.Add(-1)
			<-m.pending
			<-process.pending
		})
	}, nil
}
func (m *Manager) Derive(ctx context.Context, c *Credential, salt []byte) (cipher.AEAD, error) {
	// Only complete candidate headers reach this queue. Pending handshake slots
	// bound its size; idle sockets never hold a CPU slot. Yield between candidates
	// so a cold 64-PSK search cannot monopolize a worker.
	process.once.Do(func() { process.work = make(chan struct{}, max(1, min(8, runtime.GOMAXPROCS(0)))) })
	start := time.Now()
	select {
	case process.work <- struct{}{}:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	defer func() { <-process.work }()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	m.Metrics.QueueNanos.Add(uint64(time.Since(start)))
	m.Metrics.Attempts.Add(1)
	key := snell.DeriveKey(c.PSK, salt)
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return snell.NewAEAD(key)
}
func CheckReplay(c *Credential, salt []byte) error {
	key := sha256.Sum256(append(append([]byte(nil), c.ID[:]...), salt...))
	replay.Lock()
	defer replay.Unlock()
	now := time.Now()
	if expiry, ok := replay.entries[key]; ok && now.Before(expiry) {
		return ErrReplay
	}
	if len(replay.entries) >= 65536 {
		for k, expiry := range replay.entries {
			if !now.Before(expiry) {
				delete(replay.entries, k)
			}
		}
		if len(replay.entries) >= 65536 {
			return ErrBudget
		}
	}
	replay.entries[key] = now.Add(10 * time.Minute)
	return nil
}
