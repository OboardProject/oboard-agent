package multipsk

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestManagerUpdatesHintsAndReplayAreConcurrentAndBounded(t *testing.T) {
	m := New(t.Name(), nil)
	users := []User{{Name: "a", PSK: []byte("independent-psk-a")}, {Name: "b", PSK: []byte("independent-psk-b")}}
	if err := m.Update(users, 8); err != nil {
		t.Fatal(err)
	}
	original := m.Candidates("nat")[1]
	m.Remember("nat", original)
	if err := m.Update([]User{users[1], users[0]}, 8); err != nil {
		t.Fatal(err)
	}
	if m.Candidates("nat")[0].Name != "b" {
		t.Fatal("hint used an unstable index")
	}
	for _, invalid := range [][]User{{{Name: " a", PSK: users[0].PSK}}, {{Name: "a", PSK: users[0].PSK}, {Name: "a", PSK: users[1].PSK}}, {{Name: "short", PSK: []byte("x")}}} {
		if err := m.Update(invalid, 8); err == nil {
			t.Fatal("invalid table accepted")
		}
		if !m.Current(original) {
			t.Fatal("failed validation changed live table")
		}
	}
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(worker int) {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				if worker%2 == 0 {
					if err := m.Update(users, 8); err != nil {
						t.Error(err)
					}
				} else {
					c := m.Candidates("nat")
					if len(c) != 2 {
						t.Error("partial table")
					}
					m.Remember(fmt.Sprint(worker, j), c[0])
				}
			}
		}(i)
	}
	wg.Wait()
	for i := 0; i < 2000; i++ {
		m.Remember(fmt.Sprint(i), original)
	}
	if len(m.hints) > 1024 {
		t.Fatal("hint map grew beyond bound")
	}
	var admitted atomic.Int64
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			err := CheckReplay(original, []byte("same-connection-salt"))
			if err == nil {
				admitted.Add(1)
			} else if !errors.Is(err, ErrReplay) {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	if admitted.Load() != 1 {
		t.Fatal("concurrent replay passed")
	}
	if err := m.Update(nil, 8); err != nil {
		t.Fatal(err)
	}
	if m.Current(original) {
		t.Fatal("last user retained")
	}
}
func TestAdmissionRechecksSnapshotAndReleasesGate(t *testing.T) {
	var m *Manager
	var released atomic.Int64
	m = New(t.Name(), func(ctx context.Context, _ string, _ net.Conn) (context.Context, error) {
		if err := m.Update(nil, 8); err != nil {
			t.Fatal(err)
		}
		return WithRelease(ctx, func() { released.Add(1) }), nil
	})
	if err := m.Update([]User{{Name: "a", PSK: []byte("independent-key")}}, 8); err != nil {
		t.Fatal(err)
	}
	credential := m.Candidates("")[0]
	if _, err := m.Admit(context.Background(), credential, nil); !errors.Is(err, ErrCredential) {
		t.Fatal(err)
	}
	if released.Load() != 1 {
		t.Fatal("generation lock leaked on concurrent revoke")
	}
}
func TestAuthenticationPendingCapacityCancellationAndDeadline(t *testing.T) {
	m := New(t.Name(), nil)
	var closers []func()
	for i := 0; i < MaxListenerPending; i++ {
		a, b := net.Pipe()
		_, finish, err := m.Begin(context.Background(), b, fmt.Sprint(i))
		if err != nil {
			t.Fatal(err)
		}
		closers = append(closers, func() { finish(false); a.Close(); b.Close() })
	}
	a, b := net.Pipe()
	if _, _, err := m.Begin(context.Background(), b, "overflow"); !errors.Is(err, ErrBudget) {
		t.Fatal("unbounded pending handshakes")
	}
	a.Close()
	b.Close()
	for _, close := range closers {
		close()
	}
	if m.Metrics.Pending.Load() != 0 {
		t.Fatal("pending resources leaked")
	}
	a, b = net.Pipe()
	defer a.Close()
	defer b.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	handshake, finish, err := m.Begin(ctx, b, "deadline")
	if err != nil {
		t.Fatal(err)
	}
	defer finish(false)
	deadline, _ := handshake.Deadline()
	if time.Until(deadline) > 20*time.Millisecond {
		t.Fatal("parent deadline extended")
	}
	if _, err = b.Read(make([]byte, 1)); err == nil {
		t.Fatal("deadline not applied to socket")
	}
	finish(false)
	if m.Metrics.Pending.Load() != 0 {
		t.Fatal("timeout resources leaked")
	}
}
