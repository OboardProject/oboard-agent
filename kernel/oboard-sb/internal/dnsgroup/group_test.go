package dnsgroup

import (
	"context"
	"crypto/x509"
	"errors"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	mDNS "github.com/miekg/dns"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/dns"
)

type memberStub struct {
	dns.TransportAdapter
	exchange    func(context.Context, *mDNS.Msg) (*mDNS.Msg, error)
	calls       atomic.Int32
	closes      atomic.Int32
	environment []string
}

func (m *memberStub) Exchange(ctx context.Context, q *mDNS.Msg) (*mDNS.Msg, error) {
	m.calls.Add(1)
	return m.exchange(ctx, q)
}
func (m *memberStub) ExchangeAsync(ctx context.Context, q *mDNS.Msg, cb func(*mDNS.Msg, error)) {
	r, e := m.Exchange(ctx, q)
	cb(r, e)
}
func (m *memberStub) Start(adapter.StartStage) error { return nil }
func (m *memberStub) Reset()                         {}
func (m *memberStub) Close() error                   { m.closes.Add(1); return nil }
func (m *memberStub) Environment() []string          { return m.environment }
func stub(tag string, rcode int, err error) *memberStub {
	return &memberStub{TransportAdapter: dns.NewTransportAdapter("test", tag, nil), exchange: func(_ context.Context, q *mDNS.Msg) (*mDNS.Msg, error) {
		if err != nil {
			return nil, err
		}
		r := new(mDNS.Msg).SetReply(q)
		r.Rcode = rcode
		return r, nil
	}}
}
func group(t *testing.T, options Options, members ...adapter.DNSTransport) *Transport {
	t.Helper()
	for _, m := range members {
		options.Members = append(options.Members, m.Tag())
	}
	tr, err := New(context.Background(), nil, "group", options)
	if err != nil {
		t.Fatal(err)
	}
	g := tr.(*Transport)
	g.members = members
	t.Cleanup(func() { g.Close() })
	return g
}
func query() *mDNS.Msg { return new(mDNS.Msg).SetQuestion("service.test.", mDNS.TypeA) }

func TestFailoverResults(t *testing.T) {
	for _, tc := range []struct {
		name    string
		rcode   int
		err     error
		backup  bool
		wantErr bool
	}{
		{"success", mDNS.RcodeSuccess, nil, false, false},
		{"nxdomain", mDNS.RcodeNameError, nil, false, false},
		{"servfail", mDNS.RcodeServerFailure, nil, true, false},
		{"refused", mDNS.RcodeRefused, nil, true, false},
		{"network", 0, errors.New("network down"), true, false},
		{"certificate", 0, x509.UnknownAuthorityError{}, false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a, b := stub("a", tc.rcode, tc.err), stub("b", mDNS.RcodeSuccess, nil)
			g := group(t, Options{}, a, b)
			r, err := g.Exchange(context.Background(), query())
			if (err != nil) != tc.wantErr {
				t.Fatalf("error=%v", err)
			}
			if (b.calls.Load() > 0) != tc.backup {
				t.Fatalf("backup calls=%d", b.calls.Load())
			}
			if err == nil && !tc.backup && r.Rcode != tc.rcode {
				t.Fatalf("rcode=%d", r.Rcode)
			}
		})
	}
}
func TestBudgetLeavesTimeForBackup(t *testing.T) {
	a, b := stub("a", 0, nil), stub("b", 0, nil)
	a.exchange = func(ctx context.Context, _ *mDNS.Msg) (*mDNS.Msg, error) { <-ctx.Done(); return nil, ctx.Err() }
	g := group(t, Options{TimeoutMS: 200}, a, b)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if _, err := g.Exchange(ctx, query()); err != nil {
		t.Fatal(err)
	}
	if b.calls.Load() != 1 {
		t.Fatal("backup was starved of query budget")
	}
}
func TestCloseCancelsAndDoesNotCloseSharedMembers(t *testing.T) {
	a := stub("a", 0, nil)
	entered := make(chan struct{})
	a.exchange = func(ctx context.Context, _ *mDNS.Msg) (*mDNS.Msg, error) {
		close(entered)
		<-ctx.Done()
		return nil, ctx.Err()
	}
	g := group(t, Options{MaxConcurrency: 1}, a)
	done := make(chan error, 1)
	g.ExchangeAsync(context.Background(), query(), func(_ *mDNS.Msg, e error) { done <- e })
	<-entered
	if _, err := g.Exchange(context.Background(), query()); err == nil || !strings.Contains(err.Error(), "concurrency") {
		t.Fatalf("limit: %v", err)
	}
	g.Close()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("expected cancellation")
		}
	case <-time.After(time.Second):
		t.Fatal("query survived Close")
	}
	if a.closes.Load() != 0 {
		t.Fatal("shared member closed")
	}
	if _, err := g.Exchange(context.Background(), query()); err == nil {
		t.Fatal("closed group accepted query")
	}
}
func TestEnvironmentAndPublicAnswers(t *testing.T) {
	a := stub("a", 0, nil)
	a.environment = []string{"eth0:192.0.2.1"}
	g := group(t, Options{PublicAnswersOnly: true}, a)
	if got := strings.Join(g.Environment(), ","); got != "a:eth0:192.0.2.1" {
		t.Fatal(got)
	}
	a.environment = []string{"eth1:192.0.2.2"}
	if !strings.Contains(strings.Join(g.Environment(), ","), "eth1") {
		t.Fatal("stale environment")
	}
	for _, ip := range []string{"127.0.0.1", "10.0.0.1", "::1", "fe80::1", "::ffff:192.168.1.1"} {
		t.Run(ip, func(t *testing.T) {
			a.exchange = func(_ context.Context, q *mDNS.Msg) (*mDNS.Msg, error) {
				r := new(mDNS.Msg).SetReply(q)
				parsed := net.ParseIP(ip)
				if parsed.To4() != nil {
					r.Answer = []mDNS.RR{&mDNS.A{A: parsed}}
				} else {
					r.Answer = []mDNS.RR{&mDNS.AAAA{AAAA: parsed}}
				}
				return r, nil
			}
			if _, err := g.Exchange(context.Background(), query()); err == nil {
				t.Fatal("private answer accepted")
			}
		})
	}
}
func TestExhaustedGroupFailsClosed(t *testing.T) {
	a, b := stub("a", 0, errors.New("down")), stub("b", 0, errors.New("down"))
	g := group(t, Options{}, a, b)
	if _, err := g.Exchange(context.Background(), query()); err == nil {
		t.Fatal("expected failure")
	}
	if a.calls.Load() != 1 || b.calls.Load() != 1 {
		t.Fatal("wrong member attempts")
	}
}
