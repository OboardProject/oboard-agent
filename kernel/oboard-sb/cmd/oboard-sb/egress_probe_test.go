package main

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

type testOutboundEgressDialer struct{ calls atomic.Int32 }

func (d *testOutboundEgressDialer) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	d.calls.Add(1)
	return (&net.Dialer{}).DialContext(ctx, network, destination.String())
}

func (d *testOutboundEgressDialer) ListenPacket(context.Context, M.Socksaddr) (net.PacketConn, error) {
	return nil, errors.New("unused")
}

func TestProbeOutboundEgressIPUsesSelectedDialerAndFallsBack(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/first" {
			http.Error(w, "unavailable", http.StatusServiceUnavailable)
			return
		}
		_, _ = w.Write([]byte("8.8.8.8\n"))
	}))
	defer server.Close()
	dialer := &testOutboundEgressDialer{}
	got, err := probeOutboundEgressIP(context.Background(), dialer, []string{server.URL + "/first", server.URL + "/second"})
	if err != nil || got != "8.8.8.8" {
		t.Fatalf("fallback result = %q, %v", got, err)
	}
	if dialer.calls.Load() == 0 {
		t.Fatal("selected outbound dialer was not used")
	}
}

func TestProbeOutboundEgressIPRejectsRedirects(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/redirect" {
			http.Redirect(w, r, "/ip", http.StatusFound)
			return
		}
		_, _ = w.Write([]byte("8.8.8.8"))
	}))
	defer server.Close()
	if got, err := probeOutboundEgressIP(context.Background(), &testOutboundEgressDialer{}, []string{server.URL + "/redirect"}); err == nil {
		t.Fatalf("redirect returned %q without an error", got)
	}
}

func TestProbeOutboundEgressIPRejectsOversizedAndNonPublicResponses(t *testing.T) {
	for name, body := range map[string]string{
		"oversized":     strings.Repeat("1", 257),
		"invalid":       "not-an-ip",
		"private":       "10.0.0.1",
		"shared":        "100.64.0.1",
		"benchmark":     "198.18.0.1",
		"documentation": "192.0.2.1",
		"ipv6-doc":      "2001:db8::1",
	} {
		t.Run(name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte(body)) }))
			defer server.Close()
			if got, err := probeOutboundEgressIP(context.Background(), &testOutboundEgressDialer{}, []string{server.URL}); err == nil {
				t.Fatalf("response %q returned %q without an error", body, got)
			}
		})
	}
}

func TestOutboundEgressHandlerAllowsOnlyPathStepTags(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("8.8.8.8")) }))
	defer server.Close()
	dialer := &testOutboundEgressDialer{}
	lookups := 0
	handler := newOutboundEgressHandler(func(tag string) (N.Dialer, bool) {
		lookups++
		return dialer, tag == "path-12-step-3"
	}, []string{server.URL})

	bad := httptest.NewRecorder()
	handler.ServeHTTP(bad, httptest.NewRequest(http.MethodPost, "/outbounds/egress-ip", strings.NewReader(`{"outbound_tag":"direct"}`)))
	if bad.Code != http.StatusBadRequest || lookups != 0 {
		t.Fatalf("unprobeable tag response = %d, lookups = %d", bad.Code, lookups)
	}
	good := httptest.NewRecorder()
	handler.ServeHTTP(good, httptest.NewRequest(http.MethodPost, "/outbounds/egress-ip", strings.NewReader(`{"outbound_tag":"path-12-step-3"}`)))
	if good.Code != http.StatusOK || !strings.Contains(good.Body.String(), "8.8.8.8") || lookups != 1 {
		t.Fatalf("path tag response = %d %s, lookups = %d", good.Code, good.Body.String(), lookups)
	}
}
