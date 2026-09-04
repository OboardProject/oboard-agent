package agent

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

// A deleted or re-enrolled node keeps its old token and its own report timers.
// Without a shared backoff the HTTP callbacks kept posting on those timers
// forever, so the Controller spent a credential lookup per attempt on an
// identity that no longer exists.
func TestControllerRejectionPausesAuthenticatedCallbacks(t *testing.T) {
	for name, status := range map[string]int{
		"unauthorized":      http.StatusUnauthorized,
		"forbidden":         http.StatusForbidden,
		"too many requests": http.StatusTooManyRequests,
	} {
		t.Run(name, func(t *testing.T) {
			var requests atomic.Int64
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
				requests.Add(1)
				http.Error(w, "rejected", status)
			}))
			defer server.Close()
			runner := New(Config{ControllerURL: server.URL, AgentID: "agent-1", AgentToken: "stale", StateDir: t.TempDir()})
			ctx := context.Background()
			if err := runner.postControllerJSON(ctx, "/api/v1/agent/traffic-reports", map[string]any{}, nil, true); err == nil {
				t.Fatal("a rejected identity must surface as an error")
			}
			for i := 0; i < 5; i++ {
				if err := runner.postControllerJSON(ctx, "/api/v1/agent/traffic-reports", map[string]any{}, nil, true); err == nil {
					t.Fatal("callbacks resumed while the identity is still rejected")
				}
			}
			if got := requests.Load(); got != 1 {
				t.Fatalf("controller received %d requests, want only the one that established the rejection", got)
			}
		})
	}
}

// Unauthenticated calls (enrollment) are never gated, and a successful
// authenticated call releases the pause.
func TestControllerAuthBackoffScopeAndRelease(t *testing.T) {
	var requests atomic.Int64
	reject := atomic.Bool{}
	reject.Store(true)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		requests.Add(1)
		if reject.Load() && req.Header.Get("X-Agent-ID") != "" {
			http.Error(w, "rejected", http.StatusUnauthorized)
			return
		}
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer server.Close()
	runner := New(Config{ControllerURL: server.URL, AgentID: "agent-1", AgentToken: "stale", StateDir: t.TempDir()})
	ctx := context.Background()
	_ = runner.postControllerJSON(ctx, "/api/v1/agent/traffic-reports", map[string]any{}, nil, true)
	before := requests.Load()
	if err := runner.postControllerJSON(ctx, "/api/v1/agent/enroll", map[string]any{}, nil, false); err != nil {
		t.Fatalf("enrollment must not be gated by an agent-identity rejection: %v", err)
	}
	if requests.Load() != before+1 {
		t.Fatal("the unauthenticated call did not reach the controller")
	}
	// Re-enrollment restores the identity; the realtime loop clears the pause
	// once a session lives, and a successful callback clears it too.
	runner.controllerAuth.clear()
	reject.Store(false)
	if err := runner.postControllerJSON(ctx, "/api/v1/agent/traffic-reports", map[string]any{}, nil, true); err != nil {
		t.Fatal(err)
	}
	if wait := runner.controllerAuth.remaining(time.Now()); wait != 0 {
		t.Fatalf("a successful callback left the pause armed for %s", wait)
	}
}
