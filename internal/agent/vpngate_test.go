package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/OboardProject/oboard-agent/internal/model"
)

type fakeVPNGateKernel struct {
	mu        sync.Mutex
	loaded    map[string]model.VPNGatePoolStatus
	installs  []map[string]any
	rejectAll bool
}

func (k *fakeVPNGateKernel) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/outbounds/vpngate/members", func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		k.mu.Lock()
		defer k.mu.Unlock()
		tag, _ := body["tag"].(string)
		status, ok := k.loaded[tag]
		if !ok {
			http.Error(w, "pool not found", http.StatusNotFound)
			return
		}
		if k.rejectAll {
			http.Error(w, "vpngate pool revision conflict", http.StatusConflict)
			return
		}
		k.installs = append(k.installs, body)
		status.Revision = int64(body["revision"].(float64))
		status.ContentDigest = body["content_digest"].(string)
		k.loaded[tag] = status
		_ = json.NewEncoder(w).Encode(map[string]any{"ok": true, "status": status})
	})
	mux.HandleFunc("/outbounds/vpngate/status", func(w http.ResponseWriter, r *http.Request) {
		k.mu.Lock()
		defer k.mu.Unlock()
		pools := []model.VPNGatePoolStatus{}
		for _, status := range k.loaded {
			pools = append(pools, status)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"pools": pools})
	})
	mux.HandleFunc("/outbounds/vpngate/probe", func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Candidates []model.VPNGateProbeCandidate `json:"candidates"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		results := []model.VPNGateProbeResult{}
		for _, candidate := range body.Candidates {
			results = append(results, model.VPNGateProbeResult{ProbeID: candidate.ProbeID, Status: "succeeded", HandshakeMS: 700, RTTMS: []int64{120, 121, 119}, EgressIP: "203.0.113.9", Error: strings.Repeat("x", 2000)})
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"results": results})
	})
	return mux
}

func newVPNGateTestRunner(t *testing.T, kernel *fakeVPNGateKernel, dir string) *Runner {
	t.Helper()
	server := httptest.NewServer(kernel.handler())
	t.Cleanup(server.Close)
	r := New(Config{StateDir: dir})
	r.coreClient = &http.Client{Transport: roundTripFunc(func(q *http.Request) (*http.Response, error) {
		q.URL.Scheme = "http"
		q.URL.Host = server.Listener.Addr().String()
		return http.DefaultTransport.RoundTrip(q)
	})}
	return r
}

func vpngatePlan(revision int64, digest string) model.VPNGatePoolPlan {
	return model.VPNGatePoolPlan{PoolID: 4, Tag: "vpngate-4", Revision: revision, ContentDigest: digest, Members: []model.VPNGatePoolMember{{MemberID: "m1", OpenVPNSpec: model.OpenVPNSpec{Server: "203.0.113.1", ServerPort: 443, Network: "tcp", Cipher: "AES-128-CBC", Auth: "SHA1", CA: "ca", Cert: "cert", Key: "secret-key"}}}}
}

func TestApplyVPNGatePoolPersistsAndWaitsForKernel(t *testing.T) {
	dir := t.TempDir()
	kernel := &fakeVPNGateKernel{loaded: map[string]model.VPNGatePoolStatus{}}
	r := newVPNGateTestRunner(t, kernel, dir)
	result, err := r.applyVPNGatePool(context.Background(), vpngatePlan(1, "d1"))
	if err != nil {
		t.Fatal(err)
	}
	if result["installed"] != false {
		t.Fatalf("pool is not loaded yet; expected pending install, got %v", result)
	}
	info, err := os.Stat(r.vpngatePath())
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("plan must be persisted with mode 0600: %v %v", info, err)
	}

	// The kernel loads the pool (deployment applied, or kernel restarted):
	// a fresh runner restores the plan from disk and the reconciler installs it.
	kernel.mu.Lock()
	kernel.loaded["vpngate-4"] = model.VPNGatePoolStatus{Tag: "vpngate-4", PoolID: 4}
	kernel.mu.Unlock()
	restarted := newVPNGateTestRunner(t, kernel, dir)
	restarted.reconcileVPNGate(context.Background())
	kernel.mu.Lock()
	installs := len(kernel.installs)
	kernel.mu.Unlock()
	if installs != 1 {
		t.Fatalf("reconciler must reinstall the persisted plan once, got %d", installs)
	}
	restarted.reconcileVPNGate(context.Background())
	kernel.mu.Lock()
	installs = len(kernel.installs)
	kernel.mu.Unlock()
	if installs != 1 {
		t.Fatalf("an installed plan must not be reinstalled, got %d", installs)
	}
	if status := restarted.cachedVPNGateStatus(); len(status) != 1 || status[0].Revision != 1 {
		t.Fatalf("health status not cached: %+v", status)
	}
}

func TestApplyVPNGatePoolRevisionGate(t *testing.T) {
	kernel := &fakeVPNGateKernel{loaded: map[string]model.VPNGatePoolStatus{"vpngate-4": {Tag: "vpngate-4", PoolID: 4}}}
	r := newVPNGateTestRunner(t, kernel, t.TempDir())
	if _, err := r.applyVPNGatePool(context.Background(), vpngatePlan(2, "d2")); err != nil {
		t.Fatal(err)
	}
	if _, err := r.applyVPNGatePool(context.Background(), vpngatePlan(2, "d2")); err != nil {
		t.Fatalf("identical replay must succeed: %v", err)
	}
	if _, err := r.applyVPNGatePool(context.Background(), vpngatePlan(2, "other")); err == nil {
		t.Fatal("same revision with different content must be rejected")
	}
	if _, err := r.applyVPNGatePool(context.Background(), vpngatePlan(1, "d1")); err == nil {
		t.Fatal("older revision must be rejected")
	}
	bad := vpngatePlan(3, "d3")
	bad.Tag = "vpngate-5"
	if _, err := r.applyVPNGatePool(context.Background(), bad); err == nil {
		t.Fatal("tag must match pool_id")
	}
}

func TestApplyVPNGatePoolKernelRejectionFails(t *testing.T) {
	kernel := &fakeVPNGateKernel{loaded: map[string]model.VPNGatePoolStatus{"vpngate-4": {Tag: "vpngate-4", PoolID: 4}}, rejectAll: true}
	r := newVPNGateTestRunner(t, kernel, t.TempDir())
	if _, err := r.applyVPNGatePool(context.Background(), vpngatePlan(1, "d1")); err == nil {
		t.Fatal("a kernel rejection must fail the task")
	}
}

func TestProbeVPNGateBoundsResults(t *testing.T) {
	kernel := &fakeVPNGateKernel{loaded: map[string]model.VPNGatePoolStatus{"vpngate-4": {Tag: "vpngate-4", PoolID: 4}}}
	r := newVPNGateTestRunner(t, kernel, t.TempDir())
	report, err := r.probeVPNGate(context.Background(), model.VPNGateProbePlan{PoolID: 4, Tag: "vpngate-4", RequestID: "req", Candidates: []model.VPNGateProbeCandidate{{ProbeID: "p1"}}})
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Results) != 1 || len(report.Results[0].Error) > 512 || report.RequestID != "req" {
		t.Fatalf("unbounded probe report: %+v", report)
	}
	if _, err := r.probeVPNGate(context.Background(), model.VPNGateProbePlan{PoolID: 4, Tag: "vpngate-4"}); err == nil {
		t.Fatal("empty candidate list must be rejected")
	}
}

func TestProbeVPNGateUsesProbeTimeout(t *testing.T) {
	kernel := &fakeVPNGateKernel{}
	r := newVPNGateTestRunner(t, kernel, t.TempDir())
	// Scale down the ordinary client's deadline to reproduce a slow batch
	// without waiting for the production ten-second timeout.
	r.coreClient.Timeout = 20 * time.Millisecond
	transport := r.coreClient.Transport
	r.coreClient.Transport = roundTripFunc(func(q *http.Request) (*http.Response, error) {
		timer := time.NewTimer(100 * time.Millisecond)
		defer timer.Stop()
		select {
		case <-q.Context().Done():
			return nil, q.Context().Err()
		case <-timer.C:
			return transport.RoundTrip(q)
		}
	})
	plan := model.VPNGateProbePlan{PoolID: 4, Tag: "vpngate-4", RequestID: "slow-batch"}
	for i := 0; i < 24; i++ {
		plan.Candidates = append(plan.Candidates, model.VPNGateProbeCandidate{ProbeID: fmt.Sprintf("p%d", i)})
	}
	report, err := r.probeVPNGate(context.Background(), plan)
	if err != nil {
		t.Fatalf("batch must outlive the ordinary kernel client timeout: %v", err)
	}
	if len(report.Results) != len(plan.Candidates) || report.RequestID != plan.RequestID {
		t.Fatalf("incomplete batch report: %+v", report)
	}
	if r.coreClient.Timeout != 20*time.Millisecond {
		t.Fatal("probe changed the shared kernel client timeout")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if _, err := r.probeVPNGate(ctx, plan); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("probe must honor the caller deadline: %v", err)
	}
}

func TestVPNGateClientOperationTimeouts(t *testing.T) {
	r := &Runner{coreClient: unixHTTPClient("unused.sock")}
	for _, timeout := range []time.Duration{vpngateProbeTimeout, vpngateStatusTimeout, 10 * time.Second} {
		client := r.vpngateClient(timeout)
		if client.Timeout != timeout || client.Transport != r.coreClient.Transport {
			t.Fatalf("operation client must use %v and share the kernel transport", timeout)
		}
	}
	if r.coreClient.Timeout != 10*time.Second {
		t.Fatal("operation changed the shared kernel client timeout")
	}
}
