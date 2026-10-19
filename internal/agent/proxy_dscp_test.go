package agent

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/OboardProject/oboard-agent/internal/model"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestProxyDSCPUsesOnlyKernelLocalPolicyEndpoint(t *testing.T) {
	var got model.ProxyDSCPPolicy
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/proxy/dscp" || r.Method != "POST" {
			t.Error("unexpected request", r.Method, r.URL.Path)
			http.Error(w, "bad", 400)
			return
		}
		if err := json.NewDecoder(r.Body).Decode(&got); err != nil {
			t.Error(err)
		}
		_ = json.NewEncoder(w).Encode(model.ProxyDSCPReport{ProxyDSCPPolicy: got, Value: 46, State: "partial", Excluded: []string{"hysteria2", "ipv6-mptcp"}})
	}))
	defer srv.Close()
	r := &Runner{coreClient: &http.Client{Transport: roundTripDSCP(func(req *http.Request) (*http.Response, error) {
		req.URL.Scheme = "http"
		req.URL.Host = strings.TrimPrefix(srv.URL, "http://")
		return http.DefaultTransport.RoundTrip(req)
	})}}
	out, err := r.applyProxyDSCP(`{"enabled":true,"revision":7}`)
	if err != nil || out["requires_restart"] != false || !got.Enabled || got.Revision != 7 {
		t.Fatal(out, err, got)
	}
	report := out["proxy_dscp"].(*model.ProxyDSCPReport)
	if report.Error != "" || !slices.Contains(report.Excluded, "ipv6-mptcp") {
		t.Fatal("kernel limitation lost", report)
	}
	if _, err = r.applyProxyDSCP(`{"enabled":true,"revision":0}`); err == nil {
		t.Fatal("invalid revision accepted")
	}
}

type roundTripDSCP func(*http.Request) (*http.Response, error)

func (f roundTripDSCP) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestProxyDSCPWaitsForKernelSocket(t *testing.T) {
	for _, cause := range []error{syscall.ENOENT, syscall.ECONNREFUSED} {
		t.Run(cause.Error(), func(t *testing.T) {
			attempts := 0
			r := &Runner{coreClient: &http.Client{Transport: roundTripDSCP(func(req *http.Request) (*http.Response, error) {
				attempts++
				var policy model.ProxyDSCPPolicy
				if err := json.NewDecoder(req.Body).Decode(&policy); err != nil || policy.Revision != 7 || !policy.Enabled {
					t.Fatalf("retry changed policy: %+v %v", policy, err)
				}
				if attempts < 3 {
					return nil, &net.OpError{Op: "dial", Net: "unix", Err: cause}
				}
				w := httptest.NewRecorder()
				_ = json.NewEncoder(w).Encode(model.ProxyDSCPReport{ProxyDSCPPolicy: policy, Value: 46, State: "partial"})
				return w.Result(), nil
			})}}
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			if _, err := r.applyProxyDSCPContext(ctx, `{"enabled":true,"revision":7}`, time.Millisecond); err != nil || attempts != 3 {
				t.Fatal(attempts, err)
			}
		})
	}
}

func TestProxyDSCPReadinessWaitIsBounded(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	attempts := 0
	r := &Runner{coreClient: &http.Client{Transport: roundTripDSCP(func(req *http.Request) (*http.Response, error) {
		attempts++
		cancel()
		return nil, &net.OpError{Op: "dial", Net: "unix", Err: syscall.ENOENT}
	})}}
	if _, err := r.applyProxyDSCPContext(ctx, `{"enabled":true,"revision":7}`, time.Hour); !errors.Is(err, context.Canceled) || attempts != 1 {
		t.Fatal(attempts, err)
	}
}

func TestProxyDSCPMissingSocketDeadline(t *testing.T) {
	dir, err := os.MkdirTemp("", "dscp-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	r := &Runner{coreClient: unixHTTPClient(filepath.Join(dir, "missing.sock"))}
	defer r.coreClient.CloseIdleConnections()
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Millisecond)
	defer cancel()
	if _, err := r.applyProxyDSCPContext(ctx, `{"enabled":true,"revision":7}`, time.Millisecond); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("missing socket did not respect deadline", err)
	}
}

func TestProxyDSCPDoesNotRetryPermanentOrAmbiguousErrors(t *testing.T) {
	for _, cause := range []error{
		&net.OpError{Op: "dial", Net: "unix", Err: syscall.EACCES},
		&net.OpError{Op: "read", Net: "unix", Err: syscall.ECONNRESET},
		nil,
	} {
		attempts := 0
		r := &Runner{coreClient: &http.Client{Transport: roundTripDSCP(func(req *http.Request) (*http.Response, error) {
			attempts++
			if cause != nil {
				return nil, cause
			}
			w := httptest.NewRecorder()
			w.WriteHeader(http.StatusInternalServerError)
			return w.Result(), nil
		})}}
		if _, err := r.applyProxyDSCPContext(context.Background(), `{"enabled":true,"revision":7}`, time.Millisecond); err == nil || attempts != 1 {
			t.Fatal(cause, attempts, err)
		}
	}
}
