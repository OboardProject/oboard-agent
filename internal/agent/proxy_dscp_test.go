package agent

import (
	"encoding/json"
	"github.com/OboardProject/oboard-agent/internal/model"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
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
