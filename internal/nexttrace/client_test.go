package nexttrace

import (
	"context"
	"encoding/json"
	"github.com/OboardProject/oboard-agent/internal/model"
	"github.com/gorilla/websocket"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestNextTraceChallengeBounds(t *testing.T) {
	for raw, want := range map[string][]string{"35": {"5", "7"}, "25": {"5", "5"}, "4": {"2", "2"}, "10403": {"101", "103"}} {
		got, err := solveChallenge(t.Context(), raw)
		if err != nil || !reflect.DeepEqual(got, want) {
			t.Fatalf("%s got=%v err=%v", raw, got, err)
		}
	}
	for _, raw := range []string{"0", "1", "13", "30", "-1", strings.Repeat("9", 100)} {
		if _, err := solveChallenge(t.Context(), raw); err == nil {
			t.Fatalf("accepted %s", raw)
		}
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := solveChallenge(ctx, "10403"); err == nil {
		t.Fatal("ignored canceled challenge")
	}
}
func TestNextTraceV3AuthenticationGeographyAndCache(t *testing.T) {
	var lookups, auth atomic.Int32
	upgrader := websocket.Upgrader{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v3/challenge/request_challenge":
			auth.Add(1)
			_ = json.NewEncoder(w).Encode(map[string]any{"challenge": map[string]string{"request_id": "test", "challenge": "35"}, "request_time": 123})
		case "/v3/challenge/submit_answer":
			var value struct {
				Answer []string `json:"answer"`
			}
			if json.NewDecoder(r.Body).Decode(&value) != nil || !reflect.DeepEqual(value.Answer, []string{"5", "7"}) {
				http.Error(w, "invalid", 400)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]string{"token": "private-test-token"})
		case "/v3/ipGeoWs":
			if r.Header.Get("Authorization") != "Bearer private-test-token" {
				http.Error(w, "auth", 401)
				return
			}
			conn, err := upgrader.Upgrade(w, r, nil)
			if err != nil {
				return
			}
			defer conn.Close()
			for {
				_, raw, err := conn.ReadMessage()
				if err != nil {
					return
				}
				lookups.Add(1)
				_ = conn.WriteJSON(map[string]any{"ip": string(raw), "asnumber": "13335", "owner": "Cloudflare", "country": "美国", "prov": "加州", "city": "洛杉矶", "isp": "Cloudflare", "router": `{"backbone":["calibrated"]}`})
			}
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	client := New(nil, "")
	client.endpoint = server.URL
	client.wsEndpoint = "ws" + strings.TrimPrefix(server.URL, "http") + "/v3/ipGeoWs"
	trace := model.NetworkTraceResult{Reached: true, Hops: []model.NetworkTraceHop{{Hop: 1, Addresses: []string{"1.1.1.1"}}}}
	client.Enrich(t.Context(), &trace)
	if trace.Provider != Provider || trace.GeographyError != "" || len(trace.Hops[0].Geography) != 1 {
		t.Fatalf("trace=%+v", trace)
	}
	geo := trace.Hops[0].Geography[0]
	if geo.ASN != "AS13335" || geo.Owner != "Cloudflare" || geo.Router["backbone"][0] != "calibrated" {
		t.Fatalf("geo=%+v", geo)
	}
	second := model.NetworkTraceResult{Hops: []model.NetworkTraceHop{{Hop: 1, Addresses: []string{"1.1.1.1"}}}}
	client.Enrich(t.Context(), &second)
	if auth.Load() != 1 || lookups.Load() != 1 || len(second.Hops[0].Geography) != 1 {
		t.Fatalf("cache miss auth=%d lookups=%d", auth.Load(), lookups.Load())
	}
}
func TestNextTraceRejectsUnboundOrMissingASN(t *testing.T) {
	for _, raw := range []string{`{"ip":"8.8.8.8","asnumber":"13335"}`, `{"ip":"1.1.1.1"}`, `{"ip":"1.1.1.1","asnumber":"0"}`} {
		if _, err := decodeGeography([]byte(raw), "1.1.1.1"); err == nil {
			t.Fatal("invalid geography accepted")
		}
	}
}
func TestNextTraceLive(t *testing.T) {
	if os.Getenv("OBOARD_TEST_NEXTTRACE_LIVE") != "1" {
		t.Skip("explicit live API check only")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 25*time.Second)
	defer cancel()
	client := New(nil, "")
	defer client.http.CloseIdleConnections()
	trace := model.NetworkTraceResult{Hops: []model.NetworkTraceHop{{Hop: 1, Addresses: []string{"1.1.1.1"}}}}
	client.Enrich(ctx, &trace)
	if trace.GeographyError != "" {
		t.Fatal(trace.GeographyError)
	}
	if len(trace.Hops[0].Geography) != 1 || trace.Hops[0].Geography[0].ASN == "" {
		t.Fatal("NextTrace returned no ASN")
	}
	t.Logf("NextTrace API ASN=%s", trace.Hops[0].Geography[0].ASN)
}

func TestNextTraceV4RateLimitDoesNotLeakToken(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.Header.Get("X-NextTrace-Token") != "secret" {
			t.Error("missing API token")
		}
		http.Error(w, "secret", 429)
	}))
	defer server.Close()
	client := New(nil, "secret")
	client.endpoint = server.URL
	trace := model.NetworkTraceResult{Hops: []model.NetworkTraceHop{{Hop: 1, Addresses: []string{"1.1.1.1"}}}}
	client.Enrich(t.Context(), &trace)
	if trace.GeographyError == "" || strings.Contains(trace.GeographyError, "secret") || time.Until(client.cooldown) < 14*time.Minute {
		t.Fatalf("bad rate-limit handling: %s", trace.GeographyError)
	}
	client.Enrich(t.Context(), &trace)
	if calls.Load() != 1 {
		t.Fatal("queried during cooldown")
	}
}
