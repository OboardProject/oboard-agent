package main

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/OboardProject/oboard-agent/kernel/oboard-sb/internal/protocol/vpngatepool"
)

const (
	vpngateMembersBodyLimit = 512 << 10
	vpngateProbeBodyLimit   = 2 << 20
	vpngateProbeWriteWindow = 180 * time.Second
)

type vpngatePoolLookup func(tag string) (*vpngatepool.Pool, bool)

// registerVPNGateHandlers exposes the Agent-only pool endpoints on the Unix
// local API. Responses carry member IDs and health, never certificates, keys,
// or credentials.
func registerVPNGateHandlers(mux *http.ServeMux, listen string, lookup vpngatePoolLookup, snapshot func() []vpngatepool.Status) {
	if !strings.HasPrefix(listen, "unix:") {
		return
	}
	mux.HandleFunc("/outbounds/vpngate/members", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, vpngateMembersBodyLimit)
		var request struct {
			Tag string `json:"tag"`
			vpngatepool.MembersUpdate
		}
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			http.Error(w, "invalid members update", http.StatusBadRequest)
			return
		}
		pool, ok := lookup(strings.TrimSpace(request.Tag))
		if !ok {
			http.Error(w, "pool not found", http.StatusNotFound)
			return
		}
		if err := pool.SetMembers(request.MembersUpdate); err != nil {
			status := http.StatusBadRequest
			if errors.Is(err, vpngatepool.ErrRevisionConflict) || errors.Is(err, vpngatepool.ErrStaleRevision) {
				status = http.StatusConflict
			}
			http.Error(w, err.Error(), status)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"ok": true, "status": pool.Status()})
	})
	mux.HandleFunc("/outbounds/vpngate/status", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"pools": snapshot()})
	})
	mux.HandleFunc("/outbounds/vpngate/probe", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, vpngateProbeBodyLimit)
		var request struct {
			Tag        string                       `json:"tag"`
			Candidates []vpngatepool.ProbeCandidate `json:"candidates"`
		}
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			http.Error(w, "invalid probe request", http.StatusBadRequest)
			return
		}
		pool, ok := lookup(strings.TrimSpace(request.Tag))
		if !ok {
			http.Error(w, "pool not found", http.StatusNotFound)
			return
		}
		_ = http.NewResponseController(w).SetWriteDeadline(time.Now().Add(vpngateProbeWriteWindow))
		results, err := pool.Probe(r.Context(), request.Candidates)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"results": results})
	})
}
