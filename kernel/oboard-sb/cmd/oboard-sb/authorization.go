package main

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/OboardProject/oboard-agent/kernel/oboard-sb/internal/authorization"
	"github.com/OboardProject/oboard-agent/kernel/oboard-sb/internal/minibox"
)

func registerAuthorizationHandler(mux *http.ServeMux, listen string, tracker *minibox.RateLimitTracker) {
	if !strings.HasPrefix(listen, "unix:") {
		return
	}
	mux.HandleFunc("/authorization/config", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", 405)
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, 16<<20)
		var lease authorization.Lease
		if err := json.NewDecoder(r.Body).Decode(&lease); err != nil {
			http.Error(w, "invalid authorization snapshot", 400)
			return
		}
		if err := tracker.UpdateAuthorization(&lease); err != nil {
			http.Error(w, "authorization update rejected", 409)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]bool{"ok": true})
	})
}
