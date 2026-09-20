package main

import (
	"encoding/json"
	"github.com/OboardProject/oboard-agent/kernel/oboard-sb/internal/auditwire"
	"github.com/OboardProject/oboard-agent/kernel/oboard-sb/internal/minibox"
	"net/http"
	"strings"
)

func registerActivityHandlers(mux *http.ServeMux, listen string, tracker *minibox.RateLimitTracker) {
	if !strings.HasPrefix(listen, "unix:") {
		return
	}
	mux.HandleFunc("POST /activity/clock", func(w http.ResponseWriter, r *http.Request) {
		var p struct {
			ControllerUnix int64 `json:"controller_unix"`
		}
		if json.NewDecoder(http.MaxBytesReader(w, r.Body, 1024)).Decode(&p) != nil {
			http.Error(w, "invalid clock", 400)
			return
		}
		tracker.AlignActivityClock(p.ControllerUnix)
		w.WriteHeader(http.StatusOK)
	})
	mux.HandleFunc("POST /activity/config", func(w http.ResponseWriter, r *http.Request) {
		var p auditwire.CollectionPolicy
		if json.NewDecoder(http.MaxBytesReader(w, r.Body, 16384)).Decode(&p) != nil || !tracker.SetActivityCollection(p) {
			http.Error(w, "invalid collection policy", 400)
			return
		}
		w.WriteHeader(http.StatusOK)
	})
	mux.HandleFunc("GET /activity/read", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(tracker.ReadActivity())
	})
	mux.HandleFunc("POST /activity/ack", func(w http.ResponseWriter, r *http.Request) {
		var ack auditwire.Ack
		if json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&ack) != nil {
			http.Error(w, "invalid ack", 400)
			return
		}
		if !tracker.AckActivity(ack.CollectorBootID, ack.Sequence) {
			http.Error(w, "report not pending", 409)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]bool{"accepted": true})
	})
}
