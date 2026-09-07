package main

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/OboardProject/oboard-agent/kernel/oboard-sb/internal/minibox"
)

func registerUsersHandler(mux *http.ServeMux, listen string, users *minibox.RuntimeUsers) {
	if !strings.HasPrefix(listen, "unix:") || users == nil {
		return
	}
	mux.HandleFunc("/users/install", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, 4<<20)
		var req minibox.UserInstallRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "invalid users install", http.StatusBadRequest)
			return
		}
		status, err := users.Install(req)
		if err != nil {
			writeUsersError(w, err)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"ok": true, "status": status})
	})
	mux.HandleFunc("/users/status", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(users.Status())
	})
}

func writeUsersError(w http.ResponseWriter, err error) {
	status := http.StatusConflict
	switch {
	case errors.Is(err, minibox.ErrUserInstallIllegal):
		status = http.StatusBadRequest
	case errors.Is(err, minibox.ErrUserInstallIncomplete):
		status = http.StatusAccepted
	case errors.Is(err, minibox.ErrUserInstallDigest), errors.Is(err, minibox.ErrUserInstallBase):
		status = http.StatusConflict
	case errors.Is(err, minibox.ErrUserInstallCapability):
		status = http.StatusUnprocessableEntity
	}
	http.Error(w, err.Error(), status)
}
