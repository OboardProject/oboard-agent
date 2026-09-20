package main

import (
	"bytes"
	"encoding/json"
	"github.com/OboardProject/oboard-agent/kernel/oboard-sb/internal/auditwire"
	"github.com/OboardProject/oboard-agent/kernel/oboard-sb/internal/minibox"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestAccountActivityUnixOnlyReadACK(t *testing.T) {
	tracker := minibox.NewRateLimitTracker(minibox.RuntimeMetadata{})
	tracker.SetConnectionAuditEnabled(true)
	tcp := http.NewServeMux()
	registerActivityHandlers(tcp, "127.0.0.1:1234", tracker)
	w := httptest.NewRecorder()
	tcp.ServeHTTP(w, httptest.NewRequest("GET", "/activity/read", nil))
	if w.Code != 404 {
		t.Fatal("TCP exposed activity")
	}
	mux := http.NewServeMux()
	registerActivityHandlers(mux, "unix:/test", tracker)
	read := func() []byte {
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, httptest.NewRequest("GET", "/activity/read", nil))
		if w.Code != 200 {
			t.Fatal(w.Code)
		}
		return w.Body.Bytes()
	}
	first := read()
	if !bytes.Equal(first, read()) {
		t.Fatal("read destructive")
	}
	var report auditwire.Report
	if json.Unmarshal(first, &report) != nil || report.Sequence != 1 || report.Complete {
		t.Fatal(string(first))
	}
	raw, _ := json.Marshal(auditwire.Ack{CollectorBootID: report.CollectorBootID, Sequence: report.Sequence})
	w = httptest.NewRecorder()
	mux.ServeHTTP(w, httptest.NewRequest("POST", "/activity/ack", bytes.NewReader(raw)))
	if w.Code != 200 {
		t.Fatal(w.Code)
	}
	if bytes.Equal(first, read()) {
		t.Fatal("ack did not advance")
	}
	tracker.SetConnectionAuditEnabled(false)
	if string(read()) != "null\n" {
		t.Fatal("disabled read")
	}
}
