package main

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/OboardProject/oboard-agent/kernel/oboard-sb/internal/minibox"
)

func TestValidateLocalAPIListen(t *testing.T) {
	for _, address := range []string{"unix:/run/oboard-sb.sock", "127.0.0.1:9090", "[::1]:9090", "localhost:9090"} {
		if err := validateLocalAPIListen(address); err != nil {
			t.Fatalf("%s should be accepted: %v", address, err)
		}
	}
	for _, address := range []string{"unix:", ":9090", "0.0.0.0:9090", "[::]:9090", "192.0.2.1:9090", "invalid"} {
		if err := validateLocalAPIListen(address); err == nil {
			t.Fatalf("%s should be rejected", address)
		}
	}
}

func TestClockConfigHandlerIsUnixOnly(t *testing.T) {
	clock := minibox.NewRuntimeClock()
	tcpMux := http.NewServeMux()
	registerClockConfigHandler(tcpMux, "127.0.0.1:9090", clock)
	tcpResponse := httptest.NewRecorder()
	tcpMux.ServeHTTP(tcpResponse, httptest.NewRequest(http.MethodPost, "/clock/config", bytes.NewBufferString(`{"enabled":false}`)))
	if tcpResponse.Code != http.StatusNotFound {
		t.Fatalf("TCP clock config status = %d, want 404", tcpResponse.Code)
	}

	unixMux := http.NewServeMux()
	registerClockConfigHandler(unixMux, "unix:/run/oboard-sb.sock", clock)
	reference := time.Now().UTC().Add(time.Minute).Format(time.RFC3339Nano)
	response := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/clock/config", bytes.NewBufferString(`{"enabled":true,"reference_time":"`+reference+`","source":"test"}`))
	unixMux.ServeHTTP(response, request)
	if response.Code != http.StatusOK || !clock.Snapshot().Enabled || clock.Snapshot().Source != "test" {
		t.Fatalf("Unix clock config status=%d state=%#v body=%s", response.Code, clock.Snapshot(), response.Body.String())
	}

	methodResponse := httptest.NewRecorder()
	unixMux.ServeHTTP(methodResponse, httptest.NewRequest(http.MethodGet, "/clock/config", nil))
	if methodResponse.Code != http.StatusMethodNotAllowed {
		t.Fatalf("clock config GET status = %d", methodResponse.Code)
	}
}
