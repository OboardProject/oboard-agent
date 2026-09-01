package agent

import (
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"path/filepath"
	"strings"
	"time"

	"github.com/gorilla/websocket"
)

// controllerLinkDiagnostics records why the Controller WebSocket keeps dropping
// without ever storing credentials or the signed query. It is Agent-local
// observability only: it is not part of the Agent wire contract and never
// carries a token, header, or URL query.
type controllerLinkDiagnostics struct {
	ConnectedAt             time.Time `json:"connected_at,omitempty"`
	LastConnectedAt         time.Time `json:"last_connected_at,omitempty"`
	LastDisconnectAt        time.Time `json:"last_disconnect_at,omitempty"`
	DisconnectClass         string    `json:"disconnect_class,omitempty"`
	DisconnectDetail        string    `json:"disconnect_detail,omitempty"`
	HandshakeHTTPStatus     int       `json:"handshake_http_status,omitempty"`
	WebSocketCloseCode      int       `json:"websocket_close_code,omitempty"`
	ReconnectCount          int64     `json:"reconnect_count"`
	ConsecutiveFailures     int64     `json:"consecutive_failures"`
	LastConnectedDurationMS int64     `json:"last_connected_duration_ms,omitempty"`
	UpdatedAt               time.Time `json:"updated_at"`
}

const (
	controllerLinkClassHandshake  = "handshake_rejected"
	controllerLinkClassDial       = "dial_failed"
	controllerLinkClassAbnormal   = "abnormal_closure"
	controllerLinkClassClosed     = "closed"
	controllerLinkClassReadWrite  = "read_write_failed"
	controllerLinkClassShutdown   = "local_shutdown"
	controllerLinkStatePath       = "controller-link.json"
	controllerLinkDetailMaxLength = 200
)

func (r *Runner) recordControllerLinkConnected(at time.Time) {
	r.controllerLinkMu.Lock()
	r.controllerLink.ConnectedAt = at.UTC()
	r.controllerLink.LastConnectedAt = at.UTC()
	r.controllerLink.ReconnectCount++
	r.controllerLink.ConsecutiveFailures = 0
	r.controllerLink.UpdatedAt = at.UTC()
	snapshot := r.controllerLink
	r.controllerLinkMu.Unlock()
	r.writeControllerLinkDiagnostics(snapshot)
}

func (r *Runner) recordControllerLinkClosed(at time.Time, lived time.Duration, err error) controllerLinkDiagnostics {
	class, detail, httpStatus, closeCode := classifyControllerLinkError(err)
	r.controllerLinkMu.Lock()
	r.controllerLink.LastDisconnectAt = at.UTC()
	r.controllerLink.DisconnectClass = class
	r.controllerLink.DisconnectDetail = detail
	r.controllerLink.HandshakeHTTPStatus = httpStatus
	r.controllerLink.WebSocketCloseCode = closeCode
	if !r.controllerLink.ConnectedAt.IsZero() {
		r.controllerLink.LastConnectedDurationMS = lived.Milliseconds()
		r.controllerLink.ConnectedAt = time.Time{}
	}
	if err != nil {
		r.controllerLink.ConsecutiveFailures++
	}
	r.controllerLink.UpdatedAt = at.UTC()
	snapshot := r.controllerLink
	r.controllerLinkMu.Unlock()
	r.writeControllerLinkDiagnostics(snapshot)
	return snapshot
}

func (r *Runner) controllerLinkSnapshot() controllerLinkDiagnostics {
	r.controllerLinkMu.Lock()
	defer r.controllerLinkMu.Unlock()
	return r.controllerLink
}

func (r *Runner) writeControllerLinkDiagnostics(snapshot controllerLinkDiagnostics) {
	data, err := json.MarshalIndent(snapshot, "", "  ")
	if err != nil {
		return
	}
	_ = atomicWriteFile(filepath.Join(r.stateDir(), controllerLinkStatePath), data, 0o600)
}

// classifyControllerLinkError turns a dial or read failure into a stable class
// plus a redacted detail. `websocket.ErrBadHandshake` hides the response body,
// so the HTTP status is carried separately when the caller supplies it.
func classifyControllerLinkError(err error) (class, detail string, httpStatus, closeCode int) {
	if err == nil {
		return controllerLinkClassShutdown, "", 0, 0
	}
	var handshake *controllerHandshakeError
	if errors.As(err, &handshake) {
		return controllerLinkClassHandshake, scrubControllerLinkDetail(handshake.Error()), handshake.StatusCode, 0
	}
	var closeErr *websocket.CloseError
	if errors.As(err, &closeErr) {
		class = controllerLinkClassClosed
		if closeErr.Code == websocket.CloseAbnormalClosure || closeErr.Code == websocket.CloseNoStatusReceived {
			class = controllerLinkClassAbnormal
		}
		return class, scrubControllerLinkDetail(closeErr.Error()), 0, closeErr.Code
	}
	if errors.Is(err, websocket.ErrBadHandshake) {
		return controllerLinkClassHandshake, scrubControllerLinkDetail(err.Error()), 0, 0
	}
	var netErr net.Error
	if errors.As(err, &netErr) {
		return controllerLinkClassDial, scrubControllerLinkDetail(err.Error()), 0, 0
	}
	return controllerLinkClassReadWrite, scrubControllerLinkDetail(err.Error()), 0, 0
}

// scrubControllerLinkDetail keeps the diagnostic free of the bearer token and
// of any signed query string that may appear inside a transport error.
func scrubControllerLinkDetail(detail string) string {
	detail = strings.TrimSpace(detail)
	if detail == "" {
		return ""
	}
	if index := strings.Index(detail, "?"); index >= 0 {
		detail = detail[:index] + "?[redacted]"
	}
	detail = scrubDiagnosticOutput(detail)
	if len(detail) > controllerLinkDetailMaxLength {
		detail = detail[:controllerLinkDetailMaxLength]
	}
	return detail
}

// controllerHandshakeError carries the rejected handshake status without the
// response body, which may contain Controller-side detail Agent must not log.
type controllerHandshakeError struct {
	StatusCode int
	Status     string
}

func (e *controllerHandshakeError) Error() string {
	if e == nil {
		return ""
	}
	if strings.TrimSpace(e.Status) != "" {
		return "controller rejected websocket handshake: " + e.Status
	}
	return "controller rejected websocket handshake"
}

func (e *controllerHandshakeError) Unwrap() error { return websocket.ErrBadHandshake }

func newControllerHandshakeError(err error, response *http.Response) error {
	if err == nil || !errors.Is(err, websocket.ErrBadHandshake) || response == nil {
		return err
	}
	return &controllerHandshakeError{StatusCode: response.StatusCode, Status: response.Status}
}
