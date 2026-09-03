package agent

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"

	"github.com/creack/pty"
	"github.com/gorilla/websocket"

	"github.com/OboardProject/oboard-agent/internal/logging"
	"github.com/OboardProject/oboard-agent/internal/model"
	"github.com/OboardProject/oboard-agent/internal/security"
	"github.com/OboardProject/oboard-agent/internal/terminal"
	"github.com/OboardProject/oboard-agent/internal/version"
)

const (
	interactiveMaxCols     = 400
	interactiveMaxRows     = 150
	interactiveIdleTimeout = 15 * time.Minute
	interactiveAbsoluteTTL = time.Hour
	interactiveMaxMessage  = 64 << 10
	interactiveMaxSessions = 2

	interactiveReasonPTYStartFailed      = "pty_start_failed"
	interactiveReasonURLFailed           = "interactive_url_failed"
	interactiveReasonWebsocketDialFailed = "websocket_dial_failed"
	interactiveReasonSessionLimit        = "session_limit"
	interactiveReasonPrepareInvalid      = "prepare_invalid"
	interactiveReasonLocalGateDenied     = "agent_local_gate_denied"
	interactiveReasonLoginShellDisabled  = "login_shell_disabled"
	interactiveReasonLoginShellMissing   = "login_shell_missing"
	interactiveReasonShellExited         = "shell_exited"
)

type terminalSession struct {
	id          string
	ptmx        *os.File
	cmd         *exec.Cmd
	conn        *websocket.Conn
	spec        terminal.SessionSpec
	created     time.Time
	last        time.Time
	once        sync.Once
	stop        chan struct{}
	closeReason string
}

func (r *Runner) handleInteractivePrepare(env model.InteractivePrepareEnvelope) error {
	if env.SignatureVersion != security.InteractiveSignatureV1 && env.SignatureVersion != security.InteractiveSignatureV2 {
		return r.failInteractivePrepare(env.SessionID, interactiveReasonPrepareInvalid, fmt.Errorf("unsupported interactive signature_version %d", env.SignatureVersion))
	}
	if env.Kind != "terminal" {
		return r.failInteractivePrepare(env.SessionID, interactiveReasonPrepareInvalid, errors.New("unsupported interactive kind"))
	}
	// local gate per origin
	origin := strings.TrimSpace(env.Origin)
	if env.SignatureVersion == security.InteractiveSignatureV2 {
		if origin == "" {
			origin = model.InteractiveOriginHuman
		}
		if origin == model.InteractiveOriginMCP {
			if !r.localGateAllows("mcp_enabled") {
				return r.failInteractivePrepare(env.SessionID, interactiveReasonLocalGateDenied, errors.New("agent_local_gate_denied"))
			}
		} else {
			if !r.localGateAllows("remote_terminal") {
				return r.failInteractivePrepare(env.SessionID, interactiveReasonLocalGateDenied, errors.New("agent_local_gate_denied"))
			}
		}
	} else {
		if !r.localGateAllows("remote_terminal") {
			return r.failInteractivePrepare(env.SessionID, interactiveReasonLocalGateDenied, errors.New("agent_local_gate_denied"))
		}
	}
	serverID := r.Config().ServerID
	if serverID > 0 && env.ServerID != serverID {
		return r.failInteractivePrepare(env.SessionID, interactiveReasonPrepareInvalid, fmt.Errorf("interactive session belongs to server %d, enrolled server is %d", env.ServerID, serverID))
	}
	issued, err := parseInteractiveTime(env.IssuedAt)
	expires, expErr := parseInteractiveTime(env.ExpiresAt)
	if err != nil || expErr != nil {
		return r.failInteractivePrepare(env.SessionID, interactiveReasonPrepareInvalid, errors.New("invalid interactive timestamps"))
	}
	now := time.Now().UTC()
	if expires.Before(now) {
		return r.failInteractivePrepare(env.SessionID, interactiveReasonPrepareInvalid, errors.New("interactive prepare expired"))
	}
	if issued.After(now.Add(30 * time.Second)) {
		return r.failInteractivePrepare(env.SessionID, interactiveReasonPrepareInvalid, errors.New("interactive prepare issued in the future"))
	}
	secret := security.HashSecret(r.Config().AgentToken)
	if env.SignatureVersion == security.InteractiveSignatureV2 {
		if !security.VerifyInteractiveEnvelopeV2(secret, security.InteractiveEnvelope{
			Type: env.Type, ServerID: env.ServerID, SessionID: env.SessionID, Nonce: env.Nonce,
			IssuedAt: env.IssuedAt, ExpiresAt: env.ExpiresAt, Kind: env.Kind, Origin: origin, Cols: env.Cols, Rows: env.Rows, Mode: env.Mode,
		}, env.Signature) {
			return r.failInteractivePrepare(env.SessionID, interactiveReasonPrepareInvalid, errors.New("interactive prepare signature verification failed"))
		}
	} else {
		if !security.VerifyInteractiveEnvelope(secret, security.InteractiveEnvelope{
			Type: env.Type, ServerID: env.ServerID, SessionID: env.SessionID, Nonce: env.Nonce,
			IssuedAt: env.IssuedAt, ExpiresAt: env.ExpiresAt, Kind: env.Kind, Cols: env.Cols, Rows: env.Rows,
		}, env.Signature) {
			return r.failInteractivePrepare(env.SessionID, interactiveReasonPrepareInvalid, errors.New("interactive prepare signature verification failed"))
		}
	}
	if !r.rememberInteractiveNonce(env.Nonce) {
		return r.failInteractivePrepare(env.SessionID, interactiveReasonPrepareInvalid, errors.New("interactive prepare nonce replayed"))
	}
	cols, rows := env.Cols, env.Rows
	if cols <= 0 || cols > interactiveMaxCols {
		cols = 120
	}
	if rows <= 0 || rows > interactiveMaxRows {
		rows = 32
	}
	mode, err := terminal.ParseMode(env.Mode)
	if err != nil {
		return r.failInteractivePrepare(env.SessionID, interactiveReasonPrepareInvalid, err)
	}
	go r.runTerminalSession(env, cols, rows, mode, secret)
	return nil
}

func parseInteractiveTime(value string) (time.Time, error) {
	if parsed, err := time.Parse(time.RFC3339Nano, value); err == nil {
		return parsed, nil
	}
	return time.Parse(time.RFC3339, value)
}

func (r *Runner) rememberInteractiveNonce(nonce string) bool {
	nonce = strings.TrimSpace(nonce)
	if nonce == "" {
		return false
	}
	r.interactiveMu.Lock()
	defer r.interactiveMu.Unlock()
	if r.interactiveNonces == nil {
		r.interactiveNonces = map[string]time.Time{}
	}
	now := time.Now()
	for key, expiry := range r.interactiveNonces {
		if expiry.Before(now) {
			delete(r.interactiveNonces, key)
		}
	}
	if _, exists := r.interactiveNonces[nonce]; exists {
		return false
	}
	r.interactiveNonces[nonce] = now.Add(2 * time.Minute)
	return true
}

func (r *Runner) failInteractivePrepare(sessionID, reason string, err error) error {
	detail := ""
	if err != nil {
		detail = err.Error()
	}
	r.reportInteractiveFailed(sessionID, reason, detail)
	if err != nil {
		return err
	}
	return errors.New(reason)
}

func (r *Runner) reportInteractiveFailed(sessionID, reason, detail string) {
	if strings.TrimSpace(sessionID) == "" || strings.TrimSpace(reason) == "" {
		return
	}
	logging.Warnf("interactive failed session=%s reason=%s detail=%s", sessionID, reason, detail)
	payload := map[string]any{
		"type": "interactive_failed", "session_id": sessionID, "reason": reason, "ts": time.Now().UTC(),
	}
	if detail != "" {
		payload["detail"] = detail
	}
	r.sendControl(payload)
}

func (r *Runner) reportInteractiveReady(sessionID string) {
	if strings.TrimSpace(sessionID) == "" {
		return
	}
	r.sendControl(map[string]any{
		"type": "interactive_ready", "session_id": sessionID, "ts": time.Now().UTC(),
	})
}

func startInteractivePTY(cols, rows int, mode terminal.Mode) (*os.File, *exec.Cmd, terminal.SessionSpec, error) {
	spec, err := terminal.BuildSession(terminal.Request{Mode: mode, Cols: cols, Rows: rows, TERM: terminal.DefaultTERM, COLORTERM: terminal.DefaultCOLORTERM})
	if err != nil {
		return nil, nil, spec, err
	}
	ptmx, cmd, err := terminal.Spawn(spec)
	return ptmx, cmd, spec, err
}

func (r *Runner) runTerminalSession(env model.InteractivePrepareEnvelope, cols, rows int, mode terminal.Mode, secret string) {
	r.interactiveMu.Lock()
	if r.terminalSessions == nil {
		r.terminalSessions = map[string]*terminalSession{}
	}
	if len(r.terminalSessions) >= interactiveMaxSessions {
		r.interactiveMu.Unlock()
		r.reportInteractiveFailed(env.SessionID, interactiveReasonSessionLimit, "interactive session rejected: session limit")
		return
	}
	r.interactiveMu.Unlock()

	ptmx, cmd, spec, err := startInteractivePTY(cols, rows, mode)
	if err != nil {
		reason := interactiveReasonPTYStartFailed
		if terminal.IsLoginDisabled(err) {
			reason = interactiveReasonLoginShellDisabled
		} else if terminal.IsShellMissing(err) {
			reason = interactiveReasonLoginShellMissing
		}
		r.reportInteractiveFailed(env.SessionID, reason, err.Error())
		return
	}
	logging.Infof("terminal session started session=%s uid=%d username=%s shell=%s mode=%s cwd=%s rows=%d cols=%d",
		env.SessionID, spec.UID, spec.Username, spec.Shell, spec.Mode, spec.WorkDir, rows, cols)
	wsURL, err := security.ControllerInteractiveWebSocketURL(r.Config().ControllerURL, env.SessionID, version.IsDev(), r.Config().AllowInsecureController)
	if err != nil {
		_ = ptmx.Close()
		killProcessGroup(cmd)
		r.reportInteractiveFailed(env.SessionID, interactiveReasonURLFailed, err.Error())
		return
	}
	header := http.Header{
		"Authorization":              []string{"Bearer " + r.Config().AgentToken},
		"X-Agent-ID":                 []string{r.Config().AgentID},
		"X-OBoard-Interactive-Proof": []string{security.InteractiveProof(secret, env.SessionID, env.ServerID, env.Nonce, env.ExpiresAt)},
	}
	dialer := websocket.Dialer{ReadBufferSize: 4096, WriteBufferSize: 4096, EnableCompression: false, HandshakeTimeout: 10 * time.Second}
	conn, _, err := dialer.Dial(wsURL, header)
	if err != nil {
		_ = ptmx.Close()
		killProcessGroup(cmd)
		r.reportInteractiveFailed(env.SessionID, interactiveReasonWebsocketDialFailed, err.Error())
		return
	}
	conn.SetReadLimit(interactiveMaxMessage)
	session := &terminalSession{id: env.SessionID, ptmx: ptmx, cmd: cmd, spec: spec, conn: conn, created: time.Now(), last: time.Now(), stop: make(chan struct{})}
	r.interactiveMu.Lock()
	r.terminalSessions[env.SessionID] = session
	r.interactiveMu.Unlock()
	defer func() {
		reason := session.closeReason
		if reason == "" {
			reason = "agent_cleanup"
		}
		r.closeTerminalSession(env.SessionID, reason)
	}()

	go func() {
		buf := make([]byte, 8192)
		for {
			n, readErr := ptmx.Read(buf)
			if n > 0 {
				session.last = time.Now()
				if writeErr := conn.WriteMessage(websocket.BinaryMessage, append([]byte(nil), buf[:n]...)); writeErr != nil {
					session.signalStop()
					return
				}
			}
			if readErr != nil {
				session.closeReason = interactiveReasonShellExited
				session.signalStop()
				return
			}
		}
	}()
	_ = conn.WriteJSON(map[string]any{"type": "ready", "info": spec.Diagnostic()})
	r.reportInteractiveReady(env.SessionID)
	for {
		deadline := session.last.Add(interactiveIdleTimeout)
		absolute := session.created.Add(interactiveAbsoluteTTL)
		if absolute.Before(deadline) {
			deadline = absolute
		}
		_ = conn.SetReadDeadline(deadline)
		mt, data, err := conn.ReadMessage()
		if err != nil {
			return
		}
		session.last = time.Now()
		switch mt {
		case websocket.BinaryMessage:
			if _, err := ptmx.Write(data); err != nil {
				return
			}
		case websocket.TextMessage:
			var msg struct {
				Type string `json:"type"`
				Cols int    `json:"cols"`
				Rows int    `json:"rows"`
			}
			if json.Unmarshal(data, &msg) != nil {
				continue
			}
			switch msg.Type {
			case "resize":
				if msg.Cols > 0 && msg.Rows > 0 && msg.Cols <= interactiveMaxCols && msg.Rows <= interactiveMaxRows {
					_ = pty.Setsize(ptmx, &pty.Winsize{Cols: uint16(msg.Cols), Rows: uint16(msg.Rows)})
				}
			case "close":
				return
			}
		}
		select {
		case <-session.stop:
			return
		default:
		}
	}
}

func (s *terminalSession) signalStop() {
	s.once.Do(func() { close(s.stop) })
	if s.conn != nil {
		_ = s.conn.Close()
	}
}

func (r *Runner) closeTerminalSession(sessionID, reason string) {
	r.interactiveMu.Lock()
	session := r.terminalSessions[sessionID]
	delete(r.terminalSessions, sessionID)
	r.interactiveMu.Unlock()
	if session == nil {
		return
	}
	if session.conn != nil {
		_ = session.conn.WriteJSON(map[string]any{"type": "closed", "reason": reason})
		_ = session.conn.Close()
	}
	if session.ptmx != nil {
		_ = session.ptmx.Close()
	}
	killProcessGroup(session.cmd)
	exitCode := -1
	if session.cmd != nil && session.cmd.ProcessState != nil {
		exitCode = session.cmd.ProcessState.ExitCode()
	}
	logging.Infof("interactive session closed session=%s reason=%s uid=%d username=%s shell=%s mode=%s cwd=%s exit_code=%d",
		sessionID, reason, session.spec.UID, session.spec.Username, session.spec.Shell, session.spec.Mode, session.spec.WorkDir, exitCode)
}

func (r *Runner) closeAllTerminalSessions(reason string) {
	r.interactiveMu.Lock()
	ids := make([]string, 0, len(r.terminalSessions))
	for id := range r.terminalSessions {
		ids = append(ids, id)
	}
	r.interactiveMu.Unlock()
	for _, id := range ids {
		r.closeTerminalSession(id, reason)
	}
}
