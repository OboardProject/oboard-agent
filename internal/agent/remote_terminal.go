package agent

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/creack/pty"
	"github.com/gorilla/websocket"

	"github.com/OboardProject/oboard-agent/internal/model"
	"github.com/OboardProject/oboard-agent/internal/security"
	"github.com/OboardProject/oboard-agent/internal/version"
)

const (
	interactiveMaxCols     = 400
	interactiveMaxRows     = 150
	interactiveIdleTimeout = 15 * time.Minute
	interactiveAbsoluteTTL = time.Hour
	interactiveMaxMessage  = 64 << 10
	interactiveMaxSessions = 2
)

type terminalSession struct {
	id      string
	ptmx    *os.File
	cmd     *exec.Cmd
	conn    *websocket.Conn
	created time.Time
	last    time.Time
	once    sync.Once
	stop    chan struct{}
}

func (r *Runner) handleInteractivePrepare(env model.InteractivePrepareEnvelope) error {
	if env.SignatureVersion != 1 {
		return fmt.Errorf("unsupported interactive signature_version %d", env.SignatureVersion)
	}
	if env.Kind != "terminal" {
		return errors.New("unsupported interactive kind")
	}
	if !r.localGateAllows("remote_terminal") {
		return errors.New("agent_local_gate_denied")
	}
	serverID := r.Config().ServerID
	if serverID > 0 && env.ServerID != serverID {
		return fmt.Errorf("interactive session belongs to server %d, enrolled server is %d", env.ServerID, serverID)
	}
	issued, err := parseInteractiveTime(env.IssuedAt)
	expires, expErr := parseInteractiveTime(env.ExpiresAt)
	if err != nil || expErr != nil {
		return errors.New("invalid interactive timestamps")
	}
	now := time.Now().UTC()
	if expires.Before(now) {
		return errors.New("interactive prepare expired")
	}
	if issued.After(now.Add(30 * time.Second)) {
		return errors.New("interactive prepare issued in the future")
	}
	secret := security.HashSecret(r.Config().AgentToken)
	if !security.VerifyInteractiveEnvelope(secret, security.InteractiveEnvelope{
		Type: env.Type, ServerID: env.ServerID, SessionID: env.SessionID, Nonce: env.Nonce,
		IssuedAt: env.IssuedAt, ExpiresAt: env.ExpiresAt, Kind: env.Kind, Cols: env.Cols, Rows: env.Rows,
	}, env.Signature) {
		return errors.New("interactive prepare signature verification failed")
	}
	if !r.rememberInteractiveNonce(env.Nonce) {
		return errors.New("interactive prepare nonce replayed")
	}
	cols, rows := env.Cols, env.Rows
	if cols <= 0 || cols > interactiveMaxCols {
		cols = 120
	}
	if rows <= 0 || rows > interactiveMaxRows {
		rows = 32
	}
	go r.runTerminalSession(env, cols, rows, secret)
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

func (r *Runner) runTerminalSession(env model.InteractivePrepareEnvelope, cols, rows int, secret string) {
	r.interactiveMu.Lock()
	if r.terminalSessions == nil {
		r.terminalSessions = map[string]*terminalSession{}
	}
	if len(r.terminalSessions) >= interactiveMaxSessions {
		r.interactiveMu.Unlock()
		log.Printf("interactive session rejected: session limit")
		return
	}
	r.interactiveMu.Unlock()

	shell := "/bin/bash"
	if _, err := exec.LookPath(shell); err != nil {
		shell = "/bin/sh"
	}
	cwd := "/root"
	if _, err := os.Stat(cwd); err != nil {
		cwd = "/"
	}
	cmd := exec.Command(shell)
	cmd.Dir = cwd
	cmd.Env = append(remoteExecEnv(), "TERM=xterm-256color", "COLORTERM=truecolor")
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	ptmx, err := pty.StartWithSize(cmd, &pty.Winsize{Cols: uint16(cols), Rows: uint16(rows)})
	if err != nil {
		log.Printf("interactive pty start failed: %v", err)
		return
	}
	wsURL, err := security.ControllerInteractiveWebSocketURL(r.Config().ControllerURL, env.SessionID, version.IsDev(), r.Config().AllowInsecureController)
	if err != nil {
		_ = ptmx.Close()
		killProcessGroup(cmd)
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
		log.Printf("interactive websocket dial failed: %v", err)
		_ = ptmx.Close()
		killProcessGroup(cmd)
		return
	}
	conn.SetReadLimit(interactiveMaxMessage)
	session := &terminalSession{id: env.SessionID, ptmx: ptmx, cmd: cmd, conn: conn, created: time.Now(), last: time.Now(), stop: make(chan struct{})}
	r.interactiveMu.Lock()
	r.terminalSessions[env.SessionID] = session
	r.interactiveMu.Unlock()
	defer r.closeTerminalSession(env.SessionID, "agent_cleanup")

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
				session.signalStop()
				return
			}
		}
	}()
	_ = conn.WriteJSON(map[string]any{"type": "ready"})
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
	log.Printf("interactive session closed session=%s reason=%s", sessionID, reason)
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
