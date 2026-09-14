package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/OboardProject/oboard-agent/internal/agentlink"
	"github.com/OboardProject/oboard-agent/internal/logging"
	"github.com/OboardProject/oboard-agent/internal/security"
)

// agentlinkControlConn adapts a binary-transport session to controlConn.
// The session's Run loop is started by connectStealth; ReadMessage pulls the
// envelopes Run delivers.
type agentlinkControlConn struct {
	session  *agentlink.Session
	messages chan []byte
	runErr   chan error
	started  bool
}

func newAgentlinkControlConn(session *agentlink.Session) *agentlinkControlConn {
	return &agentlinkControlConn{
		session:  session,
		messages: make(chan []byte, 32),
		runErr:   make(chan error, 1),
	}
}

// start launches the session read loop. It must be called exactly once
// before ReadMessage.
func (c *agentlinkControlConn) start() {
	if c.started {
		return
	}
	c.started = true
	go func() {
		c.runErr <- c.session.Run(func(envelope map[string]json.RawMessage) {
			encoded, err := json.Marshal(envelope)
			if err != nil {
				return
			}
			select {
			case c.messages <- encoded:
			case <-c.session.Closed():
			}
		})
	}()
}

func (c *agentlinkControlConn) Close() error {
	return c.session.Close()
}

func (c *agentlinkControlConn) RemoteAddr() string { return "agentlink" }

func (c *agentlinkControlConn) WriteJSON(payload any) error {
	return c.session.WriteMessage(payload)
}

func (c *agentlinkControlConn) ReadMessage() ([]byte, error) {
	c.start()
	select {
	case data := <-c.messages:
		return data, nil
	case err := <-c.runErr:
		if err != nil {
			return nil, err
		}
		return nil, errors.New("agentlink session ended")
	}
}

func (c *agentlinkControlConn) SetReadDeadline(t time.Time) error {
	// Deadlines are enforced inside the session read loop (90s read
	// deadline); the adapter has nothing to arm.
	_ = t
	return nil
}

// connectStealth establishes the binary transport session and runs the
// shared control session over it.
func (r *Runner) connectStealth(ctx context.Context) error {
	cfg := r.Config()
	if cfg.Stealth == nil || cfg.Stealth.ControllerAddr == "" {
		return errors.New("stealth transport is not configured")
	}
	session, err := agentlink.Dial(ctx, agentlink.ClientConfig{
		Address:  cfg.Stealth.ControllerAddr,
		CertSHA256: cfg.Stealth.ControllerCertSHA256,
		AgentID:  cfg.AgentID,
		Token:    cfg.AgentToken,
	})
	if err != nil {
		return err
	}
	// Persist the observed pin when the config has none yet (first
	// connection after bootstrap with an out-of-band pin is not possible
	// here; bootstrap passes the pin through enrollment).
	if cfg.Stealth.ControllerCertSHA256 == "" {
		next := cfg
		copied := *cfg.Stealth
		next.Stealth = &copied
		next.Stealth.ControllerCertSHA256 = session.CertPin()
		if err := r.saveAgentConfig(next); err != nil {
			logging.Warnf("persist controller certificate pin: %v", err)
		} else {
			r.storeConfig(next)
		}
	}
	r.setLiveStealthSession(session)
	defer r.setLiveStealthSession(nil)
	conn := newAgentlinkControlConn(session)
	return r.runControlSession(ctx, conn)
}

// setLiveStealthSession records the session callbacks can reuse.
func (r *Runner) setLiveStealthSession(session *agentlink.Session) {
	r.controlSessionMu.Lock()
	r.controlSessionLink = session
	r.controlSessionMu.Unlock()
}

// enrollStealth performs enrollment over the binary transport and persists
// the returned identity plus the certificate pin.
func (r *Runner) enrollStealth(ctx context.Context, addr, pin, enrollmentToken string) error {
	session, err := agentlink.Dial(ctx, agentlink.ClientConfig{
		Address:         addr,
		EnrollmentToken: enrollmentToken,
		// Bootstrap: the panel passes the pin out of band, so the handshake
		// is validated against it directly.
		CertSHA256: pin,
	})
	if err != nil {
		return err
	}
	defer session.Close()
	var response agentlink.AuthEnrollResponse
	if len(session.AcceptPayload()) > 0 {
		if err := json.Unmarshal(session.AcceptPayload(), &response); err != nil {
			return err
		}
	}
	if response.AgentID == "" || response.AgentToken == "" {
		return fmt.Errorf("stealth enrollment returned no identity")
	}
	cfg := r.Config()
	cfg.ServerID = response.ServerID
	cfg.AgentID = response.AgentID
	cfg.AgentToken = response.AgentToken
	cfg.ConnectionAuditEnabled = response.ConnectionAuditEnabled
	if cfg.Stealth != nil {
		next := cfg
		copied := *cfg.Stealth
		next.Stealth = &copied
		next.Stealth.ControllerAddr = addr
		next.Stealth.ControllerCertSHA256 = session.CertPin()
		cfg = next
	}
	r.storeConfig(cfg)
	r.connectionAudit.setEnabled(cfg.ConnectionAuditEnabled)
	if err := r.saveAgentConfig(cfg); err != nil {
		return err
	}
	return nil
}

// controllerJSONOverTransport performs one callback as a transport RPC. The
// server bridges the request into the existing HTTP handler, so the response
// shapes are identical to the HTTP surface.
func (r *Runner) controllerJSONOverTransport(ctx context.Context, method, path string, body any, out any, auth bool) error {
	if auth {
		if wait := r.controllerAuth.remaining(time.Now()); wait > 0 {
			return fmt.Errorf("controller rejected this agent identity; callbacks paused for %s", wait.Truncate(time.Second))
		}
	}
	var raw json.RawMessage
	if body != nil {
		encoded, err := json.Marshal(body)
		if err != nil {
			return err
		}
		raw = encoded
	}
	resp, err := r.transportRequest(ctx, path, raw)
	if err != nil {
		return err
	}
	if auth {
		if resp.Status == 401 || resp.Status == 403 {
			r.controllerAuth.armWithStatus(time.Now(), resp.Status)
		} else if resp.Status < 300 {
			r.controllerAuth.clear()
		}
	}
	if resp.Status >= 300 {
		if resp.Error != "" {
			return fmt.Errorf("controller returned %d: %s", resp.Status, resp.Error)
		}
		return fmt.Errorf("controller returned %d: %s", resp.Status, string(resp.Body))
	}
	if out != nil && len(resp.Body) > 0 {
		return json.Unmarshal(resp.Body, out)
	}
	return nil
}

// transportRequest issues one RPC on the live session, dialing a short-lived
// one when no session is up (callbacks may fire between reconnects).
func (r *Runner) transportRequest(ctx context.Context, path string, body json.RawMessage) (*agentlink.ResponseFrame, error) {
	cfg := r.Config()
	if cfg.Stealth == nil || strings.TrimSpace(cfg.Stealth.ControllerAddr) == "" {
		return nil, errors.New("stealth transport is not configured")
	}
	if session := r.liveStealthSession(); session != nil {
		return session.Request(ctx, path, body, nil)
	}
	// No live session: a short-lived authenticated session serves the
	// callback. This mirrors HTTP callbacks that work while the WebSocket is
	// down.
	session, err := agentlink.Dial(ctx, agentlink.ClientConfig{
		Address:    cfg.Stealth.ControllerAddr,
		CertSHA256: cfg.Stealth.ControllerCertSHA256,
		AgentID:    cfg.AgentID,
		Token:      cfg.AgentToken,
	})
	if err != nil {
		return nil, err
	}
	defer session.Close()
	go func() {
		_ = session.Run(func(map[string]json.RawMessage) {})
	}()
	return session.Request(ctx, path, body, nil)
}

// stealthTransportActive reports whether callbacks should use the binary
// transport.
func (r *Runner) stealthTransportActive() bool {
	cfg := r.Config()
	return cfg.Stealth != nil && strings.TrimSpace(cfg.Stealth.ControllerAddr) != ""
}

// liveStealthSession returns the current control-channel session when it is
// the binary transport, or nil.
func (r *Runner) liveStealthSession() *agentlink.Session {
	r.controlSessionMu.Lock()
	defer r.controlSessionMu.Unlock()
	if r.controlSessionLink != nil {
		return r.controlSessionLink
	}
	return nil
}

// transportDownload fetches one release artifact over the binary transport
// in bounded chunks with resume, replacing the HTTP download path in stealth
// mode. Integrity stays end-to-end: the caller still verifies the signed
// manifest after assembly, exactly as with HTTP downloads.
func (r *Runner) transportDownload(ctx context.Context, session *agentlink.Session, name, destination string, expectedSize int64) error {
	if expectedSize > 0 {
		if info, err := os.Stat(destination); err == nil && info.Size() == expectedSize {
			return nil // already complete from a previous attempt
		}
	}
	file, err := os.OpenFile(destination, os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer file.Close()
	offset := int64(0)
	if info, err := os.Stat(destination); err == nil && info.Size() > 0 && (expectedSize <= 0 || info.Size() < expectedSize) {
		offset = info.Size()
		if _, err := file.Seek(offset, io.SeekStart); err != nil {
			return err
		}
	} else if err == nil && expectedSize > 0 && info.Size() > expectedSize {
		if err := file.Truncate(0); err != nil {
			return err
		}
	}
	// The request/response channel carries chunk reads; data frames arrive
	// on the same session.
	chunks := make(chan []byte, 4)
	done := make(chan error, 1)
	go func() {
		done <- session.RunData(func(header agentlink.DataHeader, payload []byte) error {
			if header.Stream != name {
				return nil // a different stream; ignore (single-stream use)
			}
			select {
			case chunks <- payload:
				return nil
			case <-ctx.Done():
				return ctx.Err()
			}
		})
	}()
	defer func() {
		session.Close()
		<-done
	}()
	const chunkSize = 512 << 10
	for {
		want := int64(chunkSize)
		if expectedSize > 0 && offset+want > expectedSize {
			want = expectedSize - offset
		}
		if want <= 0 {
			return nil
		}
		req := map[string]any{"stream": name, "offset": offset, "length": want}
		resp, err := session.Request(ctx, "/download", req, nil)
		if err != nil {
			return err
		}
		if resp.Status != 200 {
			return fmt.Errorf("transport download %s: %s", name, resp.Error)
		}
		var chunk []byte
		if len(resp.Body) > 0 {
			if err := json.Unmarshal(resp.Body, &chunk); err != nil {
				return err
			}
		}
		if len(chunk) == 0 {
			return nil // EOF
		}
		if _, err := file.Write(chunk); err != nil {
			return err
		}
		offset += int64(len(chunk))
		if expectedSize > 0 && offset >= expectedSize {
			return nil
		}
	}
}

// downloadAndInstallSignedReleaseOverTransport is the stealth-mode update
// path: the same signed release, fetched over the binary transport instead
// of HTTP. Verification, staging, preflight, and atomic install are shared
// with the HTTP path.
func (r *Runner) downloadAndInstallSignedReleaseOverTransport(ctx context.Context, repo, expectedBuild string, targets signedReleaseTargets, stagingPrefix string) (releaseInstallOutcome, error) {
	var outcome releaseInstallOutcome
	cfg := r.Config()
	session, err := agentlink.Dial(ctx, agentlink.ClientConfig{
		Address:    cfg.Stealth.ControllerAddr,
		CertSHA256: cfg.Stealth.ControllerCertSHA256,
		AgentID:    cfg.AgentID,
		Token:      cfg.AgentToken,
	})
	if err != nil {
		return outcome, err
	}
	go func() { _ = session.Run(func(map[string]json.RawMessage) {}) }()
	defer session.Close()
	tmpDir, err := os.MkdirTemp("", "oboard-signed-update.*")
	if err != nil {
		return outcome, err
	}
	defer os.RemoveAll(tmpDir)
	// Fetch and verify the manifest exactly as the HTTP path does.
	manifestPath := filepath.Join(tmpDir, "release-manifest.json")
	signaturePath := filepath.Join(tmpDir, "release-manifest.json.sig")
	if err := r.transportDownload(ctx, session, "release-manifest.json", manifestPath, 0); err != nil {
		return outcome, err
	}
	if err := r.transportDownload(ctx, session, "release-manifest.json.sig", signaturePath, 0); err != nil {
		return outcome, err
	}
	manifest, err := verifyDownloadedManifest(manifestPath, signaturePath, strings.TrimSpace(repo), strings.TrimSpace(expectedBuild))
	if err != nil {
		return outcome, err
	}
	agentName := "oboard-agent-" + runtime.GOOS + "-" + runtime.GOARCH
	coreName := "oboard-sb-" + runtime.GOOS + "-" + runtime.GOARCH
	realmName := "oboard-realm-" + runtime.GOOS + "-" + runtime.GOARCH
	agentFile, err := validateManifestBinary(manifest, agentName, "agent")
	if err != nil {
		return outcome, err
	}
	coreFile, err := validateManifestBinary(manifest, coreName, "sb")
	if err != nil {
		return outcome, err
	}
	realmFile, err := validateManifestBinary(manifest, realmName, "realm")
	if err != nil {
		return outcome, err
	}
	for _, file := range []security.ReleaseManifestFile{agentFile, coreFile, realmFile} {
		if err := r.transportDownload(ctx, session, file.Name, filepath.Join(tmpDir, file.Name), file.Size); err != nil {
			return outcome, err
		}
	}
	if err := ctx.Err(); err != nil {
		return outcome, fmt.Errorf("release update stopped before verification: %w", err)
	}
	if err := VerifyReleaseFiles(manifestPath, signaturePath, tmpDir, runtime.GOOS, runtime.GOARCH, []string{agentName, coreName, realmName}); err != nil {
		return outcome, err
	}
	if err := ctx.Err(); err != nil {
		return outcome, fmt.Errorf("release update stopped before installation: %w", err)
	}
	if err := checkUpdateDiskBudget(targets, agentFile.Size, coreFile.Size, realmFile.Size); err != nil {
		return outcome, err
	}
	state, note, err := r.preflightStagedCore(filepath.Join(tmpDir, coreName), targets.ActiveConfig, coreCheckTimeout)
	outcome.CorePreflight = state
	outcome.CorePreflightNote = note
	if err != nil {
		return outcome, err
	}
	if err := r.installVerifiedReleaseFiles(stagingPrefix, []stagedReleaseFile{
		{source: filepath.Join(tmpDir, agentName), target: targets.Agent},
		{source: filepath.Join(tmpDir, coreName), target: targets.Core},
		{source: filepath.Join(tmpDir, realmName), target: targets.Realm},
	}); err != nil {
		return outcome, err
	}
	outcome.Manifest = manifest
	return outcome, nil
}
