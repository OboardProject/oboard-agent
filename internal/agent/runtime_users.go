package agent

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/OboardProject/oboard-agent/internal/logging"
	"github.com/OboardProject/oboard-agent/internal/model"
	"github.com/OboardProject/oboard-agent/internal/security"
)

const (
	kernelCapabilityRuntimeUsers = "runtime_users_v1"
	usersSyncInterval            = 30 * time.Second
	usersMergeDebounce           = 120 * time.Millisecond
)

type persistedRuntimeUsers struct {
	Current *model.UsersInstallRequest `json:"current,omitempty"`
	Commit  string                     `json:"commit,omitempty"`
	BootID  string                     `json:"boot_id,omitempty"`
}

type kernelUsersStatus struct {
	UsersRevision int64             `json:"users_revision"`
	UsersDigest   string            `json:"users_digest"`
	BootID        string            `json:"boot_id"`
	PerInbound    map[string]string `json:"per_inbound,omitempty"`
}

func (r *Runner) runtimeUsersPath() string {
	return filepath.Join(r.stateDir(), "runtime-users.json")
}

func (r *Runner) appliedUsers() *model.UsersAppliedSnapshot {
	r.runtimeUsersMu.Lock()
	defer r.runtimeUsersMu.Unlock()
	if r.runtimeUsersCurrent == nil || r.runtimeUsersCurrent.UsersRevision <= 0 {
		return nil
	}
	return &model.UsersAppliedSnapshot{Revision: r.runtimeUsersCurrent.UsersRevision, Digest: r.runtimeUsersCurrent.UsersDigest, BootID: r.runtimeUsersBootID}
}

func (r *Runner) loadPersistedRuntimeUsers() {
	r.runtimeUsersMu.Lock()
	defer r.runtimeUsersMu.Unlock()
	raw, err := os.ReadFile(r.runtimeUsersPath())
	if err != nil {
		return
	}
	var state persistedRuntimeUsers
	if json.Unmarshal(raw, &state) != nil || state.Current == nil {
		return
	}
	r.runtimeUsersCurrent = state.Current
	r.runtimeUsersBootID = state.BootID
}

func (r *Runner) persistRuntimeUsersLocked() error {
	state := persistedRuntimeUsers{Current: r.runtimeUsersCurrent, Commit: "current", BootID: r.runtimeUsersBootID}
	data, err := json.Marshal(state)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(r.stateDir(), 0o700); err != nil {
		return err
	}
	tmp := r.runtimeUsersPath() + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, r.runtimeUsersPath())
}

var errUsersEnvelopeRejected = errors.New("users envelope rejected")

func (r *Runner) verifyUsersEnvelope(envelope model.UsersEnvelope) (model.UsersInstallRequest, error) {
	var req model.UsersInstallRequest
	cfg := r.Config()
	if cfg.ServerID > 0 && envelope.ServerID != cfg.ServerID {
		return req, fmt.Errorf("%w: server_id %d does not match enrolled server %d", errUsersEnvelopeRejected, envelope.ServerID, cfg.ServerID)
	}
	if strings.TrimSpace(envelope.UsersJSON) == "" || strings.TrimSpace(envelope.Signature) == "" {
		return req, fmt.Errorf("%w: missing users or signature", errUsersEnvelopeRejected)
	}
	if err := json.Unmarshal([]byte(envelope.UsersJSON), &req); err != nil {
		return req, fmt.Errorf("%w: %v", errUsersEnvelopeRejected, err)
	}
	fields := security.UsersEnvelopeFields{ServerID: envelope.ServerID, MessageID: envelope.MessageID, Revision: req.UsersRevision, Digest: req.UsersDigest, UsersJSON: envelope.UsersJSON}
	if !security.VerifyUsersEnvelope(security.HashSecret(cfg.AgentToken), fields, envelope.Signature) {
		return req, fmt.Errorf("%w: signature verification failed", errUsersEnvelopeRejected)
	}
	if req.UsersRevision <= 0 || strings.TrimSpace(req.UsersDigest) == "" || (req.Mode != "full" && req.Mode != "delta") {
		return req, fmt.Errorf("%w: illegal users install", errUsersEnvelopeRejected)
	}
	return req, nil
}

func usersInstallIsRevoke(req model.UsersInstallRequest) bool {
	if len(req.Entries) == 0 && req.Mode == "full" {
		return true
	}
	for _, entry := range req.Entries {
		if entry.Credential == (model.UsersCredential{}) {
			return true
		}
	}
	return false
}

func (r *Runner) applyUsersEnvelope(ctx context.Context, envelope model.UsersEnvelope) model.UsersAck {
	ack := model.UsersAck{Type: model.AgentControlUsersAck, MessageID: envelope.MessageID}
	req, err := r.verifyUsersEnvelope(envelope)
	if err != nil {
		logging.Warnf("users envelope rejected message=%s: %v", envelope.MessageID, err)
		ack.Error = err.Error()
		ack.Applied = r.appliedUsers()
		return ack
	}
	ack.Revision, ack.Digest = req.UsersRevision, req.UsersDigest
	outcome, err := r.applyRuntimeUsers(ctx, req)
	ack.Runtimes = outcome.runtimes
	ack.BootID = outcome.bootID
	ack.Applied = r.appliedUsers()
	if err != nil {
		ack.Error = err.Error()
		return ack
	}
	if outcome.runtimes["kernel"] == "incomplete" {
		return ack
	}
	ack.Revision, ack.Digest = outcome.revision, outcome.digest
	ack.Confirmed = true
	if ack.Runtimes == nil {
		ack.Runtimes = map[string]string{}
	}
	ack.Runtimes["runtime_verified"] = strconv.FormatBool(outcome.verified)
	return ack
}

type runtimeUsersApplyOutcome struct {
	revision int64
	digest   string
	bootID   string
	verified bool
	runtimes map[string]string
}

func (r *Runner) applyRuntimeUsers(ctx context.Context, req model.UsersInstallRequest) (outcome runtimeUsersApplyOutcome, resultErr error) {
	stage := "persist"
	defer func() {
		if req.UsersRevision > 0 || resultErr != nil {
			r.noteSyncOutcome("runtime_users", stage, req.UsersRevision, len(req.Entries), resultErr)
		}
	}()
	r.runtimeUsersApplyMu.Lock()
	defer r.runtimeUsersApplyMu.Unlock()
	if req.Chunk == nil {
		r.runtimeUsersMu.Lock()
		r.runtimeUsersCurrent = &req
		if err := r.persistRuntimeUsersLocked(); err != nil {
			r.runtimeUsersMu.Unlock()
			return outcome, err
		}
		r.runtimeUsersMu.Unlock()
	}
	outcome.runtimes = map[string]string{}
	if !r.kernelSupportsRuntimeUsers() {
		outcome.runtimes["kernel"] = "unsupported"
		outcome.revision, outcome.digest = req.UsersRevision, req.UsersDigest
		return outcome, fmt.Errorf("kernel does not advertise %s", kernelCapabilityRuntimeUsers)
	}
	stage = "kernel_apply"
	body, err := json.Marshal(req)
	if err != nil {
		return outcome, err
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://oboard-sb/users/install", bytes.NewReader(body))
	if err != nil {
		return outcome, err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	res, err := r.coreAPIClient().Do(httpReq)
	if err != nil {
		outcome.runtimes["kernel"] = "unreachable"
		return outcome, fmt.Errorf("apply kernel users: %w", err)
	}
	payload, _ := io.ReadAll(io.LimitReader(res.Body, 64<<10))
	res.Body.Close()
	if res.StatusCode == http.StatusAccepted {
		outcome.runtimes["kernel"] = "incomplete"
		outcome.revision, outcome.digest = req.UsersRevision, req.UsersDigest
		return outcome, nil
	}
	if res.StatusCode != http.StatusOK {
		outcome.runtimes["kernel"] = "rejected"
		return outcome, fmt.Errorf("kernel users status %d: %s", res.StatusCode, strings.TrimSpace(string(payload)))
	}
	outcome.runtimes["kernel"] = "applied"
	stage = "kernel_verify"
	status, err := r.readKernelUsersStatus(ctx)
	if err != nil {
		outcome.runtimes["kernel"] = "readback_failed"
		return outcome, err
	}
	if status.UsersRevision != req.UsersRevision || (status.UsersDigest != "" && status.UsersDigest != req.UsersDigest) {
		outcome.runtimes["kernel"] = "mismatch"
		return outcome, fmt.Errorf("kernel reports users revision=%d digest=%s, expected revision=%d digest=%s", status.UsersRevision, status.UsersDigest, req.UsersRevision, req.UsersDigest)
	}
	r.runtimeUsersMu.Lock()
	if req.Chunk == nil {
		r.runtimeUsersCurrent = &req
	}
	r.runtimeUsersBootID = status.BootID
	_ = r.persistRuntimeUsersLocked()
	r.runtimeUsersMu.Unlock()
	if req.Chunk != nil {
		r.wakeUsersSync()
	}
	outcome.revision, outcome.digest, outcome.bootID = status.UsersRevision, status.UsersDigest, status.BootID
	outcome.runtimes["kernel"] = "verified"
	outcome.verified = true
	return outcome, nil
}

func (r *Runner) kernelSupportsRuntimeUsers() bool {
	r.mu.Lock()
	capabilities := append([]string(nil), r.lastKernelCapabilities...)
	r.mu.Unlock()
	if len(capabilities) == 0 {
		_, capabilities = r.coreIdentity()
	}
	for _, capability := range capabilities {
		if capability == kernelCapabilityRuntimeUsers {
			return true
		}
	}
	return false
}

func (r *Runner) readKernelUsersStatus(ctx context.Context) (kernelUsersStatus, error) {
	var status kernelUsersStatus
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://oboard-sb/users/status", nil)
	if err != nil {
		return status, err
	}
	res, err := r.coreAPIClient().Do(req)
	if err != nil {
		return status, err
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return status, fmt.Errorf("kernel users status %d", res.StatusCode)
	}
	if err := json.NewDecoder(io.LimitReader(res.Body, 64<<10)).Decode(&status); err != nil {
		return status, err
	}
	return status, nil
}

func (r *Runner) reapplyPersistedRuntimeUsers(ctx context.Context, config []byte) error {
	r.runtimeUsersMu.Lock()
	current := r.runtimeUsersCurrent
	r.runtimeUsersMu.Unlock()
	if current == nil || current.UsersRevision <= 0 {
		r.loadPersistedRuntimeUsers()
		r.runtimeUsersMu.Lock()
		current = r.runtimeUsersCurrent
		r.runtimeUsersMu.Unlock()
	}
	if current == nil || current.UsersRevision <= 0 || !r.kernelSupportsRuntimeUsers() {
		return nil
	}
	// A persisted snapshot belongs to the configuration it was installed
	// against. Replaying it over a configuration that no longer declares those
	// inbounds can never converge, so the stale snapshot is discarded instead
	// of failing every later apply; Controller re-delivers the current desired
	// state when the new configuration still has a runtime-user scope.
	if runtimeUsersScopeStale(*current, config) {
		return r.dropPersistedRuntimeUsers()
	}
	_, err := r.applyRuntimeUsers(ctx, *current)
	return err
}

// runtimeUsersScopeStale reports whether a persisted install names an inbound
// the configuration being applied no longer declares as runtime-user managed.
// An unparsable configuration is never treated as evidence of staleness.
func runtimeUsersScopeStale(req model.UsersInstallRequest, config []byte) bool {
	var parsed struct {
		OBoard struct {
			RuntimeUsers struct {
				Inbounds []string `json:"inbounds"`
			} `json:"runtime_users"`
		} `json:"_oboard"`
	}
	if len(config) == 0 || json.Unmarshal(config, &parsed) != nil {
		return false
	}
	declared := map[string]struct{}{}
	for _, tag := range parsed.OBoard.RuntimeUsers.Inbounds {
		if tag = strings.TrimSpace(tag); tag != "" {
			declared[tag] = struct{}{}
		}
	}
	for _, tag := range req.Scope {
		if _, ok := declared[strings.TrimSpace(tag)]; !ok {
			return true
		}
	}
	return false
}

func (r *Runner) dropPersistedRuntimeUsers() error {
	r.runtimeUsersMu.Lock()
	defer r.runtimeUsersMu.Unlock()
	r.runtimeUsersCurrent = nil
	if err := os.Remove(r.runtimeUsersPath()); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

func (r *Runner) wakeUsersSync() {
	if r.usersSyncWake == nil {
		return
	}
	select {
	case r.usersSyncWake <- struct{}{}:
	default:
	}
}

func (r *Runner) startUsersSyncLoop(ctx context.Context) {
	if r.usersSyncWake == nil {
		r.usersSyncWake = make(chan struct{}, 1)
	}
	r.loadPersistedRuntimeUsers()
	go func() {
		timer := time.NewTimer(jitteredUsersInterval())
		defer timer.Stop()
		r.pullUsers(ctx, "startup")
		for {
			select {
			case <-ctx.Done():
				return
			case <-r.usersSyncWake:
				r.pullUsers(ctx, "wake")
				timer.Reset(jitteredUsersInterval())
			case <-timer.C:
				r.pullUsers(ctx, "periodic")
				timer.Reset(jitteredUsersInterval())
			}
		}
	}()
}

func jitteredUsersInterval() time.Duration {
	n, err := rand.Int(rand.Reader, big.NewInt(int64(usersSyncInterval/3)))
	if err != nil {
		return usersSyncInterval
	}
	return usersSyncInterval + time.Duration(n.Int64())
}

func (r *Runner) pullUsers(ctx context.Context, reason string) {
	if ctx.Err() != nil {
		return
	}
	pullCtx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	headers := http.Header{}
	if applied := r.appliedUsers(); applied != nil {
		headers.Set("X-Oboard-Users-Revision", strconv.FormatInt(applied.Revision, 10))
		headers.Set("X-Oboard-Users-Digest", applied.Digest)
		headers.Set("X-Oboard-Users-Boot-Id", applied.BootID)
	}
	var envelope model.UsersEnvelope
	if err := r.controllerJSON(pullCtx, http.MethodGet, "/api/v1/agent/users-snapshot", headers, nil, &envelope, true); err != nil {
		r.noteSyncOutcome("users_pull", reason, 0, 0, err)
		return
	}
	if strings.TrimSpace(envelope.UsersJSON) == "" {
		return
	}
	ack := r.applyUsersEnvelope(pullCtx, envelope)
	if ack.Error != "" {
		r.noteSyncOutcome("users_pull", reason, ack.Revision, 0, errors.New(ack.Error))
		return
	}
	r.noteSyncOutcome("users_pull", reason, ack.Revision, 0, nil)
}
