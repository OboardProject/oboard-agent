package agent

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

const appliedVersionStateFile = "last-applied-version.json"

// appliedVersionVerdict is what the monotonic guard decided about an incoming
// configuration task.
type appliedVersionVerdict int

const (
	// appliedVersionApply means the task carries newer intent and must run.
	appliedVersionApply appliedVersionVerdict = iota
	// appliedVersionReplay means this exact version and payload already landed,
	// so the task is an idempotent redelivery.
	appliedVersionReplay
	// appliedVersionSuperseded means a newer configuration is already installed
	// and this task lost the race. That is not an error: reporting it as a
	// failure strands the Controller's sync state on a version that can never
	// advance, and every retry then rebuilds the same doomed task.
	appliedVersionSuperseded
)

type appliedVersionState struct {
	Version   int64  `json:"version"`
	PayloadID string `json:"payload_sha256"`
	Kind      string `json:"kind"`
	UpdatedAt string `json:"updated_at"`
}

func appliedPayloadID(kind string, payload []byte) string {
	sum := sha256.Sum256(append(append([]byte(kind), 0), payload...))
	return hex.EncodeToString(sum[:])
}

func (r *Runner) loadAppliedVersion() (appliedVersionState, error) {
	b, err := os.ReadFile(filepath.Join(r.stateDir(), appliedVersionStateFile))
	if errors.Is(err, os.ErrNotExist) {
		return appliedVersionState{}, nil
	}
	if err != nil {
		return appliedVersionState{}, err
	}
	var state appliedVersionState
	if err := json.Unmarshal(b, &state); err != nil {
		return appliedVersionState{}, fmt.Errorf("invalid applied version state: %w", err)
	}
	if state.Version < 0 || (state.Version > 0 && state.PayloadID == "") {
		return appliedVersionState{}, errors.New("invalid applied version state values")
	}
	return state, nil
}

// checkAppliedVersion classifies a task against the single applied-version
// watermark both configuration task types share. It reports the recorded state
// alongside the verdict so a superseded task can tell the Controller what this
// Agent actually holds.
func (r *Runner) checkAppliedVersion(kind string, version int64, payload []byte) (appliedVersionVerdict, appliedVersionState, error) {
	if version <= 0 {
		return appliedVersionApply, appliedVersionState{}, errors.New("config_version must be positive")
	}
	state, err := r.loadAppliedVersion()
	if err != nil {
		return appliedVersionApply, appliedVersionState{}, err
	}
	if version < state.Version {
		return appliedVersionSuperseded, state, nil
	}
	if version == state.Version {
		payloadID := appliedPayloadID(kind, payload)
		if state.Kind != kind || state.PayloadID != payloadID {
			// One version must describe one intent. Reaching here means the
			// Controller reused a version for different content, which no
			// amount of retrying can resolve, so it stays a hard failure.
			return appliedVersionApply, state, fmt.Errorf("config_version %d was already applied with different content", version)
		}
		return appliedVersionReplay, state, nil
	}
	return appliedVersionApply, state, nil
}

// supersededVersionResult is the task result for an obsolete configuration
// task. The Controller keys off "superseded" to reconcile against the version
// the Agent really holds instead of recording a deployment failure.
func supersededVersionResult(kind string, version int64, state appliedVersionState) map[string]any {
	return map[string]any{
		"message":         "任务版本落后于已应用配置，已跳过",
		"superseded":      true,
		"kind":            kind,
		"version":         version,
		"applied_version": state.Version,
		"applied_kind":    state.Kind,
		"applied_digest":  state.PayloadID,
	}
}

func (r *Runner) persistAppliedVersion(kind string, version int64, payload []byte) error {
	if err := os.MkdirAll(r.stateDir(), 0o700); err != nil {
		return err
	}
	state := appliedVersionState{Version: version, PayloadID: appliedPayloadID(kind, payload), Kind: kind, UpdatedAt: time.Now().UTC().Format(time.RFC3339Nano)}
	b, err := json.Marshal(state)
	if err != nil {
		return err
	}
	return atomicWriteFile(filepath.Join(r.stateDir(), appliedVersionStateFile), b, 0o600)
}
