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

func (r *Runner) checkAppliedVersion(kind string, version int64, payload []byte) (bool, error) {
	if version <= 0 {
		return false, errors.New("config_version must be positive")
	}
	state, err := r.loadAppliedVersion()
	if err != nil {
		return false, err
	}
	if version < state.Version {
		return false, fmt.Errorf("config_version %d is older than last applied version %d", version, state.Version)
	}
	if version == state.Version {
		payloadID := appliedPayloadID(kind, payload)
		if state.Kind != kind || state.PayloadID != payloadID {
			return false, fmt.Errorf("config_version %d was already applied with different content", version)
		}
		return true, nil
	}
	return false, nil
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
