package agent

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/OboardProject/oboard-agent/internal/protectedstate"
	"github.com/OboardProject/oboard-agent/internal/securefile"
	"github.com/OboardProject/oboard-agent/internal/stealth"
	"os"
	"path/filepath"
)

const runtimeSecurityFile = "runtime-security.json"
const runtimeStorageReady = "runtime-storage-ready.json"
const runtimeSecretsKey = "runtime-secrets.key"

var runtimeProtectedFiles = []string{sshInboundsCurrent, sshInboundsLastGood, sshInboundHostKey, tunnelsCurrent, tunnelsLastGood}

func (r *Runner) runtimeStatePurpose(path string) string {
	for _, name := range runtimeProtectedFiles {
		if filepath.Clean(path) == r.statePath(name) {
			return name
		}
	}
	return ""
}
func (r *Runner) runtimeStorageKey() ([]byte, error) {
	raw, err := securefile.Read(r.statePath(runtimeSecretsKey), 256)
	if err != nil {
		return nil, err
	}
	if r.stealthOn() && stealth.IsEncrypted(raw) {
		raw, err = stealth.Decrypt(r.Config().StealthKey, raw)
		if err != nil {
			return nil, err
		}
	}
	if len(raw) != stealth.KeyLen {
		return nil, errors.New("invalid runtime storage key")
	}
	return raw, nil
}
func (r *Runner) protectRuntimeState(path string, raw []byte) ([]byte, error) {
	purpose := r.runtimeStatePurpose(path)
	if purpose == "" {
		return raw, nil
	}
	key, err := r.runtimeStorageKey()
	if os.IsNotExist(err) {
		if r.runtimeStorageRequired() {
			return nil, errors.New("runtime storage key missing")
		}
		return raw, nil
	}
	if err != nil {
		return nil, err
	}
	return protectedstate.Seal(key, purpose, raw)
}
func (r *Runner) openRuntimeState(path string, raw []byte) ([]byte, error) {
	if !protectedstate.IsProtected(raw) {
		if r.runtimeStatePurpose(path) != "" && r.runtimeStorageRequired() {
			return nil, errors.New("unprotected runtime state rejected")
		}
		return raw, nil
	}
	purpose := r.runtimeStatePurpose(path)
	if purpose == "" {
		return nil, errors.New("protected state has an unexpected purpose")
	}
	key, err := r.runtimeStorageKey()
	if err != nil {
		return nil, err
	}
	return protectedstate.Open(key, purpose, raw)
}
func (r *Runner) runtimeStorageRequired() bool {
	_, err := os.Lstat(r.statePath(runtimeStorageReady))
	if !os.IsNotExist(err) {
		return true
	}
	raw, err := securefile.Read(r.statePath(runtimeSecurityFile), 4096)
	if os.IsNotExist(err) {
		return false
	}
	if err != nil {
		return true
	}
	if r.stealthOn() && stealth.IsEncrypted(raw) {
		raw, err = stealth.Decrypt(r.Config().StealthKey, raw)
		if err != nil {
			return true
		}
	}
	var profile struct{ Mode string }
	return json.Unmarshal(raw, &profile) != nil || profile.Mode != "standard"
}
func (r *Runner) enableRuntimeStorage() error {
	r.runtimeStorageMu.Lock()
	defer r.runtimeStorageMu.Unlock()
	if _, err := r.runtimeStorageKey(); os.IsNotExist(err) {
		if r.runtimeStorageRequired() {
			return errors.New("runtime storage key missing")
		}
		for _, name := range runtimeProtectedFiles {
			raw, readErr := securefile.Read(r.statePath(name), 8<<20)
			if os.IsNotExist(readErr) {
				continue
			}
			if readErr != nil {
				return readErr
			}
			if r.stealthOn() && stealth.IsEncrypted(raw) {
				raw, readErr = stealth.Decrypt(r.Config().StealthKey, raw)
				if readErr != nil {
					return readErr
				}
			}
			if protectedstate.IsProtected(raw) {
				return errors.New("runtime storage key missing")
			}
		}
		key, err := stealth.GenerateKey()
		if err != nil {
			return err
		}
		if err := r.stateWritePathSyncedUnlocked(r.statePath(runtimeSecretsKey), key, 0600); err != nil {
			return err
		}
	} else if err != nil {
		return err
	}
	for _, name := range runtimeProtectedFiles {
		raw, err := r.stateReadPathUnlocked(r.statePath(name))
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			return err
		}
		if err := r.stateWritePathSyncedUnlocked(r.statePath(name), raw, 0600); err != nil {
			return err
		}
	}
	return r.stateWritePathSyncedUnlocked(r.statePath(runtimeStorageReady), []byte("1"), 0600)
}

func (r *Runner) verifyRuntimeStorage(ctx context.Context) (bool, error) {
	if !r.runtimeStorageMu.TryRLock() {
		return false, errors.New("storage busy")
	}
	defer r.runtimeStorageMu.RUnlock()
	key, err := r.runtimeStorageKey()
	if os.IsNotExist(err) && !r.runtimeStorageRequired() {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	for _, name := range runtimeProtectedFiles {
		if err := ctx.Err(); err != nil {
			return false, err
		}
		raw, err := securefile.Read(r.statePath(name), 8<<20)
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			return false, err
		}
		if r.stealthOn() && stealth.IsEncrypted(raw) {
			raw, err = stealth.Decrypt(r.Config().StealthKey, raw)
			if err != nil {
				return false, err
			}
		}
		if !protectedstate.IsProtected(raw) {
			return false, errors.New("unprotected private state")
		}
		if _, err := protectedstate.Open(key, name, raw); err != nil {
			return false, err
		}
	}
	return r.runtimeStorageRequired(), nil
}
