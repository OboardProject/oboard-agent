package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/OboardProject/oboard-agent/internal/authorization"
	"github.com/OboardProject/oboard-agent/internal/model"
)

func (r *Runner) authorizationState() *authorization.Store {
	r.authorizationMu.Lock()
	defer r.authorizationMu.Unlock()
	if r.authorizationStore == nil {
		r.authorizationStore = authorization.NewStore(filepath.Join(r.stateDir(), "authorization.json"))
	}
	return r.authorizationStore
}

func (r *Runner) authorizationAllows(key string) bool {
	now := time.Now()
	if r.clock != nil {
		now = r.clock.Now()
	}
	return r.authorizationState().Allows(key, now)
}

func configAuthorization(raw []byte) (*model.AuthorizationLease, error) {
	var config struct {
		Metadata struct {
			Authorization *model.AuthorizationLease `json:"authorization"`
			Limits        map[string]map[string]struct {
				Key string `json:"authorization_key"`
			} `json:"rate_limits"`
		} `json:"_oboard"`
	}
	if err := json.Unmarshal(raw, &config); err != nil {
		return nil, err
	}
	if config.Metadata.Authorization == nil {
		for _, entries := range config.Metadata.Limits {
			for _, entry := range entries {
				if entry.Key != "" {
					return nil, fmt.Errorf("authorization snapshot is required for installed credentials")
				}
			}
		}
	}
	return config.Metadata.Authorization, config.Metadata.Authorization.Validate()
}

func configHasAuthorizationUsers(raw []byte) (bool, error) {
	type identity struct {
		UserID int64  `json:"user_id"`
		Key    string `json:"authorization_key"`
	}
	var config struct {
		Metadata struct {
			Limits struct {
				Users    map[string]identity `json:"users"`
				Inbounds map[string]identity `json:"inbounds"`
			} `json:"rate_limits"`
		} `json:"_oboard"`
	}
	if err := json.Unmarshal(raw, &config); err != nil {
		return false, err
	}
	for _, entries := range []map[string]identity{config.Metadata.Limits.Users, config.Metadata.Limits.Inbounds} {
		for _, entry := range entries {
			if entry.UserID > 0 || entry.Key != "" {
				return true, nil
			}
		}
	}
	return false, nil
}

func (r *Runner) stageConfigAuthorization(raw []byte) (resultErr error) {
	stage := "validate"
	revision, count := int64(0), 0
	defer func() {
		if revision > 0 || resultErr != nil {
			r.noteSyncOutcome("credential_install", stage, revision, count, resultErr)
		}
	}()
	lease, err := configAuthorization(raw)
	if err != nil {
		return err
	}
	hasUsers, err := configHasAuthorizationUsers(raw)
	if err != nil {
		return err
	}
	if lease != nil {
		revision, count = lease.Revision, len(lease.Grants)
	}
	stage = "kernel_capability"
	if lease != nil && hasUsers {
		output, err := commandOutput(r.commandTimeout(), r.coreBinary(), "-version")
		if err != nil {
			return fmt.Errorf("authorization requires a lease-capable kernel: %w", err)
		}
		supported := false
		for _, capability := range parseKernelCapabilities(output) {
			supported = supported || capability == "authorization_lease_v1"
		}
		if !supported {
			return fmt.Errorf("update oboard-sb before applying proxy authorization: authorization_lease_v1 required")
		}
	}
	stage = "persist"
	return r.authorizationState().Update(lease)
}

func (r *Runner) applyConfigAuthorization(ctx context.Context, raw []byte) error {
	lease, err := configAuthorization(raw)
	if err != nil {
		return err
	}
	return r.applyAuthorization(ctx, lease)
}

func (r *Runner) applyAuthorization(ctx context.Context, lease *model.AuthorizationLease) (resultErr error) {
	stage := "persist"
	revision, count := int64(0), 0
	if lease != nil {
		revision, count = lease.Revision, len(lease.Grants)
	}
	defer func() {
		if lease != nil || resultErr != nil {
			r.noteSyncOutcome("authorization", stage, revision, count, resultErr)
		}
	}()
	store := r.authorizationState()
	if err := store.Update(lease); err != nil {
		return err
	}
	stage = "ssh_runtime"
	r.mu.Lock()
	manager := r.sshInboundManager
	r.mu.Unlock()
	manager.reapAuthorization()
	latest, err := store.Snapshot()
	if err != nil || latest == nil {
		return err
	}
	revision, count = latest.Revision, len(latest.Grants)
	stage = "read_kernel_config"
	raw, err := os.ReadFile(filepath.Join(r.stateDir(), "sing-box.json"))
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	hasUsers, err := configHasAuthorizationUsers(raw)
	if err != nil {
		return err
	}
	if !hasUsers {
		return nil
	}
	stage = "kernel_apply"
	body, err := json.Marshal(latest)
	if err != nil {
		return err
	}
	client := r.coreAPIClient()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://oboard-sb/authorization/config", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	res, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("apply kernel authorization: %w", err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return fmt.Errorf("kernel authorization status %d", res.StatusCode)
	}
	return nil
}
