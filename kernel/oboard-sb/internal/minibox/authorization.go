package minibox

import (
	"context"
	"fmt"
	"time"

	"github.com/OboardProject/oboard-agent/kernel/oboard-sb/internal/authorization"
)

func (s *runtimeState) authorizationDenied() bool {
	p := s.loadedPolicy()
	return s.authorization != nil && (p.UserID > 0 || p.AuthorizationKey != "") && !s.authorization.Allows(p.AuthorizationKey, s.now())
}

// InitializeAuthorization runs before listeners start. Its state is independent
// of configuration files, so a rollback cannot restore a superseded grant.
func (t *RateLimitTracker) InitializeAuthorization(path string, lease *authorization.Lease) error {
	if lease == nil {
		for _, state := range t.states {
			if state.loadedPolicy().AuthorizationKey != "" {
				return fmt.Errorf("authorization snapshot is required for installed credentials")
			}
		}
	}
	store := authorization.NewStore(path)
	if err := store.Update(lease); err != nil {
		return err
	}
	t.authorization = store
	for _, state := range t.states {
		state.authorization = store
	}
	return nil
}

func (t *RateLimitTracker) UpdateAuthorization(lease *authorization.Lease) error {
	if err := t.authorization.Update(lease); err != nil {
		return err
	}
	t.ReapAuthorization()
	return nil
}

func (t *RateLimitTracker) ReapAuthorization() {
	t.mu.RLock()
	keys := make([]string, 0, len(t.states))
	for key, state := range t.states {
		if state.deniedForConnection(true) {
			keys = append(keys, key)
		}
	}
	t.mu.RUnlock()
	for _, key := range keys {
		t.closeActive(key)
	}
}

func (t *RateLimitTracker) RunAuthorizationReaper(ctx context.Context) {
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			t.ReapAuthorization()
		}
	}
}
