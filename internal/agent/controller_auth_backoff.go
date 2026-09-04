package agent

import (
	"math/rand"
	"net/http"
	"sync"
	"time"
)

// controllerAuthBackoff pauses authenticated Controller callbacks after the
// Controller refuses this Agent's identity.
//
// The realtime channel already backs off for two to five minutes on 401/403,
// because a rejected identity does not become valid by retrying sooner. The
// HTTP callbacks did not: traffic, connection audit and asset polling each ran
// on their own timer and kept posting regardless of the answer. A node that was
// deleted or re-enrolled therefore kept a stale token pointed at the Controller
// indefinitely, spending a credential lookup per attempt on an identity that no
// longer exists. The same window is reused here so both channels quiet down
// together.
type controllerAuthBackoff struct {
	mu    sync.Mutex
	until time.Time
}

// remaining reports how long callbacks stay paused, or zero when they may run.
func (b *controllerAuthBackoff) remaining(now time.Time) time.Duration {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.until.IsZero() || !now.Before(b.until) {
		return 0
	}
	return b.until.Sub(now)
}

// arm starts or extends the pause. The window is randomized so a fleet that
// lost its Controller identity together does not resume in lockstep.
func (b *controllerAuthBackoff) arm(now time.Time) {
	span := reconnectAuthMax - reconnectAuthMin
	until := now.Add(reconnectAuthMin + time.Duration(rand.Int63n(int64(span)+1)))
	b.mu.Lock()
	defer b.mu.Unlock()
	if until.After(b.until) {
		b.until = until
	}
}

// clear resumes callbacks after the Controller accepts the identity again.
func (b *controllerAuthBackoff) clear() {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.until = time.Time{}
}

// isControllerAuthRejection reports whether a Controller status means this
// Agent should stop calling for a while rather than retry on its own timer.
// 429 is included because the Controller answers a source address that has
// spent its authentication-failure budget with it.
func isControllerAuthRejection(status int) bool {
	switch status {
	case http.StatusUnauthorized, http.StatusForbidden, http.StatusTooManyRequests:
		return true
	default:
		return false
	}
}
