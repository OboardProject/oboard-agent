package agent

import (
	"context"
	"errors"
	"net/url"
	"strings"
	"time"

	"github.com/OboardProject/oboard-agent/internal/authorization"
	"github.com/OboardProject/oboard-agent/internal/logging"
)

type syncLogState struct {
	stage    string
	failed   bool
	failures int
	since    time.Time
	last     time.Time
	revision int64
}

func safeSyncError(err error) string {
	if err == nil {
		return ""
	}
	var transport *url.Error
	if errors.As(err, &transport) {
		return scrubControllerLinkDetail(transport.Err.Error())
	}
	detail := err.Error()
	if i := strings.Index(detail, "controller returned "); i >= 0 {
		detail = detail[i:]
		if end := strings.Index(detail, ":"); end >= 0 {
			detail = detail[:end]
		}
	}
	return scrubControllerLinkDetail(detail)
}

// Routine renewals are summarized; transitions and new failure stages are immediate.
func (r *Runner) noteSyncOutcome(operation, stage string, revision int64, count int, err error) {
	if errors.Is(err, context.Canceled) {
		return
	}
	now := time.Now()
	r.syncLogMu.Lock()
	defer r.syncLogMu.Unlock()
	if r.syncLogStates == nil {
		r.syncLogStates = make(map[string]syncLogState)
	}
	previous, exists := r.syncLogStates[operation]
	state := previous
	state.stage, state.failed, state.revision = stage, err != nil, revision
	if err != nil {
		state.failures++
		if !previous.failed {
			state.since = now
		}
		if !previous.failed || previous.stage != stage || now.Sub(previous.last) >= time.Minute {
			logging.Warnf("sync failed: operation=%s stage=%s revision=%d entries=%d failures=%d duration=%s reason=%q", operation, stage, revision, count, state.failures, now.Sub(state.since).Round(time.Second), safeSyncError(err))
			state.last = now
		}
	} else {
		if !exists || previous.failed || previous.revision != revision || now.Sub(previous.last) >= 5*time.Minute {
			logging.Infof("sync completed: operation=%s stage=%s revision=%d entries=%d recovered=%t previous_failures=%d", operation, stage, revision, count, previous.failed, previous.failures)
			state.last = now
		} else {
			logging.Debugf("sync renewed: operation=%s revision=%d entries=%d", operation, revision, count)
		}
		state.failures, state.since = 0, time.Time{}
	}
	r.syncLogStates[operation] = state
}

func (r *Runner) noteAuthorizationAvailability() {
	lease, err := r.authorizationState().Snapshot()
	if err != nil {
		r.noteSyncOutcome("authorization_validity", "read_state", 0, 0, err)
		return
	}
	if lease == nil {
		return
	}
	now := time.Now()
	if r.clock != nil {
		now = r.clock.Now()
	}
	valid, lapsed := 0, 0
	for key, raw := range lease.Grants {
		switch {
		case lease.Allows(key, now):
			valid++
		case !grantEndedOnSchedule(lease, raw, now):
			lapsed++
		}
	}
	if lapsed > 0 {
		r.noteSyncOutcome("authorization_validity", "expired", lease.Revision, lapsed, errors.New("authorization expired; affected proxy connections are denied and closed"))
	} else {
		r.noteSyncOutcome("authorization_validity", "valid", lease.Revision, valid, nil)
	}
}

// grantEndedOnSchedule reports whether a grant stopped admitting at a business
// boundary the Controller set (a plan, exception, or device transition ending
// before the lease does) while the lease itself is still current. That grant is
// denied on purpose until the next renewal drops it; it is not a renewal lapse.
func grantEndedOnSchedule(lease *authorization.Lease, raw string, now time.Time) bool {
	issued, err := time.Parse(time.RFC3339Nano, lease.IssuedAt)
	if err != nil {
		return false
	}
	expires := issued.Add(authorization.MaxLifetime)
	if lease.ExpiresAt != "" {
		if expires, err = time.Parse(time.RFC3339Nano, lease.ExpiresAt); err != nil {
			return false
		}
	}
	end, err := time.Parse(time.RFC3339Nano, raw)
	return err == nil && now.Before(expires) && end.Before(expires) && !now.Before(end)
}
