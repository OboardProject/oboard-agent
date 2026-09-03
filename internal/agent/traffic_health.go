package agent

import (
	"strings"
	"time"

	"github.com/OboardProject/oboard-agent/internal/logging"
)

// trafficReportFailureLogInterval throttles the repeated failure record. The
// report loop runs every 15-30s; logging every attempt would bury the first
// occurrence, which is the one that dates the incident.
const trafficReportFailureLogInterval = 5 * time.Minute

// trafficLeaseAtRiskAfter is when a run of failed reports stops being a
// transient network blip and starts being the thing that will silently strip
// every user's remaining lease. It is well inside trafficLeaseStaleAfter so the
// warning arrives long before the kernel starts refusing connections.
const trafficLeaseAtRiskAfter = 30 * time.Minute

// noteTrafficReportOutcome records the result of one report cycle. A failing
// cycle means no policy refresh came back, so every user on this server is
// spending a lease that will not be topped up: that has to leave a trace.
func (r *Runner) noteTrafficReportOutcome(err error) {
	now := time.Now()
	r.trafficHealthMu.Lock()
	if err == nil {
		failures := r.trafficReportFailures
		since := r.trafficReportFailingSince
		r.trafficReportFailures = 0
		r.trafficReportFailingSince = time.Time{}
		r.trafficReportLastLoggedAt = time.Time{}
		r.trafficHealthMu.Unlock()
		if failures > 0 {
			logging.Warnf("traffic report recovered after %d consecutive failure(s) over %s; lease renewal resumed", failures, now.Sub(since).Round(time.Second))
		} else {
			logging.Tracef("traffic report accepted")
		}
		return
	}
	r.trafficReportFailures++
	if r.trafficReportFailingSince.IsZero() {
		r.trafficReportFailingSince = now
	}
	failures := r.trafficReportFailures
	since := r.trafficReportFailingSince
	shouldLog := failures == 1 || now.Sub(r.trafficReportLastLoggedAt) >= trafficReportFailureLogInterval
	if shouldLog {
		r.trafficReportLastLoggedAt = now
	}
	r.trafficHealthMu.Unlock()

	if !shouldLog {
		logging.Debugf("traffic report failed (%d consecutive): %v", failures, err)
		return
	}
	outage := now.Sub(since).Round(time.Second)
	if outage >= trafficLeaseAtRiskAfter {
		logging.Errorf("traffic report failing for %s (%d consecutive attempts); traffic leases are no longer being renewed and users will be cut off as their current lease runs out: %v", outage, failures, err)
		return
	}
	logging.Warnf("traffic report failed (%d consecutive, %s): %v", failures, outage, err)
}

// trafficSyncDiagnostics is the operator-facing view of lease renewal health.
// It carries counts and statuses only: the underlying state file also holds
// per-user snapshot keys, which do not belong in a diagnostics bundle.
func (r *Runner) trafficSyncDiagnostics() map[string]any {
	r.trafficMu.Lock()
	state := r.trafficStateLocked()
	sync := state.Sync
	recovery := state.RecoveryRequired
	revision := state.PolicyRevision
	pending := len(state.PendingReports) + len(state.Pending)
	statuses := map[string]int{}
	firstError := ""
	for _, stream := range state.Streams {
		if stream == nil {
			continue
		}
		status := strings.TrimSpace(stream.Status)
		if status == "" {
			status = "unknown"
		}
		statuses[status]++
		if firstError == "" && status != trafficStatusHealthy {
			firstError = stream.LastError
		}
	}
	r.trafficMu.Unlock()

	r.trafficHealthMu.Lock()
	failures := r.trafficReportFailures
	failingSince := r.trafficReportFailingSince
	r.trafficHealthMu.Unlock()

	out := map[string]any{
		"ok":                   true,
		"status":               sync.Status,
		"last_success":         sync.LastSuccess,
		"recovery_required":    recovery,
		"policy_revision":      revision,
		"pending_reports":      pending,
		"stream_statuses":      statuses,
		"consecutive_failures": failures,
	}
	if sync.LastError != "" {
		out["last_error"] = sync.LastError
	}
	if firstError != "" {
		out["first_stream_error"] = firstError
	}
	if !failingSince.IsZero() {
		out["failing_since"] = failingSince.UTC().Format(time.RFC3339)
	}
	out["lease_renewal"] = trafficLeaseRenewalVerdict(sync.LastSuccess, failures, failingSince, time.Now())
	return out
}

// trafficLeaseRenewalVerdict names what the operator actually needs to know:
// whether leases are still being topped up. "at_risk" is the state that
// precedes users dropping off one by one with nothing in the panel to explain
// it.
func trafficLeaseRenewalVerdict(lastSuccess string, failures int, failingSince, now time.Time) string {
	if failures == 0 {
		if lastSuccess == "" {
			return "unknown"
		}
		return "healthy"
	}
	if !failingSince.IsZero() && now.Sub(failingSince) >= trafficLeaseAtRiskAfter {
		return "at_risk"
	}
	if parsed, err := time.Parse(time.RFC3339Nano, lastSuccess); err == nil && now.Sub(parsed) >= trafficLeaseStaleAfter {
		return "stale"
	}
	return "degraded"
}
