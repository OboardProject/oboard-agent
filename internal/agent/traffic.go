package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/OboardProject/oboard-agent/internal/model"
)

const coreAPISocket = "/run/oboard-sb.sock"

const trafficReportBatchSize = 200

type trafficSnapshotItem struct {
	Key       string `json:"key"`
	UserID    int64  `json:"user_id"`
	InboundID int64  `json:"inbound_id"`
	PathID    int64  `json:"path_id"`
	PeriodKey string `json:"period_key"`
	Upload    int64  `json:"upload_bytes"`
	Download  int64  `json:"download_bytes"`
}

type trafficLocalState struct {
	Last         map[string]trafficSnapshotItem      `json:"last"`
	Pending      []trafficPendingReport              `json:"pending"`
	Acknowledged map[string]trafficCounterCheckpoint `json:"acknowledged,omitempty"`
}

type trafficCounterCheckpoint struct {
	PeriodKey string `json:"period_key"`
	Upload    int64  `json:"upload_bytes"`
	Download  int64  `json:"download_bytes"`
}

type trafficPendingReport struct {
	ReportID           string `json:"report_id"`
	UserID             int64  `json:"user_id"`
	InboundID          *int64 `json:"inbound_id,omitempty"`
	PathID             *int64 `json:"path_id,omitempty"`
	PeriodKey          string `json:"period_key"`
	Upload             int64  `json:"upload_bytes"`
	Download           int64  `json:"download_bytes"`
	StartedAt          string `json:"started_at"`
	EndedAt            string `json:"ended_at"`
	SnapshotKey        string `json:"snapshot_key,omitempty"`
	CumulativeUpload   int64  `json:"cumulative_upload_bytes,omitempty"`
	CumulativeDownload int64  `json:"cumulative_download_bytes,omitempty"`
}

type trafficReportItem struct {
	ReportID  string `json:"report_id"`
	UserID    int64  `json:"user_id"`
	InboundID *int64 `json:"inbound_id,omitempty"`
	PathID    *int64 `json:"path_id,omitempty"`
	PeriodKey string `json:"period_key"`
	Upload    int64  `json:"upload_bytes"`
	Download  int64  `json:"download_bytes"`
	StartedAt string `json:"started_at"`
	EndedAt   string `json:"ended_at"`
}

type trafficReportResponse struct {
	Accepted []string               `json:"accepted_report_ids"`
	Policies map[string]interface{} `json:"policies"`
}

func (r *Runner) startTrafficLoop(ctx context.Context) {
	// #nosec G118 -- loopCtx is the caller's lifecycle context; only the final bounded flush uses a fresh timeout after cancellation.
	go func(loopCtx context.Context) {
		ticker := time.NewTicker(r.resources.TrafficReportInterval())
		defer ticker.Stop()
		for {
			_ = r.collectAndReportTraffic(loopCtx)
			if r.Config().ConnectionAuditEnabled {
				_ = r.collectAndReportConnectionAudits(loopCtx)
			}
			select {
			case <-loopCtx.Done():
				flushCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				_ = r.collectAndReportTraffic(flushCtx)
				if r.Config().ConnectionAuditEnabled {
					_ = r.collectAndReportConnectionAudits(flushCtx)
				}
				cancel()
				return
			case <-ticker.C:
			}
		}
	}(ctx)
}

func (r *Runner) collectAndReportTraffic(ctx context.Context) error {
	r.trafficMu.Lock()
	defer r.trafficMu.Unlock()
	state := r.trafficStateLocked()
	// Keep an uncertain delivery batch stable until the controller acknowledges it.
	// This avoids appending a new report every interval while the controller is down.
	if len(state.Pending) > 0 {
		return r.reportPendingTraffic(ctx, state)
	}

	items, coreErr := r.coreTrafficSnapshot(ctx)
	sshItems := r.sshInboundTrafficSnapshot()
	if coreErr != nil && len(sshItems) == 0 {
		return coreErr
	}
	items = append(items, sshItems...)
	if len(items) == 0 {
		return r.syncTrafficPolicies(ctx, state)
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	nowID := time.Now().UnixNano()
	changed := false
	for index, item := range items {
		if item.Key == "" || item.UserID <= 0 {
			continue
		}
		last := state.Last[item.Key]
		du, dd := trafficDelta(item, last)
		if last != item {
			state.Last[item.Key] = item
			changed = true
		}
		if du == 0 && dd == 0 {
			continue
		}
		period := item.PeriodKey
		if period == "" {
			period = time.Now().UTC().Format("2006-01")
		}
		report := trafficPendingReport{ReportID: fmt.Sprintf("%s-%s-%d-%d", r.Config().AgentID, sanitizeTrafficKey(item.Key), nowID, index), UserID: item.UserID, PeriodKey: period, Upload: du, Download: dd, StartedAt: now, EndedAt: now, SnapshotKey: item.Key, CumulativeUpload: item.Upload, CumulativeDownload: item.Download}
		if item.InboundID > 0 {
			report.InboundID = &item.InboundID
		}
		if item.PathID > 0 {
			report.PathID = &item.PathID
		}
		state.Pending = append(state.Pending, report)
		changed = true
	}
	if changed {
		if err := r.saveTrafficState(*state); err != nil {
			return err
		}
	}
	if len(state.Pending) == 0 {
		return r.syncTrafficPolicies(ctx, state)
	}
	return r.reportPendingTraffic(ctx, state)
}

func trafficDelta(current, previous trafficSnapshotItem) (int64, int64) {
	if previous.PeriodKey != "" && current.PeriodKey != "" && previous.PeriodKey != current.PeriodKey {
		return current.Upload, current.Download
	}
	upload := current.Upload - previous.Upload
	download := current.Download - previous.Download
	if upload < 0 || download < 0 {
		return current.Upload, current.Download
	}
	return upload, download
}

func (r *Runner) reportPendingTraffic(ctx context.Context, state *trafficLocalState) error {
	if state == nil || len(state.Pending) == 0 {
		return nil
	}
	var resp trafficReportResponse
	req := map[string]any{"items": trafficReportBatch(state.Pending)}
	if err := r.postControllerJSON(ctx, "/api/v1/agent/traffic-reports", req, &resp, true); err != nil {
		return err
	}
	acknowledgeAcceptedTrafficReports(state, resp.Accepted)
	state.Pending = removeAcceptedTrafficReports(state.Pending, resp.Accepted)
	if err := r.saveTrafficState(*state); err != nil {
		return err
	}
	if len(resp.Policies) > 0 || len(state.Acknowledged) > 0 {
		return r.pushTrafficPolicies(ctx, resp.Policies, state.Acknowledged)
	}
	return nil
}

func (r *Runner) syncTrafficPolicies(ctx context.Context, state *trafficLocalState) error {
	var resp trafficReportResponse
	if err := r.postControllerJSON(ctx, "/api/v1/agent/traffic-reports", map[string]any{"items": []trafficPendingReport{}}, &resp, true); err != nil {
		return err
	}
	var acknowledged map[string]trafficCounterCheckpoint
	if state != nil {
		acknowledged = state.Acknowledged
	}
	if len(resp.Policies) == 0 && len(acknowledged) == 0 {
		return nil
	}
	return r.pushTrafficPolicies(ctx, resp.Policies, acknowledged)
}

func (r *Runner) sshInboundTrafficSnapshot() []trafficSnapshotItem {
	r.mu.Lock()
	manager := r.sshInboundManager
	r.mu.Unlock()
	return manager.snapshot()
}

func (r *Runner) pushTrafficPolicies(ctx context.Context, policies map[string]interface{}, acknowledged map[string]trafficCounterCheckpoint) error {
	r.mu.Lock()
	manager := r.sshInboundManager
	r.mu.Unlock()
	coreUsers, err := r.currentCoreTrafficPolicyUsers()
	if err != nil {
		// A malformed local config is handled by the normal config apply path.
		// Keep policy enforcement conservative until that repair completes.
		if err := r.pushCoreTrafficPolicy(ctx, policies, acknowledged); err != nil {
			return err
		}
		manager.updatePolicies(policies, acknowledged)
		return nil
	}
	sshUsers := manager.trafficPolicyUsers()
	corePolicies, sshPolicies := partitionRuntimePolicyLeases(policies, coreUsers, sshUsers)
	if err := r.pushCoreTrafficPolicy(ctx, corePolicies, acknowledged); err != nil {
		return err
	}
	manager.updatePolicies(sshPolicies, acknowledged)
	return nil
}

func (r *Runner) reconcileSharedCoreAndSSHTrafficPolicies(ctx context.Context, config []byte) error {
	policies, err := embeddedCoreTrafficPolicies(config)
	if err != nil {
		return err
	}
	r.mu.Lock()
	manager := r.sshInboundManager
	r.mu.Unlock()
	sshUsers := manager.trafficPolicyUsers()
	for _, raw := range policies {
		encoded, err := json.Marshal(raw)
		if err != nil {
			return err
		}
		var policy model.TrafficRuntimePolicy
		if err := json.Unmarshal(encoded, &policy); err != nil {
			return err
		}
		if sshUsers[policy.UserID] {
			return r.pushTrafficPolicies(ctx, policies, r.trafficAcknowledgements())
		}
	}
	return nil
}

func (r *Runner) currentCoreTrafficPolicyUsers() (map[int64]bool, error) {
	policies, err := r.currentCoreTrafficPolicies()
	if err != nil {
		return nil, err
	}
	out := map[int64]bool{}
	for _, policy := range policies {
		if policy.UserID > 0 {
			out[policy.UserID] = true
		}
	}
	return out, nil
}

func (r *Runner) currentCoreTrafficPolicies() (map[string]model.TrafficRuntimePolicy, error) {
	b, err := os.ReadFile(filepath.Join(r.stateDir(), "sing-box.json"))
	if errors.Is(err, os.ErrNotExist) {
		return map[string]model.TrafficRuntimePolicy{}, nil
	}
	if err != nil {
		return nil, err
	}
	policies, err := embeddedCoreTrafficPolicies(b)
	if err != nil {
		return nil, err
	}
	out := make(map[string]model.TrafficRuntimePolicy, len(policies))
	for key, raw := range policies {
		encoded, err := json.Marshal(raw)
		if err != nil {
			return nil, err
		}
		var policy model.TrafficRuntimePolicy
		if err := json.Unmarshal(encoded, &policy); err != nil {
			return nil, err
		}
		if policy.UserID > 0 {
			out[key] = policy
		}
	}
	return out, nil
}

func partitionRuntimePolicyLeases(policies map[string]interface{}, coreUsers, sshUsers map[int64]bool) (map[string]interface{}, map[string]interface{}) {
	corePolicies := map[string]interface{}{}
	sshPolicies := map[string]interface{}{}
	for key, raw := range policies {
		encoded, err := json.Marshal(raw)
		if err != nil {
			corePolicies[key] = raw
			sshPolicies[key] = raw
			continue
		}
		var policy model.TrafficRuntimePolicy
		if json.Unmarshal(encoded, &policy) != nil || policy.UserID <= 0 {
			corePolicies[key] = raw
			sshPolicies[key] = raw
			continue
		}
		hasCore := coreUsers[policy.UserID]
		hasSSH := sshUsers[policy.UserID]
		if !hasCore && !hasSSH {
			// Unknown destination during a transient config handoff: do not drop
			// enforcement from either runtime.
			hasCore, hasSSH = true, true
		}
		corePolicy, sshPolicy := policy, policy
		if hasCore && hasSSH && policy.LeaseEnforced {
			corePolicy.LeaseBytes = (policy.LeaseBytes + 1) / 2
			sshPolicy.LeaseBytes = policy.LeaseBytes / 2
			corePolicy.ResetLeaseBytes = (policy.ResetLeaseBytes + 1) / 2
			sshPolicy.ResetLeaseBytes = policy.ResetLeaseBytes / 2
		}
		if hasCore {
			corePolicies[key] = corePolicy
		}
		if hasSSH {
			sshPolicies[key] = sshPolicy
		}
	}
	return corePolicies, sshPolicies
}

func (r *Runner) trafficAcknowledgements() map[string]trafficCounterCheckpoint {
	r.trafficMu.Lock()
	defer r.trafficMu.Unlock()
	state := r.trafficStateLocked()
	out := make(map[string]trafficCounterCheckpoint, len(state.Acknowledged))
	for key, checkpoint := range state.Acknowledged {
		out[key] = checkpoint
	}
	return out
}

func trafficReportBatch(pending []trafficPendingReport) []trafficReportItem {
	limit := len(pending)
	if limit > trafficReportBatchSize {
		limit = trafficReportBatchSize
	}
	out := make([]trafficReportItem, 0, limit)
	for _, report := range pending[:limit] {
		out = append(out, trafficReportItem{ReportID: report.ReportID, UserID: report.UserID, InboundID: report.InboundID, PathID: report.PathID, PeriodKey: report.PeriodKey, Upload: report.Upload, Download: report.Download, StartedAt: report.StartedAt, EndedAt: report.EndedAt})
	}
	return out
}

func acknowledgeAcceptedTrafficReports(state *trafficLocalState, acceptedIDs []string) {
	if state == nil || len(acceptedIDs) == 0 {
		return
	}
	if state.Acknowledged == nil {
		state.Acknowledged = map[string]trafficCounterCheckpoint{}
	}
	accepted := make(map[string]struct{}, len(acceptedIDs))
	for _, id := range acceptedIDs {
		accepted[id] = struct{}{}
	}
	for _, report := range state.Pending {
		if _, ok := accepted[report.ReportID]; !ok || report.SnapshotKey == "" {
			continue
		}
		state.Acknowledged[report.SnapshotKey] = trafficCounterCheckpoint{PeriodKey: report.PeriodKey, Upload: report.CumulativeUpload, Download: report.CumulativeDownload}
	}
}

func removeAcceptedTrafficReports(pending []trafficPendingReport, acceptedIDs []string) []trafficPendingReport {
	if len(pending) == 0 || len(acceptedIDs) == 0 {
		return pending
	}
	accepted := make(map[string]struct{}, len(acceptedIDs))
	for _, id := range acceptedIDs {
		accepted[id] = struct{}{}
	}
	remaining := pending[:0]
	for _, report := range pending {
		if _, ok := accepted[report.ReportID]; !ok {
			remaining = append(remaining, report)
		}
	}
	return remaining
}

func (r *Runner) coreTrafficSnapshot(ctx context.Context) ([]trafficSnapshotItem, error) {
	client := r.coreClient
	if client == nil {
		client = unixHTTPClient(coreAPISocket)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://oboard-sb/traffic/snapshot", nil)
	if err != nil {
		return nil, err
	}
	res, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	if res.StatusCode >= 300 {
		return nil, fmt.Errorf("core traffic snapshot status %d", res.StatusCode)
	}
	var payload struct {
		Items []trafficSnapshotItem `json:"items"`
	}
	if err := json.NewDecoder(res.Body).Decode(&payload); err != nil {
		return nil, err
	}
	return payload.Items, nil
}

func (r *Runner) coreResourceSnapshot(ctx context.Context) map[string]any {
	client := r.coreClient
	if client == nil {
		client = unixHTTPClient(coreAPISocket)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://oboard-sb/resources", nil)
	if err != nil {
		return map[string]any{"ok": false, "error": err.Error()}
	}
	res, err := client.Do(req)
	if err != nil {
		return map[string]any{"ok": false, "error": err.Error()}
	}
	defer res.Body.Close()
	if res.StatusCode >= 300 {
		return map[string]any{"ok": false, "status": res.StatusCode}
	}
	var payload map[string]any
	if err := json.NewDecoder(res.Body).Decode(&payload); err != nil {
		return map[string]any{"ok": false, "error": err.Error()}
	}
	payload["ok"] = true
	return payload
}

func (r *Runner) pushCoreTrafficPolicy(ctx context.Context, policies map[string]interface{}, acknowledged map[string]trafficCounterCheckpoint) error {
	converted := map[string]interface{}{}
	for _, raw := range policies {
		b, err := json.Marshal(raw)
		if err != nil {
			return err
		}
		var p struct {
			UserID int64 `json:"user_id"`
		}
		if err := json.Unmarshal(b, &p); err != nil {
			return err
		}
		if p.UserID <= 0 {
			continue
		}
		converted[fmt.Sprintf("user:%d", p.UserID)] = raw
	}
	if len(converted) == 0 && len(acknowledged) == 0 {
		return nil
	}
	body, err := json.Marshal(map[string]any{"policies": converted, "acknowledged": acknowledged})
	if err != nil {
		return err
	}
	client := r.coreClient
	if client == nil {
		client = unixHTTPClient(coreAPISocket)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://oboard-sb/traffic/policy", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	res, err := client.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	if res.StatusCode >= 300 {
		return fmt.Errorf("core traffic policy status %d", res.StatusCode)
	}
	return nil
}

func unixHTTPClient(socket string) *http.Client {
	dialer := &net.Dialer{Timeout: 3 * time.Second}
	return &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return dialer.DialContext(ctx, "unix", socket)
		},
		MaxIdleConns:        4,
		MaxIdleConnsPerHost: 4,
		MaxConnsPerHost:     4,
		IdleConnTimeout:     30 * time.Second,
		DisableCompression:  true,
	}}
}

func (r *Runner) trafficStateLocked() *trafficLocalState {
	if !r.trafficStateLoaded {
		r.trafficState = r.loadTrafficState()
		r.trafficStateLoaded = true
	}
	if r.trafficState.Last == nil {
		r.trafficState.Last = map[string]trafficSnapshotItem{}
	}
	if r.trafficState.Acknowledged == nil {
		r.trafficState.Acknowledged = map[string]trafficCounterCheckpoint{}
	}
	return &r.trafficState
}

func (r *Runner) trafficStatePath() string {
	return filepath.Join(r.stateDir(), "traffic-state.json")
}

func (r *Runner) loadTrafficState() trafficLocalState {
	state := trafficLocalState{Last: map[string]trafficSnapshotItem{}, Acknowledged: map[string]trafficCounterCheckpoint{}}
	b, err := os.ReadFile(r.trafficStatePath())
	if err != nil {
		return state
	}
	_ = json.Unmarshal(b, &state)
	if state.Last == nil {
		state.Last = map[string]trafficSnapshotItem{}
	}
	if state.Acknowledged == nil {
		state.Acknowledged = map[string]trafficCounterCheckpoint{}
	}
	return state
}

func (r *Runner) saveTrafficState(state trafficLocalState) error {
	if err := os.MkdirAll(r.stateDir(), 0o700); err != nil {
		return err
	}
	b, err := json.Marshal(state)
	if err != nil {
		return err
	}
	return atomicWriteFile(r.trafficStatePath(), b, 0o600)
}

func sanitizeTrafficKey(key string) string {
	key = strings.Map(func(r rune) rune {
		if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' {
			return r
		}
		return '-'
	}, key)
	return strings.Trim(key, "-")
}
