package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	connectionAuditReportBatchSize = 200
	maxAgentAuditBuckets           = 2048
)

type connectionAuditSnapshotItem struct {
	UserID          int64  `json:"user_id"`
	InboundID       int64  `json:"inbound_id,omitempty"`
	PathID          int64  `json:"path_id,omitempty"`
	SourceIP        string `json:"source_ip"`
	SourceGeoCode   string `json:"source_geo_code,omitempty"`
	Network         string `json:"network"`
	Destination     string `json:"destination,omitempty"`
	DestinationPort int    `json:"destination_port,omitempty"`
	OutboundTag     string `json:"outbound_tag,omitempty"`
	OutboundType    string `json:"outbound_type,omitempty"`
	ConnectionCount int64  `json:"connection_count"`
	ActivePeak      int64  `json:"active_peak"`
	ActiveAtEnd     int64  `json:"active_at_end"`
	StartedAt       string `json:"started_at"`
	EndedAt         string `json:"ended_at"`
}

type connectionAuditPendingReport struct {
	ReportID string `json:"report_id"`
	connectionAuditSnapshotItem
}

type connectionAuditLocalState struct {
	Pending []connectionAuditPendingReport `json:"pending"`
}

type connectionAuditReportResponse struct {
	Accepted []string `json:"accepted_report_ids"`
}

type agentAuditBucket struct {
	connectionAuditSnapshotItem
	key    string
	active int64
}

type connectionAuditAccumulator struct {
	mu           sync.Mutex
	buckets      map[string]*agentAuditBucket
	activeByUser map[int64]int64
	generation   uint64
	enabled      atomic.Bool
}

func newConnectionAuditAccumulator(enabled bool) *connectionAuditAccumulator {
	a := &connectionAuditAccumulator{}
	a.enabled.Store(enabled)
	return a
}

func (a *connectionAuditAccumulator) setEnabled(enabled bool) {
	if a == nil {
		return
	}
	a.enabled.Store(enabled)
	if enabled {
		return
	}
	a.mu.Lock()
	a.buckets = nil
	a.activeByUser = nil
	a.generation++
	a.mu.Unlock()
}

func (a *connectionAuditAccumulator) start(item connectionAuditSnapshotItem) func() {
	if a == nil || !a.enabled.Load() || item.UserID <= 0 || strings.TrimSpace(item.SourceIP) == "" {
		return func() {}
	}
	item.Network = strings.ToLower(strings.TrimSpace(item.Network))
	if item.Network == "" {
		item.Network = "tcp"
	}
	item.Destination = strings.TrimSpace(item.Destination)
	if len(item.Destination) > 255 {
		item.Destination = item.Destination[:255]
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	a.mu.Lock()
	if !a.enabled.Load() {
		a.mu.Unlock()
		return func() {}
	}
	key := fmt.Sprintf("%d\x00%d\x00%d\x00%d\x00%s\x00%s\x00%s\x00%d\x00%s\x00%s", a.generation, item.UserID, item.InboundID, item.PathID, item.SourceIP, item.Network, item.Destination, item.DestinationPort, item.OutboundTag, item.OutboundType)
	if a.buckets == nil {
		a.buckets = make(map[string]*agentAuditBucket)
	}
	bucket := a.buckets[key]
	if bucket == nil && len(a.buckets) < maxAgentAuditBuckets {
		item.StartedAt = now
		bucket = &agentAuditBucket{connectionAuditSnapshotItem: item, key: key}
		a.buckets[key] = bucket
	}
	if bucket != nil {
		if a.activeByUser == nil {
			a.activeByUser = make(map[int64]int64)
		}
		a.activeByUser[item.UserID]++
		bucket.ConnectionCount++
		bucket.active++
		if a.activeByUser[item.UserID] > bucket.ActivePeak {
			bucket.ActivePeak = a.activeByUser[item.UserID]
		}
		bucket.EndedAt = now
	}
	a.mu.Unlock()
	if bucket == nil {
		return func() {}
	}
	return func() { a.end(key) }
}

func (a *connectionAuditAccumulator) end(key string) {
	if a == nil || key == "" {
		return
	}
	a.mu.Lock()
	if bucket := a.buckets[key]; bucket != nil {
		if bucket.active > 0 {
			bucket.active--
			if active := a.activeByUser[bucket.UserID]; active > 1 {
				a.activeByUser[bucket.UserID] = active - 1
			} else {
				delete(a.activeByUser, bucket.UserID)
			}
		}
		bucket.EndedAt = time.Now().UTC().Format(time.RFC3339Nano)
	}
	a.mu.Unlock()
}

func (a *connectionAuditAccumulator) drain() []connectionAuditSnapshotItem {
	if a == nil || !a.enabled.Load() {
		return nil
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	now := time.Now().UTC().Format(time.RFC3339Nano)
	items := make([]connectionAuditSnapshotItem, 0, len(a.buckets))
	for key, bucket := range a.buckets {
		if bucket == nil {
			delete(a.buckets, key)
			continue
		}
		if bucket.ConnectionCount > 0 || bucket.active > 0 {
			item := bucket.connectionAuditSnapshotItem
			item.ActiveAtEnd = bucket.active
			if item.EndedAt == "" {
				item.EndedAt = now
			}
			items = append(items, item)
		}
		if bucket.active == 0 {
			delete(a.buckets, key)
			continue
		}
		bucket.ConnectionCount = 0
		bucket.ActivePeak = a.activeByUser[bucket.UserID]
		bucket.ActiveAtEnd = 0
		bucket.StartedAt = now
		bucket.EndedAt = now
	}
	return items
}

func (r *Runner) collectAndReportConnectionAudits(ctx context.Context) error {
	if !r.Config().ConnectionAuditEnabled {
		return nil
	}
	r.connectionAuditMu.Lock()
	defer r.connectionAuditMu.Unlock()
	state := r.connectionAuditStateLocked()
	if len(state.Pending) > 0 {
		return r.reportPendingConnectionAudits(ctx, state)
	}
	items, coreErr := r.coreConnectionAuditSnapshot(ctx)
	items = append(items, r.connectionAudit.drain()...)
	if coreErr != nil && len(items) == 0 {
		return coreErr
	}
	if len(items) == 0 {
		return nil
	}
	nowID := time.Now().UnixNano()
	for index, item := range items {
		if item.UserID <= 0 || strings.TrimSpace(item.SourceIP) == "" {
			continue
		}
		state.Pending = append(state.Pending, connectionAuditPendingReport{
			ReportID:                    fmt.Sprintf("%s-connection-%d-%d", r.Config().AgentID, nowID, index),
			connectionAuditSnapshotItem: item,
		})
	}
	if err := r.saveConnectionAuditState(*state); err != nil {
		return err
	}
	return r.reportPendingConnectionAudits(ctx, state)
}

func (r *Runner) configureCoreConnectionAudit(ctx context.Context, enabled bool) error {
	r.connectionAuditCoreMu.Lock()
	defer r.connectionAuditCoreMu.Unlock()
	r.connectionAuditCoreKnown = false
	client := r.coreClient
	if client == nil {
		client = unixHTTPClient(coreAPISocket)
	}
	body, err := json.Marshal(map[string]bool{"enabled": enabled})
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://oboard-sb/connections/config", bytes.NewReader(body))
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
		return fmt.Errorf("core connection audit config status %d", res.StatusCode)
	}
	r.connectionAuditCoreEnabled = enabled
	r.connectionAuditCoreKnown = true
	return nil
}

func (r *Runner) coreConnectionAuditNeedsSync(enabled bool) bool {
	r.connectionAuditCoreMu.Lock()
	defer r.connectionAuditCoreMu.Unlock()
	return !r.connectionAuditCoreKnown || r.connectionAuditCoreEnabled != enabled
}

func (r *Runner) setConnectionAuditPolicy(enabled bool) {
	cfg := r.Config()
	changed := cfg.ConnectionAuditEnabled != enabled
	if !changed && !r.coreConnectionAuditNeedsSync(enabled) {
		return
	}
	if changed {
		cfg.ConnectionAuditEnabled = enabled
		if strings.TrimSpace(cfg.ConfigPath) != "" {
			if err := SaveConfig(cfg.ConfigPath, cfg); err != nil {
				return
			}
		}
		r.storeConfig(cfg)
		r.connectionAudit.setEnabled(enabled)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	_ = r.configureCoreConnectionAudit(ctx, enabled)
	cancel()
	if changed && !enabled {
		r.connectionAuditMu.Lock()
		r.connectionAuditState = connectionAuditLocalState{}
		r.connectionAuditStateLoaded = false
		_ = os.Remove(r.connectionAuditStatePath())
		r.connectionAuditMu.Unlock()
	}
}

func (r *Runner) coreConnectionAuditSnapshot(ctx context.Context) ([]connectionAuditSnapshotItem, error) {
	client := r.coreClient
	if client == nil {
		client = unixHTTPClient(coreAPISocket)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://oboard-sb/connections/drain", nil)
	if err != nil {
		return nil, err
	}
	res, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	if res.StatusCode >= 300 {
		return nil, fmt.Errorf("core connection audit status %d", res.StatusCode)
	}
	var payload struct {
		Items []connectionAuditSnapshotItem `json:"items"`
	}
	if err := json.NewDecoder(res.Body).Decode(&payload); err != nil {
		return nil, err
	}
	return payload.Items, nil
}

func (r *Runner) reportPendingConnectionAudits(ctx context.Context, state *connectionAuditLocalState) error {
	if state == nil || len(state.Pending) == 0 {
		return nil
	}
	limit := len(state.Pending)
	if limit > connectionAuditReportBatchSize {
		limit = connectionAuditReportBatchSize
	}
	var resp connectionAuditReportResponse
	if err := r.postControllerJSON(ctx, "/api/v1/agent/connection-reports", map[string]any{"items": state.Pending[:limit]}, &resp, true); err != nil {
		return err
	}
	accepted := make(map[string]struct{}, len(resp.Accepted))
	for _, id := range resp.Accepted {
		accepted[id] = struct{}{}
	}
	remaining := state.Pending[:0]
	for _, report := range state.Pending {
		if _, ok := accepted[report.ReportID]; !ok {
			remaining = append(remaining, report)
		}
	}
	state.Pending = remaining
	return r.saveConnectionAuditState(*state)
}

func (r *Runner) connectionAuditStateLocked() *connectionAuditLocalState {
	if !r.connectionAuditStateLoaded {
		r.connectionAuditState = r.loadConnectionAuditState()
		r.connectionAuditStateLoaded = true
	}
	return &r.connectionAuditState
}

func (r *Runner) connectionAuditStatePath() string {
	return filepath.Join(r.stateDir(), "connection-audit-state.json")
}

func (r *Runner) loadConnectionAuditState() connectionAuditLocalState {
	var state connectionAuditLocalState
	b, err := os.ReadFile(r.connectionAuditStatePath())
	if err == nil {
		_ = json.Unmarshal(b, &state)
	}
	return state
}

func (r *Runner) saveConnectionAuditState(state connectionAuditLocalState) error {
	if err := os.MkdirAll(r.stateDir(), 0o700); err != nil {
		return err
	}
	sort.SliceStable(state.Pending, func(i, j int) bool { return state.Pending[i].ReportID < state.Pending[j].ReportID })
	b, err := json.Marshal(state)
	if err != nil {
		return err
	}
	return atomicWriteFile(r.connectionAuditStatePath(), b, 0o600)
}

func sourceIPFromNetAddr(address net.Addr) string {
	if address == nil {
		return ""
	}
	host, _, err := net.SplitHostPort(address.String())
	if err != nil {
		return ""
	}
	ip, err := netip.ParseAddr(strings.Trim(host, "[]"))
	if err != nil {
		return ""
	}
	return ip.Unmap().String()
}
