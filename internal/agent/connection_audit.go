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
	maxAgentPresenceEvents         = 2048
	agentPresenceRefreshInterval   = 30 * time.Second
)

type connectionPresenceEvent struct {
	Sequence          uint64 `json:"seq"`
	UserID            int64  `json:"user_id"`
	InboundID         int64  `json:"inbound_id,omitempty"`
	PathID            int64  `json:"path_id,omitempty"`
	DeviceIDHash      string `json:"device_id_hash,omitempty"`
	CredentialEpoch   int64  `json:"credential_epoch,omitempty"`
	ServerID          int64  `json:"server_id,omitempty"`
	SourceIP          string `json:"source_ip"`
	Network           string `json:"network"`
	Event             string `json:"event"`
	State             string `json:"state"`
	ActiveConnections int64  `json:"active_connections"`
	Meaningful        bool   `json:"meaningful"`
	PayloadLastAt     string `json:"payload_last_at,omitempty"`
	At                string `json:"at"`
}

type connectionAuditSnapshotItem struct {
	UserID               int64  `json:"user_id"`
	InboundID            int64  `json:"inbound_id,omitempty"`
	PathID               int64  `json:"path_id,omitempty"`
	DeviceIDHash         string `json:"device_id_hash,omitempty"`
	CredentialEpoch      int64  `json:"credential_epoch,omitempty"`
	ClientInstanceIDHash string `json:"client_instance_id_hash,omitempty"`
	SourceIP             string `json:"source_ip"`
	SourceGeoCode        string `json:"source_geo_code,omitempty"`
	Network              string `json:"network"`
	Destination          string `json:"destination,omitempty"`
	DestinationPort      int    `json:"destination_port,omitempty"`
	OutboundTag          string `json:"outbound_tag,omitempty"`
	OutboundType         string `json:"outbound_type,omitempty"`
	ConnectionCount      int64  `json:"connection_count"`
	ClosedCount          int64  `json:"closed_count"`
	DurationTotalMS      int64  `json:"duration_total_ms"`
	DurationMaxMS        int64  `json:"duration_max_ms"`
	UploadBytes          int64  `json:"upload_bytes"`
	DownloadBytes        int64  `json:"download_bytes"`
	PayloadFirstAt       string `json:"payload_first_at,omitempty"`
	PayloadLastAt        string `json:"payload_last_at,omitempty"`
	DurationLE1SCount    int64  `json:"duration_le_1s_count"`
	DurationLE5SCount    int64  `json:"duration_le_5s_count"`
	DurationLE20SCount   int64  `json:"duration_le_20s_count"`
	DurationGT20SCount   int64  `json:"duration_gt_20s_count"`
	ProbeState           string `json:"probe_state,omitempty"`
	InternalProbe        bool   `json:"internal_probe"`
	PresenceSequence     uint64 `json:"presence_sequence,omitempty"`
	ActivePeak           int64  `json:"active_peak"`
	ActiveAtEnd          int64  `json:"active_at_end"`
	StartedAt            string `json:"started_at"`
	EndedAt              string `json:"ended_at"`
	CollectionGeneration uint64 `json:"collection_generation"`
	BucketCapacity       int    `json:"bucket_capacity"`
	DroppedBucketCount   int64  `json:"dropped_bucket_count"`
	CollectionStartedAt  string `json:"collection_started_at"`
	CollectionEndedAt    string `json:"collection_ended_at"`
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
	key            string
	activeIdentity string
	active         int64
}

type connectionAuditAccumulator struct {
	mu               sync.Mutex
	buckets          map[string]*agentAuditBucket
	activeByIdentity map[string]int64
	generation       uint64
	dropped          int64
	presenceSeq      uint64
	presenceStates   map[string]*agentConnectionPresenceState
	presenceEvents   []connectionPresenceEvent
	presenceDropped  int64
	windowStart      time.Time
	enabled          atomic.Bool
}

type connectionAuditSession struct {
	audit       *connectionAuditAccumulator
	key         string
	presenceKey string
	started     time.Time
	once        sync.Once
}

type agentConnectionPresenceState struct {
	connectionPresenceEvent
	lastEmittedAt time.Time
}

func newConnectionAuditAccumulator(enabled bool) *connectionAuditAccumulator {
	a := &connectionAuditAccumulator{}
	a.enabled.Store(enabled)
	if enabled {
		a.windowStart = time.Now().UTC()
	}
	return a
}

func (a *connectionAuditAccumulator) setEnabled(enabled bool) {
	if a == nil {
		return
	}
	wasEnabled := a.enabled.Swap(enabled)
	if enabled {
		if !wasEnabled {
			a.mu.Lock()
			a.windowStart = time.Now().UTC()
			a.dropped = 0
			a.mu.Unlock()
		}
		return
	}
	a.mu.Lock()
	a.buckets = nil
	a.activeByIdentity = nil
	a.presenceStates = nil
	a.presenceEvents = nil
	a.presenceDropped = 0
	a.generation++
	a.dropped = 0
	a.windowStart = time.Time{}
	a.mu.Unlock()
}

func (a *connectionAuditAccumulator) start(item connectionAuditSnapshotItem) func() {
	session := a.startSession(item)
	return session.finish
}

func (a *connectionAuditAccumulator) startSession(item connectionAuditSnapshotItem) *connectionAuditSession {
	session := &connectionAuditSession{}
	if a == nil || !a.enabled.Load() || item.UserID <= 0 || strings.TrimSpace(item.SourceIP) == "" {
		return session
	}
	item.Network = strings.ToLower(strings.TrimSpace(item.Network))
	if item.Network == "" {
		item.Network = "tcp"
	}
	item.Destination = strings.TrimSpace(item.Destination)
	if len(item.Destination) > 255 {
		item.Destination = item.Destination[:255]
	}
	started := time.Now().UTC()
	now := started.Format(time.RFC3339Nano)
	a.mu.Lock()
	if !a.enabled.Load() {
		a.mu.Unlock()
		return session
	}
	key := fmt.Sprintf("%d\x00%d\x00%d\x00%d\x00%s\x00%s\x00%s\x00%s\x00%d\x00%s\x00%s", a.generation, item.UserID, item.InboundID, item.PathID, item.DeviceIDHash, item.SourceIP, item.Network, item.Destination, item.DestinationPort, item.OutboundTag, item.OutboundType)
	if a.buckets == nil {
		a.buckets = make(map[string]*agentAuditBucket)
	}
	bucket := a.buckets[key]
	if bucket == nil && len(a.buckets) < maxAgentAuditBuckets {
		item.StartedAt = now
		a.presenceSeq++
		item.PresenceSequence = a.presenceSeq
		bucket = &agentAuditBucket{connectionAuditSnapshotItem: item, key: key, activeIdentity: connectionAuditActiveIdentity(item.UserID, item.DeviceIDHash, item.SourceIP)}
		a.buckets[key] = bucket
	} else if bucket == nil {
		a.dropped++
	}
	if bucket != nil {
		if a.activeByIdentity == nil {
			a.activeByIdentity = make(map[string]int64)
		}
		identityKey := bucket.activeIdentity
		a.activeByIdentity[identityKey]++
		bucket.ConnectionCount++
		bucket.active++
		if a.activeByIdentity[identityKey] > bucket.ActivePeak {
			bucket.ActivePeak = a.activeByIdentity[identityKey]
		}
		bucket.EndedAt = now
		presenceKey := agentConnectionPresenceKey(item)
		presence := a.presenceStates[presenceKey]
		if presence == nil {
			if a.presenceStates == nil {
				a.presenceStates = make(map[string]*agentConnectionPresenceState)
			}
			presence = &agentConnectionPresenceState{connectionPresenceEvent: connectionPresenceEvent{UserID: item.UserID, InboundID: item.InboundID, PathID: item.PathID, DeviceIDHash: item.DeviceIDHash, CredentialEpoch: item.CredentialEpoch, SourceIP: item.SourceIP, Network: item.Network, State: "active"}}
			a.presenceStates[presenceKey] = presence
		}
		presence.ActiveConnections++
		if presence.ActiveConnections == 1 {
			a.enqueuePresenceEventLocked(presence, "first_authenticated", started)
		}
		session.presenceKey = presenceKey
	}
	a.mu.Unlock()
	if bucket == nil {
		return session
	}
	session.audit = a
	session.key = key
	session.started = started
	return session
}

func (s *connectionAuditSession) addTraffic(upload bool, bytes int64) {
	if s == nil || s.audit == nil || s.key == "" || bytes <= 0 {
		return
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	s.audit.mu.Lock()
	if bucket := s.audit.buckets[s.key]; bucket != nil {
		if upload {
			bucket.UploadBytes += bytes
		} else {
			bucket.DownloadBytes += bytes
		}
		if bucket.PayloadFirstAt == "" {
			bucket.PayloadFirstAt = now
		}
		bucket.PayloadLastAt = now
		bucket.EndedAt = now
	}
	if presence := s.audit.presenceStates[s.presenceKey]; presence != nil {
		firstPayload := !presence.Meaningful
		presence.Meaningful = true
		presence.PayloadLastAt = now
		if firstPayload {
			s.audit.enqueuePresenceEventLocked(presence, "first_meaningful_payload", time.Now().UTC())
		}
	}
	s.audit.mu.Unlock()
}

func (s *connectionAuditSession) finish() {
	if s == nil || s.audit == nil || s.key == "" {
		return
	}
	s.once.Do(func() {
		s.audit.end(s.key, s.started)
		s.audit.endPresence(s.presenceKey)
	})
}

func agentConnectionPresenceKey(item connectionAuditSnapshotItem) string {
	return fmt.Sprintf("%d\x00%d\x00%d\x00%s\x00%d\x00%s\x00%s", item.UserID, item.InboundID, item.PathID, strings.TrimSpace(item.DeviceIDHash), item.CredentialEpoch, strings.TrimSpace(item.SourceIP), strings.ToLower(strings.TrimSpace(item.Network)))
}

func (a *connectionAuditAccumulator) enqueuePresenceEventLocked(state *agentConnectionPresenceState, event string, at time.Time) {
	if state == nil || event == "" {
		return
	}
	state.Event = event
	state.At = at.UTC().Format(time.RFC3339Nano)
	state.lastEmittedAt = at.UTC()
	if len(a.presenceEvents) >= maxAgentPresenceEvents {
		a.presenceDropped++
		return
	}
	a.presenceEvents = append(a.presenceEvents, state.connectionPresenceEvent)
}

func (a *connectionAuditAccumulator) endPresence(key string) {
	if a == nil || key == "" {
		return
	}
	a.mu.Lock()
	if presence := a.presenceStates[key]; presence != nil {
		if presence.ActiveConnections > 0 {
			presence.ActiveConnections--
		}
		if presence.ActiveConnections == 0 {
			presence.State = "inactive"
			a.enqueuePresenceEventLocked(presence, "last_connection_closed", time.Now().UTC())
			delete(a.presenceStates, key)
		}
	}
	a.mu.Unlock()
}

func (a *connectionAuditAccumulator) recordCredentialRejected(item connectionAuditSnapshotItem) {
	if a == nil || !a.enabled.Load() || item.UserID <= 0 || strings.TrimSpace(item.SourceIP) == "" {
		return
	}
	if item.Network == "" {
		item.Network = "tcp"
	}
	a.mu.Lock()
	rejected := &agentConnectionPresenceState{connectionPresenceEvent: connectionPresenceEvent{UserID: item.UserID, InboundID: item.InboundID, PathID: item.PathID, DeviceIDHash: item.DeviceIDHash, CredentialEpoch: item.CredentialEpoch, SourceIP: item.SourceIP, Network: item.Network, State: "rejected"}}
	a.enqueuePresenceEventLocked(rejected, "credential_rejected", time.Now().UTC())
	a.mu.Unlock()
}

func (a *connectionAuditAccumulator) drainPresenceEvents() ([]connectionPresenceEvent, int64) {
	if a == nil || !a.enabled.Load() {
		return nil, 0
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	now := time.Now().UTC()
	for _, state := range a.presenceStates {
		if state != nil && state.ActiveConnections > 0 && now.Sub(state.lastEmittedAt) >= agentPresenceRefreshInterval {
			a.enqueuePresenceEventLocked(state, "activity_refresh", now)
		}
	}
	events := append([]connectionPresenceEvent(nil), a.presenceEvents...)
	dropped := a.presenceDropped
	a.presenceEvents = nil
	a.presenceDropped = 0
	return events, dropped
}

func (a *connectionAuditAccumulator) end(key string, started time.Time) {
	if a == nil || key == "" {
		return
	}
	a.mu.Lock()
	if bucket := a.buckets[key]; bucket != nil {
		if bucket.active > 0 {
			bucket.active--
			if active := a.activeByIdentity[bucket.activeIdentity]; active > 1 {
				a.activeByIdentity[bucket.activeIdentity] = active - 1
			} else {
				delete(a.activeByIdentity, bucket.activeIdentity)
			}
		}
		now := time.Now().UTC()
		duration := now.Sub(started).Milliseconds()
		if duration < 0 {
			duration = 0
		}
		bucket.ClosedCount++
		bucket.DurationTotalMS += duration
		if duration > bucket.DurationMaxMS {
			bucket.DurationMaxMS = duration
		}
		switch {
		case duration <= 1000:
			bucket.DurationLE1SCount++
		case duration <= 5000:
			bucket.DurationLE5SCount++
		case duration <= 20000:
			bucket.DurationLE20SCount++
		default:
			bucket.DurationGT20SCount++
		}
		bucket.EndedAt = now.Format(time.RFC3339Nano)
	}
	a.mu.Unlock()
}

func (a *connectionAuditAccumulator) drain() []connectionAuditSnapshotItem {
	if a == nil || !a.enabled.Load() {
		return nil
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	nowTime := time.Now().UTC()
	now := nowTime.Format(time.RFC3339Nano)
	started := a.windowStart
	if started.IsZero() {
		started = nowTime
	}
	items := make([]connectionAuditSnapshotItem, 0, len(a.buckets))
	for key, bucket := range a.buckets {
		if bucket == nil {
			delete(a.buckets, key)
			continue
		}
		if bucket.ConnectionCount > 0 || bucket.active > 0 {
			item := bucket.connectionAuditSnapshotItem
			item.ActiveAtEnd = bucket.active
			item.CollectionGeneration = a.generation
			item.BucketCapacity = maxAgentAuditBuckets
			item.DroppedBucketCount = a.dropped
			item.CollectionStartedAt = started.Format(time.RFC3339Nano)
			item.CollectionEndedAt = now
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
		bucket.ClosedCount = 0
		bucket.DurationTotalMS = 0
		bucket.DurationMaxMS = 0
		bucket.UploadBytes = 0
		bucket.DownloadBytes = 0
		bucket.PayloadFirstAt = ""
		bucket.PayloadLastAt = ""
		bucket.DurationLE1SCount = 0
		bucket.DurationLE5SCount = 0
		bucket.DurationLE20SCount = 0
		bucket.DurationGT20SCount = 0
		bucket.ProbeState = ""
		bucket.InternalProbe = false
		a.presenceSeq++
		bucket.PresenceSequence = a.presenceSeq
		bucket.ActivePeak = a.activeByIdentity[bucket.activeIdentity]
		bucket.ActiveAtEnd = 0
		bucket.StartedAt = now
		bucket.EndedAt = now
	}
	a.dropped = 0
	a.windowStart = nowTime
	return items
}

func connectionAuditActiveIdentity(userID int64, deviceIDHash, sourceIP string) string {
	deviceIDHash = strings.TrimSpace(deviceIDHash)
	if deviceIDHash != "" {
		return fmt.Sprintf("%d\x00device:%s", userID, deviceIDHash)
	}
	return fmt.Sprintf("%d\x00legacy:%s", userID, strings.TrimSpace(sourceIP))
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
		Items                []connectionAuditSnapshotItem `json:"items"`
		CollectionGeneration uint64                        `json:"collection_generation"`
		BucketCapacity       int                           `json:"bucket_capacity"`
		DroppedBucketCount   int64                         `json:"dropped_bucket_count"`
		CollectionStartedAt  string                        `json:"collection_started_at"`
		CollectionEndedAt    string                        `json:"collection_ended_at"`
	}
	if err := json.NewDecoder(res.Body).Decode(&payload); err != nil {
		return nil, err
	}
	for index := range payload.Items {
		payload.Items[index].CollectionGeneration = payload.CollectionGeneration
		payload.Items[index].BucketCapacity = payload.BucketCapacity
		payload.Items[index].DroppedBucketCount = payload.DroppedBucketCount
		payload.Items[index].CollectionStartedAt = payload.CollectionStartedAt
		payload.Items[index].CollectionEndedAt = payload.CollectionEndedAt
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
