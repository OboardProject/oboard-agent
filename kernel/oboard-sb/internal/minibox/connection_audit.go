package minibox

import (
	"context"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/sagernet/sing-box/adapter"
)

const (
	maxConnectionAuditBuckets   = 4096
	maxConnectionPresenceEvents = 4096
	connectionPresenceRefresh   = 30 * time.Second
)

const connectionAuditHandleSeparator = "\xff"

// ConnectionAuditBucket is a bounded, payload-free summary of routed
// connections. The Agent drains these buckets and moves the history to the
// Controller; the kernel only retains the current reporting window.
type ConnectionAuditBucket struct {
	UserID             int64  `json:"user_id"`
	InboundID          int64  `json:"inbound_id,omitempty"`
	PathID             int64  `json:"path_id,omitempty"`
	DeviceIDHash       string `json:"device_id_hash,omitempty"`
	CredentialEpoch    int64  `json:"credential_epoch,omitempty"`
	SourceIP           string `json:"source_ip"`
	SourceGeoCode      string `json:"source_geo_code,omitempty"`
	Network            string `json:"network"`
	Destination        string `json:"destination,omitempty"`
	DestinationPort    int    `json:"destination_port,omitempty"`
	OutboundTag        string `json:"outbound_tag,omitempty"`
	OutboundType       string `json:"outbound_type,omitempty"`
	ConnectionCount    int64  `json:"connection_count"`
	ClosedCount        int64  `json:"closed_count"`
	DurationTotalMS    int64  `json:"duration_total_ms"`
	DurationMaxMS      int64  `json:"duration_max_ms"`
	UploadBytes        int64  `json:"upload_bytes"`
	DownloadBytes      int64  `json:"download_bytes"`
	PayloadFirstAt     string `json:"payload_first_at,omitempty"`
	PayloadLastAt      string `json:"payload_last_at,omitempty"`
	DurationLE1SCount  int64  `json:"duration_le_1s_count"`
	DurationLE5SCount  int64  `json:"duration_le_5s_count"`
	DurationLE20SCount int64  `json:"duration_le_20s_count"`
	DurationGT20SCount int64  `json:"duration_gt_20s_count"`
	ProbeState         string `json:"probe_state,omitempty"`
	InternalProbe      bool   `json:"internal_probe"`
	PresenceSequence   uint64 `json:"presence_sequence,omitempty"`
	ActivePeak         int64  `json:"active_peak"`
	ActiveAtEnd        int64  `json:"active_at_end"`
	StartedAt          string `json:"started_at"`
	EndedAt            string `json:"ended_at"`

	active         int64
	key            string
	activeIdentity string
}

type ConnectionPresenceEvent struct {
	Sequence          uint64 `json:"sequence"`
	UserID            int64  `json:"user_id"`
	InboundID         int64  `json:"inbound_id,omitempty"`
	PathID            int64  `json:"path_id,omitempty"`
	DeviceIDHash      string `json:"device_id_hash,omitempty"`
	CredentialEpoch   int64  `json:"credential_epoch,omitempty"`
	SourceIP          string `json:"source_ip"`
	Network           string `json:"network"`
	Event             string `json:"event"`
	State             string `json:"state"`
	ActiveConnections int64  `json:"active_connections"`
	Meaningful        bool   `json:"meaningful"`
	PayloadLastAt     string `json:"payload_last_at,omitempty"`
	At                string `json:"at"`
}

type ConnectionPresenceDrain struct {
	Events       []ConnectionPresenceEvent `json:"events"`
	DroppedCount int64                     `json:"dropped_count"`
}

type connectionPresenceState struct {
	ConnectionPresenceEvent
	lastEmittedAt time.Time
}

func (t *RateLimitTracker) FamilySelectorSelected(ctx context.Context, selectorTag, childTag, childType string) {
	selectorTag = strings.TrimSpace(selectorTag)
	childTag = strings.TrimSpace(childTag)
	childType = strings.TrimSpace(childType)
	if t == nil || selectorTag == "" || childTag == "" {
		return
	}
	metadata := adapter.ContextFrom(ctx)
	if metadata == nil {
		return
	}
	metadata.Outbound = childTag
	if !t.auditEnabled.Load() {
		return
	}
	t.auditMu.Lock()
	if t.auditFamilyChildTypes == nil {
		t.auditFamilyChildTypes = make(map[string]string)
	}
	if len(t.auditFamilyChildTypes) < maxConnectionAuditBuckets || t.auditFamilyChildTypes[childTag] != "" {
		t.auditFamilyChildTypes[childTag] = childType
	}
	t.auditMu.Unlock()
	state := t.runtimeFor(*metadata)
	if state == nil || state.currentConfig().policy.UserID <= 0 {
		return
	}
	sourceAddr := metadata.Source.Addr.Unmap()
	if !sourceAddr.IsValid() {
		return
	}
	destination := strings.TrimSpace(metadata.Destination.AddrString())
	if len(destination) > 255 {
		destination = destination[:255]
	}
	network := strings.TrimSpace(metadata.Network)
	if network == "" {
		network = "tcp"
	}
	baseKey := strings.Join([]string{
		state.key,
		sourceAddr.String(),
		network,
		destination,
		strconv.Itoa(int(metadata.Destination.Port)),
		selectorTag,
		"family-selector",
	}, "\x00")
	t.auditMu.Lock()
	defer t.auditMu.Unlock()
	bucket := t.auditBuckets[strconv.FormatUint(t.auditGeneration, 10)+"\x00"+baseKey]
	if bucket == nil {
		return
	}
	bucket.OutboundTag = childTag
	bucket.OutboundType = childType
}

func (t *RateLimitTracker) recordConnectionStart(state *runtimeState, metadata adapter.InboundContext, outbound adapter.Outbound, network string, admittedValue ...bool) string {
	if t == nil || state == nil || !t.auditEnabled.Load() {
		return ""
	}
	policy := state.currentConfig().policy
	if policy.UserID <= 0 {
		return ""
	}
	sourceAddr := metadata.Source.Addr.Unmap()
	if !sourceAddr.IsValid() {
		return ""
	}
	sourceIP := sourceAddr.String()
	destination := strings.TrimSpace(metadata.Destination.AddrString())
	if len(destination) > 255 {
		destination = destination[:255]
	}
	if network == "" {
		network = strings.TrimSpace(metadata.Network)
	}
	if network == "" {
		network = "tcp"
	}
	outboundTag := strings.TrimSpace(metadata.Outbound)
	outboundType := ""
	if outbound != nil {
		declaredTag := strings.TrimSpace(outbound.Tag())
		declaredType := strings.TrimSpace(outbound.Type())
		if declaredType == "family-selector" && outboundTag != "" && outboundTag != declaredTag {
			t.auditMu.Lock()
			outboundType = strings.TrimSpace(t.auditFamilyChildTypes[outboundTag])
			t.auditMu.Unlock()
			if outboundType == "" {
				outboundType = "family-branch"
			}
		} else {
			outboundTag = declaredTag
			outboundType = declaredType
		}
	}
	sourceGeoCode := strings.ToUpper(strings.TrimSpace(metadata.SourceGeoIPCode))
	if len(sourceGeoCode) != 2 {
		sourceGeoCode = ""
	}
	baseKey := strings.Join([]string{
		state.key,
		sourceIP,
		network,
		destination,
		strconv.Itoa(int(metadata.Destination.Port)),
		outboundTag,
		outboundType,
	}, "\x00")
	now := t.timeNow().UTC()
	admitted := true
	if len(admittedValue) > 0 {
		admitted = admittedValue[0]
	}

	t.auditMu.Lock()
	defer t.auditMu.Unlock()
	if !t.auditEnabled.Load() {
		return ""
	}
	key := strconv.FormatUint(t.auditGeneration, 10) + "\x00" + baseKey
	if t.auditBuckets == nil {
		t.auditBuckets = make(map[string]*ConnectionAuditBucket)
	}
	bucket := t.auditBuckets[key]
	if bucket == nil {
		if len(t.auditBuckets) >= maxConnectionAuditBuckets {
			t.auditDropped++
			return ""
		}
		bucket = &ConnectionAuditBucket{
			UserID:           policy.UserID,
			InboundID:        policy.InboundID,
			PathID:           policy.PathID,
			DeviceIDHash:     policy.DeviceIDHash,
			CredentialEpoch:  policy.CredentialEpoch,
			SourceIP:         sourceIP,
			SourceGeoCode:    sourceGeoCode,
			Network:          network,
			Destination:      destination,
			DestinationPort:  int(metadata.Destination.Port),
			OutboundTag:      outboundTag,
			OutboundType:     outboundType,
			PresenceSequence: t.auditPresenceSequence.Add(1),
			StartedAt:        now.Format(time.RFC3339Nano),
			key:              key,
			activeIdentity:   connectionAuditActiveIdentity(policy.UserID, policy.DeviceIDHash, sourceIP),
		}
		t.auditBuckets[key] = bucket
	}
	if t.auditActiveByIdentity == nil {
		t.auditActiveByIdentity = make(map[string]int64)
	}
	identityKey := bucket.activeIdentity
	t.auditActiveByIdentity[identityKey]++
	bucket.ConnectionCount++
	bucket.active++
	if t.auditActiveByIdentity[identityKey] > bucket.ActivePeak {
		bucket.ActivePeak = t.auditActiveByIdentity[identityKey]
	}
	advanceAuditEnd(bucket, now)
	presenceKey := connectionPresenceKey(policy.UserID, policy.DeviceIDHash, policy.CredentialEpoch, sourceIP, network)
	if admitted {
		presence := t.presenceStates[presenceKey]
		if presence == nil {
			if t.presenceStates == nil {
				t.presenceStates = make(map[string]*connectionPresenceState)
			}
			presence = &connectionPresenceState{ConnectionPresenceEvent: ConnectionPresenceEvent{UserID: policy.UserID, InboundID: policy.InboundID, PathID: policy.PathID, DeviceIDHash: policy.DeviceIDHash, CredentialEpoch: policy.CredentialEpoch, SourceIP: sourceIP, Network: network, State: "active"}}
			t.presenceStates[presenceKey] = presence
		}
		presence.ActiveConnections++
		if presence.ActiveConnections == 1 {
			t.enqueuePresenceEventLocked(presence, "first_authenticated", now)
		}
	} else {
		rejected := &connectionPresenceState{ConnectionPresenceEvent: ConnectionPresenceEvent{UserID: policy.UserID, InboundID: policy.InboundID, PathID: policy.PathID, DeviceIDHash: policy.DeviceIDHash, CredentialEpoch: policy.CredentialEpoch, SourceIP: sourceIP, Network: network, State: "rejected"}}
		t.enqueuePresenceEventLocked(rejected, "credential_rejected", now)
	}
	return strings.Join([]string{key, strconv.FormatInt(now.UnixNano(), 10), presenceKey, strconv.FormatBool(admitted)}, connectionAuditHandleSeparator)
}

func (t *RateLimitTracker) recordConnectionPayload(handle string, upload, download int64) {
	if t == nil || handle == "" || upload < 0 || download < 0 || upload+download <= 0 {
		return
	}
	parts := strings.Split(handle, connectionAuditHandleSeparator)
	key := parts[0]
	t.auditMu.Lock()
	defer t.auditMu.Unlock()
	bucket := t.auditBuckets[key]
	if bucket == nil {
		return
	}
	nowTime := t.timeNow().UTC()
	now := nowTime.Format(time.RFC3339Nano)
	if bucket.PayloadFirstAt == "" {
		bucket.PayloadFirstAt = now
	}
	bucket.PayloadLastAt = now
	bucket.UploadBytes += upload
	bucket.DownloadBytes += download
	// A bucket that survived a drain keeps its window end at the drain
	// boundary. Payload recorded afterwards must move that end forward too, or
	// the next drain would emit payload_last_at > ended_at.
	advanceAuditEnd(bucket, nowTime)
	if len(parts) >= 4 && parts[3] == "true" {
		if presence := t.presenceStates[parts[2]]; presence != nil {
			firstPayload := !presence.Meaningful
			presence.Meaningful = true
			presence.PayloadLastAt = now
			if firstPayload {
				t.enqueuePresenceEventLocked(presence, "first_meaningful_payload", t.timeNow().UTC())
			}
		}
	}
}

func (t *RateLimitTracker) recordConnectionEnd(handle string) {
	if t == nil || handle == "" {
		return
	}
	parts := strings.Split(handle, connectionAuditHandleSeparator)
	key := parts[0]
	startedRaw := ""
	if len(parts) >= 2 {
		startedRaw = parts[1]
	}
	startedNano, _ := strconv.ParseInt(startedRaw, 10, 64)
	t.auditMu.Lock()
	defer t.auditMu.Unlock()
	if bucket := t.auditBuckets[key]; bucket != nil {
		if bucket.active > 0 {
			bucket.active--
			if active := t.auditActiveByIdentity[bucket.activeIdentity]; active > 1 {
				t.auditActiveByIdentity[bucket.activeIdentity] = active - 1
			} else {
				delete(t.auditActiveByIdentity, bucket.activeIdentity)
			}
		}
		now := t.timeNow().UTC()
		if startedNano > 0 {
			duration := now.Sub(time.Unix(0, startedNano)).Milliseconds()
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
		}
		advanceAuditEnd(bucket, now)
	}
	if len(parts) >= 4 && parts[3] == "true" {
		if presence := t.presenceStates[parts[2]]; presence != nil {
			if presence.ActiveConnections > 0 {
				presence.ActiveConnections--
			}
			if presence.ActiveConnections == 0 {
				presence.State = "inactive"
				t.enqueuePresenceEventLocked(presence, "last_connection_closed", t.timeNow().UTC())
				delete(t.presenceStates, parts[2])
			}
		}
	}
}

// advanceAuditEnd moves a bucket's window end forward without ever moving it
// backwards, and keeps it at or after the bucket's start and last payload time.
// Controller rejects a report whose payload_last_at is later than ended_at, so
// every writer must go through this helper.
func advanceAuditEnd(bucket *ConnectionAuditBucket, now time.Time) {
	if bucket == nil {
		return
	}
	end := now.UTC()
	if current, err := time.Parse(time.RFC3339Nano, bucket.EndedAt); err == nil && current.After(end) {
		end = current
	}
	if started, err := time.Parse(time.RFC3339Nano, bucket.StartedAt); err == nil && started.After(end) {
		end = started
	}
	if payload, err := time.Parse(time.RFC3339Nano, bucket.PayloadLastAt); err == nil && payload.After(end) {
		end = payload
	}
	bucket.EndedAt = end.Format(time.RFC3339Nano)
}

// normalizeAuditItemWindow is the last defence before a bucket leaves the
// kernel. The logical clock may step slightly backwards, so the emitted item is
// clamped into
// collection_started_at <= started_at <= payload_first_at <= payload_last_at <= ended_at <= collection_ended_at.
func normalizeAuditItemWindow(item *ConnectionAuditBucket, collectionStarted, collectionEnded time.Time) {
	if item == nil {
		return
	}
	parse := func(value string) (time.Time, bool) {
		parsed, err := time.Parse(time.RFC3339Nano, value)
		return parsed.UTC(), err == nil
	}
	format := func(value time.Time) string { return value.UTC().Format(time.RFC3339Nano) }
	started, hasStarted := parse(item.StartedAt)
	if !hasStarted || started.Before(collectionStarted) {
		started = collectionStarted
	}
	if started.After(collectionEnded) {
		started = collectionEnded
	}
	ended, hasEnded := parse(item.EndedAt)
	if !hasEnded || ended.Before(started) {
		ended = started
	}
	payloadFirst, hasPayloadFirst := parse(item.PayloadFirstAt)
	payloadLast, hasPayloadLast := parse(item.PayloadLastAt)
	if hasPayloadFirst || hasPayloadLast {
		if !hasPayloadFirst {
			payloadFirst = payloadLast
		}
		if !hasPayloadLast {
			payloadLast = payloadFirst
		}
		if payloadFirst.Before(started) {
			payloadFirst = started
		}
		if payloadLast.Before(payloadFirst) {
			payloadLast = payloadFirst
		}
		if payloadLast.After(collectionEnded) {
			payloadLast = collectionEnded
		}
		if payloadFirst.After(payloadLast) {
			payloadFirst = payloadLast
		}
		if ended.Before(payloadLast) {
			ended = payloadLast
		}
		item.PayloadFirstAt = format(payloadFirst)
		item.PayloadLastAt = format(payloadLast)
	}
	if ended.After(collectionEnded) {
		ended = collectionEnded
	}
	if ended.Before(started) {
		started = ended
	}
	item.StartedAt = format(started)
	item.EndedAt = format(ended)
}

func connectionPresenceKey(userID int64, deviceIDHash string, credentialEpoch int64, sourceIP, network string) string {
	return strings.Join([]string{strconv.FormatInt(userID, 10), strings.TrimSpace(deviceIDHash), strconv.FormatInt(credentialEpoch, 10), strings.TrimSpace(sourceIP), strings.ToLower(strings.TrimSpace(network))}, "\x00")
}

func (t *RateLimitTracker) enqueuePresenceEventLocked(state *connectionPresenceState, event string, at time.Time) {
	if state == nil || event == "" {
		return
	}
	state.Event = event
	state.At = at.UTC().Format(time.RFC3339Nano)
	state.Sequence = t.auditPresenceSequence.Add(1)
	state.lastEmittedAt = at.UTC()
	item := state.ConnectionPresenceEvent
	if len(t.presenceEvents) >= maxConnectionPresenceEvents {
		t.presenceDropped++
		return
	}
	t.presenceEvents = append(t.presenceEvents, item)
}

func (t *RateLimitTracker) DrainConnectionPresenceEvents() ConnectionPresenceDrain {
	if t == nil || !t.auditEnabled.Load() {
		return ConnectionPresenceDrain{}
	}
	t.auditMu.Lock()
	defer t.auditMu.Unlock()
	now := t.timeNow().UTC()
	for _, state := range t.presenceStates {
		if state != nil && state.ActiveConnections > 0 && now.Sub(state.lastEmittedAt) >= connectionPresenceRefresh {
			t.enqueuePresenceEventLocked(state, "activity_refresh", now)
		}
	}
	drain := ConnectionPresenceDrain{Events: append([]ConnectionPresenceEvent(nil), t.presenceEvents...), DroppedCount: t.presenceDropped}
	t.presenceEvents = nil
	t.presenceDropped = 0
	return drain
}

type ConnectionAuditDrain struct {
	Items                []ConnectionAuditBucket `json:"items"`
	CollectionGeneration uint64                  `json:"collection_generation"`
	BucketCapacity       int                     `json:"bucket_capacity"`
	DroppedBucketCount   int64                   `json:"dropped_bucket_count"`
	CollectionStartedAt  string                  `json:"collection_started_at"`
	CollectionEndedAt    string                  `json:"collection_ended_at"`
}

// DrainConnectionAudits atomically advances the in-kernel reporting window.
// Buckets with active connections remain so their eventual close is tracked.
func (t *RateLimitTracker) DrainConnectionAudits() []ConnectionAuditBucket {
	return t.DrainConnectionAuditSnapshot().Items
}

func (t *RateLimitTracker) DrainConnectionAuditSnapshot() ConnectionAuditDrain {
	if t == nil || !t.auditEnabled.Load() {
		return ConnectionAuditDrain{BucketCapacity: maxConnectionAuditBuckets}
	}
	t.auditMu.Lock()
	defer t.auditMu.Unlock()
	nowTime := t.timeNow().UTC()
	now := nowTime.Format(time.RFC3339Nano)
	started := t.auditWindowStart
	if started.IsZero() || started.After(nowTime) {
		// The logical clock may step slightly backwards. Collapse the window
		// instead of emitting collection_ended_at < collection_started_at,
		// which Controller rejects for the whole batch.
		started = nowTime
	}
	drain := ConnectionAuditDrain{CollectionGeneration: t.auditGeneration, BucketCapacity: maxConnectionAuditBuckets, DroppedBucketCount: t.auditDropped, CollectionStartedAt: started.Format(time.RFC3339Nano), CollectionEndedAt: now}
	items := make([]ConnectionAuditBucket, 0, len(t.auditBuckets))
	for key, bucket := range t.auditBuckets {
		if bucket == nil {
			delete(t.auditBuckets, key)
			continue
		}
		if bucket.ConnectionCount > 0 || bucket.active > 0 {
			item := *bucket
			item.ActiveAtEnd = bucket.active
			item.active = 0
			item.key = ""
			if item.EndedAt == "" {
				item.EndedAt = now
			}
			normalizeAuditItemWindow(&item, started, nowTime)
			items = append(items, item)
		}
		if bucket.active == 0 {
			delete(t.auditBuckets, key)
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
		bucket.PresenceSequence = t.auditPresenceSequence.Add(1)
		bucket.ActivePeak = t.auditActiveByIdentity[bucket.activeIdentity]
		bucket.ActiveAtEnd = 0
		bucket.StartedAt = now
		bucket.EndedAt = now
	}
	sort.Slice(items, func(i, j int) bool {
		if items[i].UserID != items[j].UserID {
			return items[i].UserID < items[j].UserID
		}
		if items[i].SourceIP != items[j].SourceIP {
			return items[i].SourceIP < items[j].SourceIP
		}
		if items[i].Destination != items[j].Destination {
			return items[i].Destination < items[j].Destination
		}
		return items[i].DestinationPort < items[j].DestinationPort
	})
	drain.Items = items
	t.auditDropped = 0
	t.auditWindowStart = nowTime
	return drain
}

func connectionAuditActiveIdentity(userID int64, deviceIDHash, sourceIP string) string {
	deviceIDHash = strings.TrimSpace(deviceIDHash)
	if deviceIDHash != "" {
		return strconv.FormatInt(userID, 10) + "\x00device:" + deviceIDHash
	}
	return strconv.FormatInt(userID, 10) + "\x00legacy:" + strings.TrimSpace(sourceIP)
}
