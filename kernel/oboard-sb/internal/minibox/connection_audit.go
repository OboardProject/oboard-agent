package minibox

import (
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/sagernet/sing-box/adapter"
)

const maxConnectionAuditBuckets = 4096

// ConnectionAuditBucket is a bounded, payload-free summary of routed
// connections. The Agent drains these buckets and moves the history to the
// Controller; the kernel only retains the current reporting window.
type ConnectionAuditBucket struct {
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

	active int64
	key    string
}

func (t *RateLimitTracker) recordConnectionStart(state *runtimeState, metadata adapter.InboundContext, outbound adapter.Outbound, network string) string {
	if t == nil || state == nil || !t.auditEnabled.Load() {
		return ""
	}
	policy := state.currentConfig().policy
	if policy.UserID <= 0 || !metadata.Source.Addr.IsValid() {
		return ""
	}
	sourceIP := metadata.Source.Addr.Unmap().String()
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
		outboundTag = strings.TrimSpace(outbound.Tag())
		outboundType = strings.TrimSpace(outbound.Type())
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
	now := time.Now().UTC()

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
			return ""
		}
		bucket = &ConnectionAuditBucket{
			UserID:          policy.UserID,
			InboundID:       policy.InboundID,
			PathID:          policy.PathID,
			SourceIP:        sourceIP,
			SourceGeoCode:   sourceGeoCode,
			Network:         network,
			Destination:     destination,
			DestinationPort: int(metadata.Destination.Port),
			OutboundTag:     outboundTag,
			OutboundType:    outboundType,
			StartedAt:       now.Format(time.RFC3339Nano),
			key:             key,
		}
		t.auditBuckets[key] = bucket
	}
	if t.auditActiveByUser == nil {
		t.auditActiveByUser = make(map[int64]int64)
	}
	t.auditActiveByUser[policy.UserID]++
	bucket.ConnectionCount++
	bucket.active++
	if t.auditActiveByUser[policy.UserID] > bucket.ActivePeak {
		bucket.ActivePeak = t.auditActiveByUser[policy.UserID]
	}
	bucket.EndedAt = now.Format(time.RFC3339Nano)
	return key
}

func (t *RateLimitTracker) recordConnectionEnd(key string) {
	if t == nil || key == "" {
		return
	}
	t.auditMu.Lock()
	defer t.auditMu.Unlock()
	if bucket := t.auditBuckets[key]; bucket != nil {
		if bucket.active > 0 {
			bucket.active--
			if active := t.auditActiveByUser[bucket.UserID]; active > 1 {
				t.auditActiveByUser[bucket.UserID] = active - 1
			} else {
				delete(t.auditActiveByUser, bucket.UserID)
			}
		}
		bucket.EndedAt = time.Now().UTC().Format(time.RFC3339Nano)
	}
}

// DrainConnectionAudits atomically advances the in-kernel reporting window.
// Buckets with active connections remain so their eventual close is tracked.
func (t *RateLimitTracker) DrainConnectionAudits() []ConnectionAuditBucket {
	if t == nil || !t.auditEnabled.Load() {
		return nil
	}
	t.auditMu.Lock()
	defer t.auditMu.Unlock()
	now := time.Now().UTC().Format(time.RFC3339Nano)
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
			items = append(items, item)
		}
		if bucket.active == 0 {
			delete(t.auditBuckets, key)
			continue
		}
		bucket.ConnectionCount = 0
		bucket.ActivePeak = t.auditActiveByUser[bucket.UserID]
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
	return items
}
