package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

const connectionPresencePollInterval = time.Second
const connectionPresenceCapability = "connection_presence_v1"

// Controller rejects a delta carrying more than 500 events and closes the
// websocket once a frame passes its 1 MiB read limit, so one poll is written as
// several contract-sized messages instead of a single oversized frame.
const connectionPresenceDeltaBatchSize = 500

// Undelivered events are kept for another connection, bounded so a long outage
// cannot grow the buffer without limit on a small node.
const maxPendingPresenceEvents = 4096

// Controller rejects an event whose observation time left its acceptance
// window, and one rejected event fails the whole delta. Expired events are
// dropped locally before they can poison a later batch.
const connectionPresenceEventMaxAge = 5 * time.Minute

type connectionPresenceDelta struct {
	Events       []connectionPresenceEvent `json:"events"`
	DroppedCount int64                     `json:"dropped_count"`
}

type coreConnectionPresenceEvent struct {
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

func (r *Runner) collectConnectionPresenceDelta(ctx context.Context) (connectionPresenceDelta, error) {
	if !r.Config().ConnectionAuditEnabled {
		r.discardPendingPresenceEvents()
		return connectionPresenceDelta{}, nil
	}
	events, dropped := r.connectionAudit.drainPresenceEvents()
	coreEvents, coreDropped, coreErr := r.coreConnectionPresenceEvents(ctx)
	events = append(events, coreEvents...)
	dropped += coreDropped
	serverID := r.Config().ServerID
	for index := range events {
		events[index].Sequence = r.nextConnectionPresenceSequence()
		events[index].ServerID = serverID
	}
	// Events a previous connection could not deliver keep their original
	// sequence, so they stay ahead of the freshly drained ones.
	pending, pendingDropped := r.takePendingPresenceEvents()
	if len(pending) > 0 {
		events = append(pending, events...)
	}
	dropped += pendingDropped
	kept, expired := dropExpiredPresenceEvents(events, time.Now().UTC())
	return connectionPresenceDelta{Events: kept, DroppedCount: dropped + expired}, coreErr
}

// sendConnectionPresenceDelta writes one poll result as contract-sized
// messages. Whatever the connection did not accept is requeued so a dropped
// link costs a reconnect instead of the presence coverage itself.
func (r *Runner) sendConnectionPresenceDelta(delta connectionPresenceDelta, writeMessage func(payload any, wait bool) error) error {
	events := delta.Events
	dropped := delta.DroppedCount
	for {
		chunk := events
		if len(chunk) > connectionPresenceDeltaBatchSize {
			chunk = chunk[:connectionPresenceDeltaBatchSize]
		}
		batch := connectionPresenceDelta{Events: chunk, DroppedCount: dropped}
		if err := writeMessage(map[string]any{"type": "presence_delta", "presence_delta": batch}, true); err != nil {
			r.requeuePresenceEvents(events, dropped)
			return err
		}
		// The dropped counter describes the poll, not the chunk, so it is
		// reported once.
		dropped = 0
		events = events[len(chunk):]
		if len(events) == 0 {
			return nil
		}
	}
}

func dropExpiredPresenceEvents(events []connectionPresenceEvent, now time.Time) ([]connectionPresenceEvent, int64) {
	kept := events[:0]
	expired := int64(0)
	for _, event := range events {
		at, err := time.Parse(time.RFC3339Nano, strings.TrimSpace(event.At))
		if err != nil || now.Sub(at) > connectionPresenceEventMaxAge {
			expired++
			continue
		}
		kept = append(kept, event)
	}
	return kept, expired
}

func (r *Runner) takePendingPresenceEvents() ([]connectionPresenceEvent, int64) {
	r.presencePendingMu.Lock()
	defer r.presencePendingMu.Unlock()
	events, dropped := r.presencePendingEvents, r.presencePendingDropped
	r.presencePendingEvents, r.presencePendingDropped = nil, 0
	return events, dropped
}

func (r *Runner) requeuePresenceEvents(events []connectionPresenceEvent, dropped int64) {
	if len(events) == 0 && dropped == 0 {
		return
	}
	r.presencePendingMu.Lock()
	defer r.presencePendingMu.Unlock()
	merged := make([]connectionPresenceEvent, 0, len(events)+len(r.presencePendingEvents))
	merged = append(merged, events...)
	merged = append(merged, r.presencePendingEvents...)
	r.presencePendingDropped += dropped
	if overflow := len(merged) - maxPendingPresenceEvents; overflow > 0 {
		// Presence is state-like: the newest events describe the current
		// sessions best, so the oldest ones are the ones to lose.
		r.presencePendingDropped += int64(overflow)
		merged = merged[overflow:]
	}
	r.presencePendingEvents = merged
}

func (r *Runner) discardPendingPresenceEvents() {
	r.presencePendingMu.Lock()
	r.presencePendingEvents, r.presencePendingDropped = nil, 0
	r.presencePendingMu.Unlock()
}

func (r *Runner) coreConnectionPresenceEvents(ctx context.Context) ([]connectionPresenceEvent, int64, error) {
	if err := r.validateConnectionPresenceCapability(ctx); err != nil {
		return nil, 0, err
	}
	client := r.coreClient
	if client == nil {
		client = unixHTTPClient(coreAPISocket)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://oboard-sb/connections/presence/drain", nil)
	if err != nil {
		return nil, 0, err
	}
	res, err := client.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer res.Body.Close()
	if res.StatusCode >= 300 {
		return nil, 0, fmt.Errorf("core connection presence status %d", res.StatusCode)
	}
	var payload struct {
		Events       []coreConnectionPresenceEvent `json:"events"`
		DroppedCount int64                         `json:"dropped_count"`
	}
	if err := json.NewDecoder(res.Body).Decode(&payload); err != nil {
		return nil, 0, err
	}
	events := make([]connectionPresenceEvent, 0, len(payload.Events))
	for _, item := range payload.Events {
		events = append(events, connectionPresenceEvent{UserID: item.UserID, InboundID: item.InboundID, PathID: item.PathID, DeviceIDHash: strings.TrimSpace(item.DeviceIDHash), CredentialEpoch: item.CredentialEpoch, SourceIP: strings.TrimSpace(item.SourceIP), Network: strings.ToLower(strings.TrimSpace(item.Network)), Event: item.Event, State: item.State, ActiveConnections: item.ActiveConnections, Meaningful: item.Meaningful, PayloadLastAt: item.PayloadLastAt, At: item.At})
	}
	return events, payload.DroppedCount, nil
}

func (r *Runner) validateConnectionPresenceCapability(ctx context.Context) error {
	r.connectionAuditCoreMu.Lock()
	defer r.connectionAuditCoreMu.Unlock()
	if r.presenceCapabilityKnown {
		if r.presenceCapabilityEnabled {
			return nil
		}
		return errors.New("kernel does not support connection_presence_v1")
	}
	client := r.coreClient
	if client == nil {
		client = unixHTTPClient(coreAPISocket)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://oboard-sb/version", nil)
	if err != nil {
		return err
	}
	res, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("query kernel presence capability: %w", err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return fmt.Errorf("query kernel presence capability: status %d", res.StatusCode)
	}
	var payload struct {
		Capabilities []string `json:"capabilities"`
	}
	if err := json.NewDecoder(io.LimitReader(res.Body, 64<<10)).Decode(&payload); err != nil {
		return fmt.Errorf("decode kernel presence capability: %w", err)
	}
	r.presenceCapabilityKnown = true
	for _, capability := range payload.Capabilities {
		if capability == connectionPresenceCapability {
			r.presenceCapabilityEnabled = true
			return nil
		}
	}
	return errors.New("kernel does not support connection_presence_v1")
}

func (r *Runner) nextConnectionPresenceSequence() uint64 {
	for {
		current := r.presenceSequence.Load()
		next := uint64(time.Now().UTC().UnixNano())
		if next <= current {
			next = current + 1
		}
		if r.presenceSequence.CompareAndSwap(current, next) {
			return next
		}
	}
}
