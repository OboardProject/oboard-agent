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
	return connectionPresenceDelta{Events: events, DroppedCount: dropped}, coreErr
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
