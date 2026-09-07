package model

import (
	"encoding/json"
	"time"
)

const (
	HostPowerActionPoweroff = "poweroff"
	HostPowerActionReboot   = "reboot"

	HostPowerReceiptAccepted  = "accepted"
	HostPowerReceiptPreparing = "preparing"
	HostPowerReceiptInitiated = "initiated"
	HostPowerReceiptObserved  = "observed"
	HostPowerReceiptUnknown   = "unknown"

	HostPowerProtocolVersion = 1
)

type HostPowerTaskPayload struct {
	ProtocolVersion   int             `json:"protocol_version"`
	OperationID       string          `json:"operation_id"`
	Action            string          `json:"action"`
	ServerID          int64           `json:"server_id"`
	Source            string          `json:"source"`
	RunID             string          `json:"run_id"`
	ScriptRevisionID  int64           `json:"script_revision_id,omitempty"`
	TriggerBindingID  int64           `json:"trigger_binding_id,omitempty"`
	GrantID           int64           `json:"grant_id,omitempty"`
	IssuedAt          time.Time       `json:"issued_at"`
	ExpiresAt         time.Time       `json:"expires_at"`
	ExpectedBootID    string          `json:"expected_boot_id,omitempty"`
	Reason            string          `json:"reason,omitempty"`
	PreconditionsJSON json.RawMessage `json:"preconditions,omitempty"`
	PayloadDigest     string          `json:"payload_digest"`
}
