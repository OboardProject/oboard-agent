package minibox

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"strings"

	"github.com/sagernet/sing-box/option"
	badjson "github.com/sagernet/sing/common/json"
)

type HY2Tuning struct {
	Enabled               bool
	UpMbps                int
	DownMbps              int
	IgnoreClientBandwidth bool
	BrutalDebug           bool
}

type RuntimeMetadata struct {
	RateLimits      RuntimeRateLimits       `json:"rate_limits,omitempty"`
	ConnectionAudit *RuntimeConnectionAudit `json:"connection_audit,omitempty"`
	TrustedForward  *RuntimeTrustedForward  `json:"trusted_forward,omitempty"`
}

type RuntimeTrustedForward struct {
	Receivers []RuntimeTrustedForwardReceiver `json:"receivers,omitempty"`
}

type RuntimeTrustedForwardReceiver struct {
	Version             int    `json:"version"`
	ID                  string `json:"id"`
	PathID              int64  `json:"path_id"`
	InboundTag          string `json:"inbound_tag"`
	Network             string `json:"network"`
	Listen              string `json:"listen"`
	ListenPort          int    `json:"listen_port"`
	Target              string `json:"target"`
	TargetPort          int    `json:"target_port"`
	Key                 string `json:"key"`
	MaxClockSkewSeconds int    `json:"max_clock_skew_seconds"`
}

type RuntimeConnectionAudit struct {
	Enabled bool `json:"enabled"`
}

type RuntimeRateLimits struct {
	Users    map[string]RuntimeUserLimit `json:"users,omitempty"`
	Inbounds map[string]RuntimeUserLimit `json:"inbounds,omitempty"`
}

type RuntimeUserLimit struct {
	UserID            int64  `json:"user_id,omitempty"`
	InboundID         int64  `json:"inbound_id,omitempty"`
	PathID            int64  `json:"path_id,omitempty"`
	DeviceIDHash      string `json:"device_id_hash,omitempty"`
	CredentialEpoch   int64  `json:"credential_epoch,omitempty"`
	CredentialStatus  string `json:"credential_status,omitempty"`
	Billable          bool   `json:"billable"`
	SpeedLimitMbps    int    `json:"speed_limit_mbps,omitempty"`
	TrafficLimitBytes int64  `json:"traffic_limit_bytes,omitempty"`
	UsedBaselineBytes int64  `json:"used_baseline_bytes,omitempty"`
	LeaseBytes        int64  `json:"lease_bytes,omitempty"`
	ResetLeaseBytes   int64  `json:"reset_lease_bytes,omitempty"`
	LeaseEnforced     bool   `json:"lease_enforced,omitempty"`
	PeriodKey         string `json:"period_key,omitempty"`
	PeriodStart       string `json:"period_start,omitempty"`
	PeriodEnd         string `json:"period_end,omitempty"`
	ResetMode         string `json:"reset_mode,omitempty"`
	ResetDay          int    `json:"reset_day,omitempty"`
	ResetAnchor       string `json:"reset_anchor,omitempty"`
	PreviousPeriodKey string `json:"previous_period_key,omitempty"`
	Timezone          string `json:"timezone,omitempty"`
	QuotaState        string `json:"quota_state,omitempty"`
	EnforcementMode   string `json:"enforcement_mode,omitempty"`
}

func LoadConfig(path string, tuning HY2Tuning) (option.Options, RuntimeMetadata, error) {
	// #nosec G304 -- path is an explicit local CLI flag supplied by the Agent service.
	data, err := os.ReadFile(path)
	if err != nil {
		return option.Options{}, RuntimeMetadata{}, err
	}
	cleanData, metadata, err := splitRuntimeMetadata(data)
	if err != nil {
		return option.Options{}, RuntimeMetadata{}, err
	}
	if err := validateTrustedForwardMetadata(metadata.TrustedForward); err != nil {
		return option.Options{}, RuntimeMetadata{}, err
	}
	opts, err := badjson.UnmarshalExtendedContext[option.Options](Context(context.Background()), cleanData)
	if err != nil {
		return option.Options{}, RuntimeMetadata{}, err
	}
	if opts.Log == nil {
		opts.Log = &option.LogOptions{Level: "warn", Timestamp: true}
	} else if opts.Log.Level == "" {
		opts.Log.Level = "warn"
	}
	ApplyHY2Tuning(&opts, tuning)
	return opts, metadata, nil
}

func validateTrustedForwardMetadata(trusted *RuntimeTrustedForward) error {
	if trusted == nil {
		return nil
	}
	seenID := map[string]bool{}
	seenListen := map[string]bool{}
	for _, receiver := range trusted.Receivers {
		if receiver.Version != trustedForwardVersion || strings.TrimSpace(receiver.ID) == "" || receiver.PathID <= 0 || strings.TrimSpace(receiver.InboundTag) == "" {
			return fmt.Errorf("trusted forward receiver identity is invalid")
		}
		if seenID[receiver.ID] {
			return fmt.Errorf("duplicate trusted forward receiver %q", receiver.ID)
		}
		seenID[receiver.ID] = true
		switch receiver.Network {
		case "tcp", "udp", "tcp_udp":
		default:
			return fmt.Errorf("trusted forward receiver %q network is invalid", receiver.ID)
		}
		if receiver.ListenPort < 1 || receiver.ListenPort > 65535 || receiver.TargetPort < 1 || receiver.TargetPort > 65535 {
			return fmt.Errorf("trusted forward receiver %q port is invalid", receiver.ID)
		}
		if target, err := netip.ParseAddr(strings.TrimSpace(receiver.Target)); err != nil || !target.IsLoopback() {
			return fmt.Errorf("trusted forward receiver %q target must be a loopback IP", receiver.ID)
		}
		key, err := base64.RawStdEncoding.DecodeString(receiver.Key)
		if err != nil {
			key, err = base64.StdEncoding.DecodeString(receiver.Key)
		}
		if err != nil || len(key) != sha256.Size {
			return fmt.Errorf("trusted forward receiver %q key is invalid", receiver.ID)
		}
		if receiver.MaxClockSkewSeconds < 30 || receiver.MaxClockSkewSeconds > 300 {
			return fmt.Errorf("trusted forward receiver %q clock skew is invalid", receiver.ID)
		}
		listenKey := strings.Join([]string{receiver.Network, strings.TrimSpace(receiver.Listen), fmt.Sprint(receiver.ListenPort)}, "\x00")
		if seenListen[listenKey] {
			return fmt.Errorf("duplicate trusted forward receiver listener %q", receiver.ID)
		}
		seenListen[listenKey] = true
	}
	return nil
}

func splitRuntimeMetadata(data []byte) ([]byte, RuntimeMetadata, error) {
	var root map[string]json.RawMessage
	if err := json.Unmarshal(data, &root); err != nil {
		return nil, RuntimeMetadata{}, err
	}
	var metadata RuntimeMetadata
	if raw, ok := root["_oboard"]; ok && len(raw) > 0 && string(raw) != "null" {
		if err := json.Unmarshal(raw, &metadata); err != nil {
			return nil, RuntimeMetadata{}, err
		}
		delete(root, "_oboard")
	}
	cleanData, err := json.Marshal(root)
	if err != nil {
		return nil, RuntimeMetadata{}, err
	}
	return cleanData, metadata, nil
}

func ApplyHY2Tuning(opts *option.Options, tuning HY2Tuning) {
	if opts == nil || !tuning.Enabled {
		return
	}
	for i := range opts.Inbounds {
		if opts.Inbounds[i].Type != "hysteria2" {
			continue
		}
		hy2, ok := opts.Inbounds[i].Options.(*option.Hysteria2InboundOptions)
		if !ok || hy2 == nil {
			continue
		}
		if tuning.UpMbps > 0 {
			hy2.UpMbps = tuning.UpMbps
		}
		if tuning.DownMbps > 0 {
			hy2.DownMbps = tuning.DownMbps
		}
		if tuning.IgnoreClientBandwidth {
			hy2.IgnoreClientBandwidth = true
		}
		if tuning.BrutalDebug {
			hy2.BrutalDebug = true
		}
	}
}
