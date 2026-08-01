package core

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/OboardProject/oboard-agent/internal/model"
	"golang.org/x/crypto/ssh"
)

func ValidateSafeHost(host string) error {
	host = strings.TrimSpace(host)
	if host == "" {
		return errors.New("host is required")
	}
	if len(host) > 253 {
		return errors.New("host is too long")
	}
	if strings.HasPrefix(host, "-") || strings.Contains(host, "://") || strings.Contains(host, "@") || strings.Contains(host, "/") {
		return errors.New("host contains unsafe characters")
	}
	for _, r := range host {
		if r == ' ' || r == '\t' || r == '\n' || r == '\r' {
			return errors.New("host contains unsafe characters")
		}
	}
	check := host
	if strings.HasPrefix(check, "[") {
		end := strings.Index(check, "]")
		if end <= 1 || end != len(check)-1 {
			return errors.New("invalid IPv6 host")
		}
		check = check[1:end]
	}
	if ip := net.ParseIP(check); ip != nil {
		return nil
	}
	for _, label := range strings.Split(check, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return errors.New("invalid hostname label")
		}
		for _, r := range label {
			if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' {
				continue
			}
			return errors.New("hostname contains invalid characters")
		}
	}
	return nil
}

func ValidateNetworkInterfaceName(name string) error {
	name = strings.TrimSpace(name)
	if name == "" {
		return nil
	}
	if len(name) > 15 {
		return errors.New("interface name is too long")
	}
	for _, r := range name {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '.' || r == '_' || r == '-' || r == ':' {
			continue
		}
		return errors.New("interface name contains invalid characters")
	}
	return nil
}

func ValidateDNSCandidates(items []model.DNSCandidate) error {
	if len(items) > 32 {
		return errors.New("too many dns benchmark candidates")
	}
	for i, candidate := range items {
		if err := validateDNSCandidate(candidate); err != nil {
			return fmt.Errorf("candidate[%d]: %w", i, err)
		}
	}
	return nil
}

func validateDNSCandidate(candidate model.DNSCandidate) error {
	switch candidate.Transport {
	case "", model.DNSTransportUDP, model.DNSTransportTCP, model.DNSTransportDoT, model.DNSTransportDoH, model.DNSTransportDoQ:
	default:
		return fmt.Errorf("unsupported dns transport %q", candidate.Transport)
	}
	if err := ValidateSafeHost(candidate.Server); err != nil {
		return fmt.Errorf("dns server: %w", err)
	}
	if err := rejectPrivateDNSHost(candidate.Server); err != nil {
		return err
	}
	if candidate.Port != 0 {
		if err := validatePort(candidate.Port); err != nil {
			return fmt.Errorf("dns port: %w", err)
		}
	}
	if candidate.Path != "" {
		if !strings.HasPrefix(candidate.Path, "/") || strings.Contains(candidate.Path, "://") || len(candidate.Path) > 256 {
			return errors.New("dns path must start with / and not contain unsafe characters")
		}
		for _, r := range candidate.Path {
			if r == ' ' || r == '\t' || r == '\n' || r == '\r' {
				return errors.New("dns path must start with / and not contain unsafe characters")
			}
		}
	}
	if candidate.TLSName != "" {
		if err := ValidateSafeHost(candidate.TLSName); err != nil {
			return fmt.Errorf("dns tls_name: %w", err)
		}
	}
	if candidate.Tag != "" {
		if len(candidate.Tag) > 64 || strings.ContainsAny(candidate.Tag, " \t\n\r") {
			return errors.New("dns tag is invalid")
		}
	}
	return nil
}

func rejectPrivateDNSHost(host string) error {
	ip := net.ParseIP(strings.Trim(strings.TrimSpace(host), "[]"))
	if ip == nil {
		return nil
	}
	if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsUnspecified() || ip.IsMulticast() {
		return errors.New("dns server must not be a private or loopback address")
	}
	if ip4 := ip.To4(); ip4 != nil {
		if ip4[0] == 169 && ip4[1] == 254 || ip4[0] == 100 && ip4[1] >= 64 && ip4[1] <= 127 {
			return errors.New("dns server must not be a private or loopback address")
		}
	}
	return nil
}

func ValidateTunnelConfig(tunnel model.Tunnel) error {
	if len(tunnel.ConfigJSON) > 8192 {
		return errors.New("tunnel config_json is too large")
	}
	switch tunnel.Type {
	case model.TunnelTypeWireGuard:
		return validateWireGuardTunnelConfig(tunnel)
	case model.TunnelTypeSSH:
		return validateSSHTunnelConfig(tunnel)
	default:
		return fmt.Errorf("unsupported tunnel type %q", tunnel.Type)
	}
}

func validateWireGuardTunnelConfig(tunnel model.Tunnel) error {
	var config struct {
		PrivateKey          string   `json:"private_key"`
		PeerPublicKey       string   `json:"peer_public_key"`
		AllowedIPs          []string `json:"allowed_ips"`
		PersistentKeepalive int      `json:"persistent_keepalive"`
	}
	if err := strictJSON(tunnel.ConfigJSON, &config); err != nil {
		return fmt.Errorf("wireguard config_json: %w", err)
	}
	if unsafeScalar(config.PrivateKey, 256) || unsafeScalar(config.PeerPublicKey, 256) {
		return errors.New("wireguard keys must be non-empty strings without control characters and <= 256 bytes")
	}
	if config.PersistentKeepalive < 0 || config.PersistentKeepalive > 65535 {
		return errors.New("wireguard persistent_keepalive must be between 0 and 65535")
	}
	if tunnel.LocalAddress != "" {
		if err := validateIPPrefixList([]string{tunnel.LocalAddress}); err != nil {
			return fmt.Errorf("local_address: %w", err)
		}
	}
	if tunnel.PeerAddress != "" {
		if err := validateIPPrefixList([]string{tunnel.PeerAddress}); err != nil {
			return fmt.Errorf("peer_address: %w", err)
		}
	}
	if len(config.AllowedIPs) > 32 {
		return errors.New("wireguard allowed_ips supports at most 32 entries")
	}
	if err := validateIPPrefixList(config.AllowedIPs); err != nil {
		return fmt.Errorf("allowed_ips: %w", err)
	}
	return nil
}

func validateSSHTunnelConfig(tunnel model.Tunnel) error {
	var config struct {
		ManagedPair      bool     `json:"managed_pair"`
		Role             string   `json:"role"`
		User             string   `json:"user"`
		KeyPath          string   `json:"key_path"`
		ClientPrivateKey string   `json:"client_private_key"`
		AuthorizedKey    string   `json:"authorized_key"`
		PermitOpen       string   `json:"permit_open"`
		ServerPort       int      `json:"server_port"`
		LocalForward     string   `json:"local_forward"`
		RemoteForward    string   `json:"remote_forward"`
		ExtraArgs        []string `json:"extra_args"`
		ManagedBy        string   `json:"managed_by"`
		PathID           int64    `json:"path_id"`
		StepID           int64    `json:"step_id"`
	}
	if err := strictJSON(tunnel.ConfigJSON, &config); err != nil {
		return fmt.Errorf("ssh config_json: %w", err)
	}
	if !safeSSHUser(config.User) {
		return errors.New("ssh user must match [A-Za-z0-9._-]{1,64}")
	}
	if config.ManagedPair {
		switch config.Role {
		case "client":
			if err := validateSSHPrivateKey(config.ClientPrivateKey); err != nil {
				return fmt.Errorf("ssh managed client_private_key: %w", err)
			}
		case "server":
			if err := validateSSHPublicKey(config.AuthorizedKey); err != nil {
				return fmt.Errorf("ssh managed authorized_key: %w", err)
			}
			if err := validateSSHPermitOpen(config.PermitOpen); err != nil {
				return fmt.Errorf("ssh managed permit_open: %w", err)
			}
			if err := validatePort(config.ServerPort); err != nil {
				return fmt.Errorf("ssh managed server_port: %w", err)
			}
		default:
			return errors.New("ssh managed role must be client or server")
		}
	}
	if config.KeyPath != "" && (unsafeScalar(config.KeyPath, 512) || !filepath.IsAbs(config.KeyPath) || strings.Contains(filepath.Clean(config.KeyPath), "..")) {
		return errors.New("ssh key_path must be an absolute safe path")
	}
	if len(config.ExtraArgs) > 0 {
		return errors.New("ssh extra_args is disabled; use first-class tunnel fields instead")
	}
	if err := validateSSHForward(config.LocalForward); err != nil {
		return fmt.Errorf("local_forward: %w", err)
	}
	if err := validateSSHForward(config.RemoteForward); err != nil {
		return fmt.Errorf("remote_forward: %w", err)
	}
	return nil
}

func ValidateTunnelEndpoint(raw string) error {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}
	if unsafeScalar(raw, 253) || strings.HasPrefix(raw, "-") || strings.ContainsAny(raw, " \t/") {
		return errors.New("endpoint contains unsafe characters")
	}
	if strings.Contains(raw, "://") || strings.Contains(raw, "@") {
		return errors.New("endpoint must be a host or IP, not a URL/user@host")
	}
	return ValidateSafeHost(raw)
}

func validatePort(port int) error {
	if port < 1 || port > 65535 {
		return fmt.Errorf("invalid port %d", port)
	}
	return nil
}

func strictJSON(raw string, value any) error {
	if strings.TrimSpace(raw) == "" {
		raw = "{}"
	}
	decoder := json.NewDecoder(bytes.NewReader([]byte(raw)))
	decoder.DisallowUnknownFields()
	return decoder.Decode(value)
}

func unsafeScalar(value string, max int) bool {
	if strings.TrimSpace(value) == "" || len(value) > max {
		return true
	}
	return strings.ContainsAny(value, "\x00\n\r")
}

func validateIPPrefixList(items []string) error {
	for _, item := range items {
		item = strings.TrimSpace(item)
		if item == "" {
			return errors.New("empty IP prefix")
		}
		if _, err := netip.ParsePrefix(item); err == nil {
			continue
		}
		if _, err := netip.ParseAddr(item); err == nil {
			continue
		}
		return fmt.Errorf("%q is not an IP/CIDR prefix", item)
	}
	return nil
}

func safeSSHUser(user string) bool {
	if user == "" || len(user) > 64 {
		return false
	}
	for _, r := range user {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '.' || r == '_' || r == '-' {
			continue
		}
		return false
	}
	return true
}

func validateSSHPrivateKey(raw string) error {
	if len(raw) == 0 || len(raw) > 4096 {
		return errors.New("must be a non-empty OpenSSH private key")
	}
	if _, err := ssh.ParseRawPrivateKey([]byte(raw)); err != nil {
		return errors.New("must be a valid OpenSSH private key")
	}
	return nil
}

func validateSSHPublicKey(raw string) error {
	if len(raw) == 0 || len(raw) > 1024 || strings.ContainsAny(raw, "\r\n") {
		return errors.New("must be a non-empty SSH public key")
	}
	if _, _, _, _, err := ssh.ParseAuthorizedKey([]byte(raw)); err != nil {
		return errors.New("must be a valid SSH public key")
	}
	return nil
}

func validateSSHPermitOpen(raw string) error {
	host, portText, err := net.SplitHostPort(raw)
	if err != nil {
		return errors.New("must be host:port")
	}
	if err := ValidateSafeHost(host); err != nil {
		return err
	}
	port, err := strconv.Atoi(portText)
	if err != nil {
		return errors.New("port must be numeric")
	}
	return validatePort(port)
}

func validateSSHForward(value string) error {
	if value == "" {
		return nil
	}
	if unsafeScalar(value, 512) || strings.HasPrefix(value, "-") || strings.ContainsAny(value, " \t") {
		return errors.New("forward spec contains unsafe characters")
	}
	parts := strings.Split(value, ":")
	if len(parts) < 3 || len(parts) > 4 {
		return errors.New("forward spec must be [bind:]port:host:hostport")
	}
	return nil
}
