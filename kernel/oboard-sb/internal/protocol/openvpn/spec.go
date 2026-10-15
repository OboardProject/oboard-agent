// SPDX-License-Identifier: GPL-3.0-or-later

package openvpn

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/netip"
	"strings"
)

const (
	DefaultMTU = 1280
	minMTU     = 576
	maxMTU     = 1500

	maxPEMBytes        = 16 * 1024
	maxCredentialBytes = 128
	maxResolvers       = 4
)

var (
	supportedCiphers = map[string]bool{"AES-128-CBC": true, "AES-256-CBC": true, "AES-128-GCM": true, "AES-256-GCM": true}
	supportedAuth    = map[string]bool{"SHA1": true, "SHA256": true, "SHA512": true}
	defaultResolvers = []string{"1.1.1.1", "8.8.8.8"}
)

// allowNonPublicServer lets tests point a tunnel at a local server.
var allowNonPublicServer = false

// Spec is the complete client description of one OpenVPN server. Controller
// renders it from a sanitized configuration; nothing here is parsed from an
// operator- or server-supplied .ovpn file.
type Spec struct {
	Server     string   `json:"server"`
	ServerPort uint16   `json:"server_port"`
	Network    string   `json:"network"`
	Cipher     string   `json:"cipher"`
	Auth       string   `json:"auth"`
	CA         string   `json:"ca"`
	Cert       string   `json:"cert"`
	Key        string   `json:"key"`
	Username   string   `json:"username,omitempty"`
	Password   string   `json:"password,omitempty"`
	MTU        int      `json:"mtu,omitempty"`
	Resolvers  []string `json:"resolvers,omitempty"`
}

// Normalize validates the spec and fills defaults in place.
func (s *Spec) Normalize() error {
	s.Server = strings.TrimSpace(s.Server)
	addr, err := netip.ParseAddr(s.Server)
	if err != nil {
		return fmt.Errorf("openvpn server must be an IP address")
	}
	addr = addr.Unmap()
	if !addr.Is4() {
		return fmt.Errorf("openvpn server must be an IPv4 address")
	}
	if !allowNonPublicServer && !publicAddr(addr) {
		return fmt.Errorf("openvpn server must be a public address")
	}
	s.Server = addr.String()
	if s.ServerPort == 0 {
		return fmt.Errorf("openvpn server_port is required")
	}
	s.Network = strings.ToLower(strings.TrimSpace(s.Network))
	if s.Network != "tcp" && s.Network != "udp" {
		return fmt.Errorf("openvpn network must be tcp or udp")
	}
	s.Cipher = strings.ToUpper(strings.TrimSpace(s.Cipher))
	if !supportedCiphers[s.Cipher] {
		return fmt.Errorf("unsupported openvpn cipher %q", s.Cipher)
	}
	s.Auth = strings.ToUpper(strings.TrimSpace(s.Auth))
	if !supportedAuth[s.Auth] {
		return fmt.Errorf("unsupported openvpn auth %q", s.Auth)
	}
	if len(s.CA) > maxPEMBytes || len(s.Cert) > maxPEMBytes || len(s.Key) > maxPEMBytes {
		return fmt.Errorf("openvpn certificate material is too large")
	}
	if !x509.NewCertPool().AppendCertsFromPEM([]byte(s.CA)) {
		return fmt.Errorf("openvpn ca is not a PEM certificate")
	}
	if _, err := tls.X509KeyPair([]byte(s.Cert), []byte(s.Key)); err != nil {
		return fmt.Errorf("openvpn client certificate and key do not form a valid pair")
	}
	if len(s.Username) > maxCredentialBytes || len(s.Password) > maxCredentialBytes {
		return fmt.Errorf("openvpn credentials are too long")
	}
	if strings.ContainsAny(s.Username+s.Password, "\x00\r\n") {
		return fmt.Errorf("openvpn credentials contain control characters")
	}
	if s.MTU == 0 {
		s.MTU = DefaultMTU
	}
	if s.MTU < minMTU || s.MTU > maxMTU {
		return fmt.Errorf("openvpn mtu must be between %d and %d", minMTU, maxMTU)
	}
	if len(s.Resolvers) == 0 {
		s.Resolvers = append([]string(nil), defaultResolvers...)
	}
	if len(s.Resolvers) > maxResolvers {
		return fmt.Errorf("openvpn accepts at most %d resolvers", maxResolvers)
	}
	for i, raw := range s.Resolvers {
		resolver, err := netip.ParseAddr(strings.TrimSpace(raw))
		if err != nil || !resolver.Unmap().Is4() || resolver.IsUnspecified() || resolver.IsMulticast() {
			return fmt.Errorf("openvpn resolver %q must be an IPv4 address", raw)
		}
		s.Resolvers[i] = resolver.Unmap().String()
	}
	return nil
}

func publicAddr(addr netip.Addr) bool {
	return addr.IsGlobalUnicast() && !addr.IsPrivate() && !addr.IsLoopback() && !addr.IsLinkLocalUnicast()
}
