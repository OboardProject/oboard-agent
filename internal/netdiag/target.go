// Package netdiag implements the Agent's native network diagnostics for
// plugin capabilities: ICMP ping, ICMP/UDP/TCP trace, TCP connect probes,
// A/AAAA lookups and GET/HEAD HTTP probes. Everything uses Go sockets; no
// ping, traceroute, curl or any other program is ever executed, and targets
// are refused unless they resolve to public addresses.
package netdiag

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"strings"

	"github.com/OboardProject/oboard-agent/internal/model"
)

// Error carries one of the model.NetworkDiagnosticCode* codes.
type Error struct {
	Code    string
	Message string
}

func (e *Error) Error() string { return e.Code + ": " + e.Message }

func fail(code, message string) *Error { return &Error{Code: code, Message: message} }

// CodeOf returns the diagnostic code for err.
func CodeOf(err error) string {
	var diag *Error
	if errors.As(err, &diag) {
		return diag.Code
	}
	return model.NetworkDiagnosticCodeFailed
}

var (
	ErrUnsupported      = fail(model.NetworkDiagnosticCodeUnsupported, "this diagnostic is not supported on this platform")
	ErrTargetNotAllowed = fail(model.NetworkDiagnosticCodeTargetNotAllowed, "the target resolves to a private, loopback, link-local or reserved address")
	ErrResolve          = fail(model.NetworkDiagnosticCodeResolveFailed, "the target could not be resolved")
)

// Resolver is net.DefaultResolver in production and a fake in tests.
type Resolver interface {
	LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error)
}

var nonPublicPrefixes = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),
	netip.MustParsePrefix("10.0.0.0/8"),
	netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("127.0.0.0/8"),
	netip.MustParsePrefix("169.254.0.0/16"),
	netip.MustParsePrefix("172.16.0.0/12"),
	netip.MustParsePrefix("192.0.0.0/24"),
	netip.MustParsePrefix("192.0.2.0/24"),
	netip.MustParsePrefix("192.31.196.0/24"),
	netip.MustParsePrefix("192.52.193.0/24"),
	netip.MustParsePrefix("192.88.99.0/24"),
	netip.MustParsePrefix("192.168.0.0/16"),
	netip.MustParsePrefix("192.175.48.0/24"),
	netip.MustParsePrefix("198.18.0.0/15"),
	netip.MustParsePrefix("198.51.100.0/24"),
	netip.MustParsePrefix("203.0.113.0/24"),
	netip.MustParsePrefix("224.0.0.0/4"),
	netip.MustParsePrefix("240.0.0.0/4"),
	netip.MustParsePrefix("64:ff9b::/96"),
	netip.MustParsePrefix("64:ff9b:1::/48"),
	netip.MustParsePrefix("2001::/23"),
	netip.MustParsePrefix("2001:db8::/32"),
	netip.MustParsePrefix("2002::/16"),
	netip.MustParsePrefix("2620:4f:8000::/48"),
	netip.MustParsePrefix("3fff::/20"),
	netip.MustParsePrefix("fc00::/7"),
	netip.MustParsePrefix("fe80::/10"),
	netip.MustParsePrefix("ff00::/8"),
}

var ipv6GlobalUnicast = netip.MustParsePrefix("2000::/3")

// PublicIP reports whether ip is a globally routable unicast address. It is
// the same policy the Controller applies to plugin targets.
func PublicIP(ip netip.Addr) bool {
	if !ip.IsValid() || ip.Zone() != "" {
		return false
	}
	ip = ip.Unmap()
	if !ip.IsGlobalUnicast() || ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsMulticast() || (ip.Is6() && !ipv6GlobalUnicast.Contains(ip)) {
		return false
	}
	for _, prefix := range nonPublicPrefixes {
		if prefix.Contains(ip) {
			return false
		}
	}
	return true
}

// ValidHostname accepts multi-label DNS names outside internal-only suffixes.
func ValidHostname(host string) bool {
	if len(host) == 0 || len(host) > model.NetworkTargetMaxBytes || !strings.Contains(host, ".") || strings.HasSuffix(host, ".") {
		return false
	}
	for _, suffix := range []string{".localhost", ".local", ".internal", ".home.arpa", ".lan", ".intranet", ".corp", ".test", ".invalid", ".onion"} {
		if strings.HasSuffix(host, suffix) {
			return false
		}
	}
	labels := strings.Split(host, ".")
	if strings.TrimLeft(labels[len(labels)-1], "0123456789") == "" {
		return false
	}
	for _, label := range labels {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, c := range label {
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
				return false
			}
		}
	}
	return true
}

// NormalizeTarget validates a target string without resolving it.
func NormalizeTarget(target string) (string, error) {
	target = strings.ToLower(strings.TrimSpace(target))
	if ip, err := netip.ParseAddr(strings.Trim(target, "[]")); err == nil {
		if !PublicIP(ip) {
			return "", ErrTargetNotAllowed
		}
		return ip.Unmap().String(), nil
	}
	if !ValidHostname(target) {
		return "", fail(model.NetworkDiagnosticCodeInvalidInput, "target must be a public DNS name or IP address")
	}
	return target, nil
}

// ResolveTarget returns one public address of the requested family. Every
// resolved address must be public: a mixed answer is refused as a whole so a
// hostile resolver cannot steer a probe at an internal address.
func ResolveTarget(ctx context.Context, resolver Resolver, target, family string) (netip.Addr, error) {
	target, err := NormalizeTarget(target)
	if err != nil {
		return netip.Addr{}, err
	}
	if ip, err := netip.ParseAddr(target); err == nil {
		if !familyMatches(ip, family) {
			return netip.Addr{}, fail(model.NetworkDiagnosticCodeInvalidInput, "the target address does not match ip_family")
		}
		return ip, nil
	}
	if resolver == nil {
		resolver = net.DefaultResolver
	}
	network := "ip"
	switch family {
	case model.NetworkFamilyIPv4:
		network = "ip4"
	case model.NetworkFamilyIPv6:
		network = "ip6"
	}
	addresses, err := resolver.LookupNetIP(ctx, network, target)
	if err != nil || len(addresses) == 0 {
		return netip.Addr{}, ErrResolve
	}
	if len(addresses) > 32 {
		addresses = addresses[:32]
	}
	var chosen netip.Addr
	for _, address := range addresses {
		address = address.Unmap()
		if !PublicIP(address) {
			return netip.Addr{}, ErrTargetNotAllowed
		}
		if !chosen.IsValid() && familyMatches(address, family) {
			chosen = address
		}
	}
	if !chosen.IsValid() {
		return netip.Addr{}, ErrResolve
	}
	return chosen, nil
}

func familyMatches(ip netip.Addr, family string) bool {
	switch family {
	case model.NetworkFamilyIPv4:
		return ip.Is4()
	case model.NetworkFamilyIPv6:
		return ip.Is6()
	default:
		return true
	}
}

func familyName(ip netip.Addr) string {
	if ip.Is4() {
		return model.NetworkFamilyIPv4
	}
	return model.NetworkFamilyIPv6
}

func validFamily(family string) bool {
	switch family {
	case model.NetworkFamilyAuto, model.NetworkFamilyIPv4, model.NetworkFamilyIPv6:
		return true
	default:
		return false
	}
}
