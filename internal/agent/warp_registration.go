package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"sort"
	"strings"
	"time"

	"github.com/OboardProject/oboard-agent/internal/core"
	"github.com/OboardProject/oboard-agent/internal/model"
)

type warpRegistrationBinding struct {
	InterfaceName string
	SourcePrefix  string
	Family        string
}

func (binding warpRegistrationBinding) key() string {
	if binding.InterfaceName != "" || binding.SourcePrefix != "" || binding.Family != "" {
		return "interface:" + binding.InterfaceName + ";source-prefix:" + binding.SourcePrefix + ";family:" + binding.Family
	}
	return ""
}

func deriveWARPRegistrationBindings(config string) (map[int64]warpRegistrationBinding, error) {
	if strings.TrimSpace(config) == "" {
		return map[int64]warpRegistrationBinding{}, nil
	}
	var root map[string]any
	if err := json.Unmarshal([]byte(config), &root); err != nil {
		return nil, fmt.Errorf("decode core config for WARP registration bindings: %w", err)
	}
	prefixesByTag := map[string]string{}
	for _, raw := range anyMapSlice(root["outbounds"]) {
		if trimmedAnyString(raw["type"]) != "source-prefix" {
			continue
		}
		tag := trimmedAnyString(raw["tag"])
		prefix, err := netip.ParsePrefix(trimmedAnyString(raw["prefix"]))
		if tag != "" && err == nil {
			prefixesByTag[tag] = prefix.Masked().String()
		}
	}
	candidates := map[int64]map[string]warpRegistrationBinding{}
	for _, endpoint := range anyMapSlice(root["endpoints"]) {
		profileID := int64FromAny(endpoint["_oboard_warp_pending"])
		if profileID <= 0 {
			continue
		}
		binding := warpRegistrationBinding{InterfaceName: trimmedAnyString(endpoint["bind_interface"])}
		if err := core.ValidateNetworkInterfaceName(binding.InterfaceName); err != nil {
			return nil, fmt.Errorf("WARP profile %d bind_interface: %w", profileID, err)
		}
		if binding.InterfaceName == "" {
			binding.SourcePrefix = prefixesByTag[trimmedAnyString(endpoint["detour"])]
		}
		if key := binding.key(); key != "" {
			if candidates[profileID] == nil {
				candidates[profileID] = map[string]warpRegistrationBinding{}
			}
			candidates[profileID][key] = binding
		}
	}
	result := make(map[int64]warpRegistrationBinding, len(candidates))
	for profileID, bindings := range candidates {
		if len(bindings) != 1 {
			keys := make([]string, 0, len(bindings))
			for key := range bindings {
				keys = append(keys, key)
			}
			sort.Strings(keys)
			return nil, fmt.Errorf("WARP profile %d has conflicting registration bindings: %s", profileID, strings.Join(keys, ", "))
		}
		for _, binding := range bindings {
			result[profileID] = binding
		}
	}
	return result, nil
}

func trimmedAnyString(value any) string {
	text, _ := value.(string)
	return strings.TrimSpace(text)
}

func anyMapSlice(value any) []map[string]any {
	if values, ok := value.([]map[string]any); ok {
		return values
	}
	values, _ := value.([]any)
	result := make([]map[string]any, 0, len(values))
	for _, value := range values {
		if item, ok := value.(map[string]any); ok {
			result = append(result, item)
		}
	}
	return result
}

func newWARPRegistrationHTTPClient(base *http.Client, binding warpRegistrationBinding, plan model.WARPRequestPlan) (*http.Client, error) {
	transport := lowOverheadTransport()
	transport.Proxy = nil
	dialer := &net.Dialer{
		Timeout:   15 * time.Second,
		KeepAlive: 30 * time.Second,
	}
	if binding.key() != "" {
		interfaces, err := listNetworkInterfaces()
		if err != nil {
			return nil, err
		}
		interfaceName, localAddress, err := selectWARPRegistrationAddress(interfaces, binding, plan.IPStack)
		if err != nil {
			return nil, err
		}
		dialer.LocalAddr = &net.TCPAddr{IP: net.IP(localAddress.AsSlice())}
		dialer.Control = warpBindToInterfaceControl(interfaceName)
	}
	transport.DialContext = dialer.DialContext
	timeout := 20 * time.Second
	if base != nil && base.Timeout > 0 && base.Timeout < timeout {
		timeout = base.Timeout
	}
	return &http.Client{Timeout: timeout, Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error {
		return errors.New("WARP registration redirects are not allowed")
	}}, nil
}

func selectWARPRegistrationAddress(interfaces []model.NetworkInterfaceInfo, binding warpRegistrationBinding, preferred model.IPStack) (string, netip.Addr, error) {
	switch binding.Family {
	case "", "auto", "ipv4_only", "ipv6_only":
	default:
		return "", netip.Addr{}, errors.New("invalid WARP underlay family")
	}
	if err := core.ValidateNetworkInterfaceName(binding.InterfaceName); err != nil {
		return "", netip.Addr{}, fmt.Errorf("invalid WARP registration interface: %w", err)
	}
	var wantedPrefix netip.Prefix
	if binding.SourcePrefix != "" {
		prefix, err := netip.ParsePrefix(binding.SourcePrefix)
		if err != nil {
			return "", netip.Addr{}, fmt.Errorf("invalid WARP registration source prefix %q: %w", binding.SourcePrefix, err)
		}
		wantedPrefix = prefix.Masked()
	}
	type candidate struct {
		interfaceName string
		address       netip.Addr
	}
	candidates := []candidate{}
	for _, networkInterface := range interfaces {
		if !networkInterface.Up {
			continue
		}
		if binding.InterfaceName != "" && networkInterface.Name != binding.InterfaceName {
			continue
		}
		for _, raw := range networkInterface.Addresses {
			prefix, err := netip.ParsePrefix(raw)
			if err != nil {
				continue
			}
			address := prefix.Addr().Unmap()
			if binding.Family == "ipv4_only" && !address.Is4() || binding.Family == "ipv6_only" && !address.Is6() {
				continue
			}
			if !address.IsValid() || address.IsUnspecified() || address.IsLoopback() || address.IsLinkLocalUnicast() || address.IsMulticast() {
				continue
			}
			if wantedPrefix.IsValid() && !wantedPrefix.Contains(address) {
				continue
			}
			candidates = append(candidates, candidate{interfaceName: networkInterface.Name, address: address})
		}
	}
	if len(candidates) == 0 {
		if binding.Family == "ipv6_only" {
			return "", netip.Addr{}, errors.New("registration_ipv6_unavailable: no usable local address in the allowed underlay")
		}
		return "", netip.Addr{}, errors.New("WARP registration binding has no usable local address")
	}
	sort.Slice(candidates, func(i, j int) bool {
		leftPreferred := warpAddressMatchesIPStack(candidates[i].address, preferred)
		rightPreferred := warpAddressMatchesIPStack(candidates[j].address, preferred)
		if leftPreferred != rightPreferred {
			return leftPreferred
		}
		if candidates[i].address.Is6() != candidates[j].address.Is6() {
			return candidates[i].address.Is6()
		}
		if candidates[i].interfaceName != candidates[j].interfaceName {
			return candidates[i].interfaceName < candidates[j].interfaceName
		}
		return candidates[i].address.Less(candidates[j].address)
	})
	return candidates[0].interfaceName, candidates[0].address, nil
}

func warpAddressMatchesIPStack(address netip.Addr, stack model.IPStack) bool {
	switch stack {
	case model.IPStackIPv4Only:
		return address.Is4()
	case model.IPStackIPv6Only:
		return address.Is6()
	default:
		return false
	}
}

func warpBindingFromDialConstraint(dc *model.DialConstraint) warpRegistrationBinding {
	if dc == nil || strings.TrimSpace(dc.Mode) != "interface" {
		return warpRegistrationBinding{}
	}
	b := warpRegistrationBinding{InterfaceName: strings.TrimSpace(dc.InterfaceName), Family: strings.ToLower(strings.TrimSpace(dc.Family))}
	addr := strings.TrimSpace(dc.SourceAddress)
	if addr != "" {
		if parsed, err := netip.ParseAddr(addr); err == nil {
			// Preserve as a /32 or /128 prefix for the existing prefix-matching path.
			if parsed.Is4() {
				b.SourcePrefix = parsed.String() + "/32"
			} else {
				b.SourcePrefix = parsed.String() + "/128"
			}
		} else if p, err := netip.ParsePrefix(addr); err == nil {
			b.SourcePrefix = p.Masked().String()
		}
	}
	return b
}

func mergeWARPRegistrationBinding(binding warpRegistrationBinding, underlay *model.DialConstraint) (warpRegistrationBinding, error) {
	if underlay == nil || underlay.Mode != "interface" {
		return binding, nil
	}
	explicit := warpBindingFromDialConstraint(underlay)
	if binding.InterfaceName != "" && explicit.InterfaceName != "" && binding.InterfaceName != explicit.InterfaceName {
		return warpRegistrationBinding{}, errors.New("warp_identity_underlay_conflict: profile and branch interfaces differ")
	}
	if binding.SourcePrefix != "" && explicit.SourcePrefix != "" {
		bound, err1 := netip.ParsePrefix(binding.SourcePrefix)
		source, err2 := netip.ParsePrefix(explicit.SourcePrefix)
		if err1 != nil || err2 != nil || !bound.Contains(source.Addr()) {
			return warpRegistrationBinding{}, errors.New("warp_identity_underlay_conflict: profile source is outside branch prefix")
		}
	}
	if binding.Family != "" && binding.Family != "auto" && explicit.Family != "" && explicit.Family != "auto" && binding.Family != explicit.Family {
		return warpRegistrationBinding{}, errors.New("warp_identity_underlay_conflict: profile and branch families differ")
	}
	if explicit.InterfaceName == "" {
		explicit.InterfaceName = binding.InterfaceName
	}
	if explicit.SourcePrefix == "" {
		explicit.SourcePrefix = binding.SourcePrefix
	}
	if explicit.Family == "" || explicit.Family == "auto" {
		explicit.Family = binding.Family
	}
	return explicit, nil
}

func applyDialConstraintToEndpoint(endpoint map[string]any, dc *model.DialConstraint) error {
	if dc == nil {
		return nil
	}
	if strings.TrimSpace(dc.Mode) == "auto" {
		if dc.InterfaceName != "" || dc.SourceAddress != "" || dc.Family != "" && dc.Family != "auto" {
			return errors.New("automatic WARP underlay cannot contain explicit bindings")
		}
		delete(endpoint, "bind_interface")
		delete(endpoint, "inet4_bind_address")
		delete(endpoint, "inet6_bind_address")
		return nil
	}
	if strings.TrimSpace(dc.Mode) != "interface" {
		return errors.New("invalid WARP underlay mode")
	}
	if strings.TrimSpace(dc.InterfaceName) == "" && strings.TrimSpace(dc.SourceAddress) == "" {
		return errors.New("WARP underlay requires interface or exact source address")
	}
	family := strings.ToLower(strings.TrimSpace(dc.Family))
	if family != "" && family != "auto" && family != "ipv4_only" && family != "ipv6_only" {
		return errors.New("invalid WARP underlay family")
	}
	for _, peer := range anyMapSlice(endpoint["peers"]) {
		if address, err := netip.ParseAddr(trimmedAnyString(peer["address"])); err == nil {
			if family == "ipv6_only" && !address.Unmap().Is6() || family == "ipv4_only" && !address.Unmap().Is4() {
				return errors.New("underlay_family_mismatch: WARP peer address conflicts with underlay")
			}
		}
	}
	if detour, _ := endpoint["detour"].(string); strings.TrimSpace(detour) != "" {
		return fmt.Errorf("WARP underlay binding cannot be combined with detour")
	}
	delete(endpoint, "detour")
	iface := strings.TrimSpace(dc.InterfaceName)
	if iface != "" {
		if err := core.ValidateNetworkInterfaceName(iface); err != nil {
			return fmt.Errorf("invalid underlay interface: %w", err)
		}
		endpoint["bind_interface"] = iface
	} else {
		delete(endpoint, "bind_interface")
	}
	addrStr := strings.TrimSpace(dc.SourceAddress)
	if addrStr != "" {
		addr, err := netip.ParseAddr(addrStr)
		if err != nil {
			return fmt.Errorf("underlay source address must be an exact IP address")
		}
		addr = addr.Unmap()
		if !addr.IsGlobalUnicast() || addr.IsLoopback() {
			return errors.New("underlay source address must be a unicast address")
		}
		if family := strings.ToLower(strings.TrimSpace(dc.Family)); family == "ipv4_only" && addr.Is6() {
			return fmt.Errorf("family ipv4_only conflicts with IPv6 source_address")
		} else if family == "ipv6_only" && addr.Is4() {
			return fmt.Errorf("family ipv6_only conflicts with IPv4 source_address")
		}
		if addr.Is4() {
			endpoint["inet4_bind_address"] = addr.String()
			delete(endpoint, "inet6_bind_address")
		} else {
			endpoint["inet6_bind_address"] = addr.String()
			delete(endpoint, "inet4_bind_address")
		}
	} else {
		delete(endpoint, "inet4_bind_address")
		delete(endpoint, "inet6_bind_address")
	}
	return nil
}

func boundWARPRegistrationClient(ctx context.Context, base *http.Client, binding warpRegistrationBinding, plan model.WARPRequestPlan) (*http.Client, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}
	return newWARPRegistrationHTTPClient(base, binding, plan)
}
