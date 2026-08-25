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
}

func (binding warpRegistrationBinding) key() string {
	if binding.InterfaceName != "" {
		return "interface:" + binding.InterfaceName
	}
	if binding.SourcePrefix != "" {
		return "source-prefix:" + binding.SourcePrefix
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
	interfaces, err := listNetworkInterfaces()
	if err != nil {
		return nil, err
	}
	interfaceName, localAddress, err := selectWARPRegistrationAddress(interfaces, binding, plan.IPStack)
	if err != nil {
		return nil, err
	}
	transport := lowOverheadTransport()
	if base != nil {
		if existing, ok := base.Transport.(*http.Transport); ok && existing != nil {
			transport = existing.Clone()
		}
	}
	dialer := &net.Dialer{
		Timeout:   15 * time.Second,
		KeepAlive: 30 * time.Second,
		LocalAddr: &net.TCPAddr{IP: net.IP(localAddress.AsSlice())},
		Control:   warpBindToInterfaceControl(interfaceName),
	}
	transport.DialContext = dialer.DialContext
	timeout := 20 * time.Second
	if base != nil && base.Timeout > 0 {
		timeout = base.Timeout
	}
	return &http.Client{Timeout: timeout, Transport: transport}, nil
}

func selectWARPRegistrationAddress(interfaces []model.NetworkInterfaceInfo, binding warpRegistrationBinding, preferred model.IPStack) (string, netip.Addr, error) {
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

func boundWARPRegistrationClient(ctx context.Context, base *http.Client, binding warpRegistrationBinding, plan model.WARPRequestPlan) (*http.Client, error) {
	if binding.key() == "" {
		return base, nil
	}
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}
	return newWARPRegistrationHTTPClient(base, binding, plan)
}
