package agent

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
	"sort"
	"strings"

	"github.com/OboardProject/oboard-agent/internal/core"
	"github.com/OboardProject/oboard-agent/internal/model"
)

const (
	maxNetworkInterfaces         = 256
	maxNetworkInterfaceAddresses = 32
)

func listNetworkInterfaces() ([]model.NetworkInterfaceInfo, error) {
	interfaces, err := net.Interfaces()
	if err != nil {
		return nil, fmt.Errorf("list network interfaces: %w", err)
	}
	return collectNetworkInterfaces(interfaces, func(iface net.Interface) ([]net.Addr, error) {
		return iface.Addrs()
	})
}

func collectNetworkInterfaces(interfaces []net.Interface, addresses func(net.Interface) ([]net.Addr, error)) ([]model.NetworkInterfaceInfo, error) {
	if len(interfaces) > maxNetworkInterfaces {
		return nil, fmt.Errorf("network interface count %d exceeds limit %d", len(interfaces), maxNetworkInterfaces)
	}
	result := make([]model.NetworkInterfaceInfo, 0, len(interfaces))
	seenNames := make(map[string]struct{}, len(interfaces))
	for _, iface := range interfaces {
		name := strings.TrimSpace(iface.Name)
		if err := core.ValidateNetworkInterfaceName(name); err != nil {
			return nil, fmt.Errorf("network interface %q: %w", name, err)
		}
		if _, exists := seenNames[name]; exists {
			return nil, fmt.Errorf("duplicate network interface %q", name)
		}
		seenNames[name] = struct{}{}

		rawAddresses, err := addresses(iface)
		if err != nil {
			return nil, fmt.Errorf("list addresses for network interface %q: %w", name, err)
		}
		normalized := make([]string, 0, len(rawAddresses))
		seenAddresses := make(map[string]struct{}, len(rawAddresses))
		for _, raw := range rawAddresses {
			value, err := normalizeInterfaceAddress(raw.String())
			if err != nil {
				return nil, fmt.Errorf("network interface %q address: %w", name, err)
			}
			if _, exists := seenAddresses[value]; exists {
				continue
			}
			seenAddresses[value] = struct{}{}
			normalized = append(normalized, value)
		}
		sort.Strings(normalized)
		if len(normalized) > maxNetworkInterfaceAddresses {
			normalized = normalized[:maxNetworkInterfaceAddresses]
		}
		result = append(result, model.NetworkInterfaceInfo{
			Name:      name,
			Up:        iface.Flags&net.FlagUp != 0,
			Running:   iface.Flags&net.FlagRunning != 0,
			Loopback:  iface.Flags&net.FlagLoopback != 0,
			Addresses: normalized,
		})
	}
	sort.Slice(result, func(i, j int) bool {
		left, right := networkInterfaceSortRank(result[i]), networkInterfaceSortRank(result[j])
		if left != right {
			return left < right
		}
		return result[i].Name < result[j].Name
	})
	return result, nil
}

func normalizeInterfaceAddress(value string) (string, error) {
	value = strings.TrimSpace(value)
	if prefix, err := netip.ParsePrefix(value); err == nil {
		return prefix.String(), nil
	}
	address, err := netip.ParseAddr(value)
	if err != nil {
		return "", fmt.Errorf("invalid IP address %q", value)
	}
	return netip.PrefixFrom(address, address.BitLen()).String(), nil
}

func networkInterfaceSortRank(iface model.NetworkInterfaceInfo) int {
	if iface.Up && !iface.Loopback {
		return 0
	}
	if !iface.Loopback {
		return 1
	}
	return 2
}

func collectNetworkInventory() (*model.NetworkInterfaceInventory, string, error) {
	interfaces, err := listNetworkInterfaces()
	if err != nil {
		return nil, "", err
	}
	// Deterministic hash over canonical JSON.
	canonical, err := jsonMarshalCanonical(interfaces)
	if err != nil {
		return nil, "", err
	}
	hash := fmt.Sprintf("%x", sha256.Sum256(canonical))
	inv := &model.NetworkInterfaceInventory{Interfaces: interfaces, Hash: hash}
	return inv, hash, nil
}

func jsonMarshalCanonical(v any) ([]byte, error) {
	// Use standard json.Marshal which is deterministic for this struct (sorted fields).
	// For extra determinism, we could sort again but interfaces are already sorted.
	return json.Marshal(v)
}
