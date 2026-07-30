// SPDX-License-Identifier: GPL-3.0-or-later

package mieru

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
)

const maxPorts = 64

func expandPorts(primary uint16, ranges []string) ([]uint16, error) {
	ports := make(map[uint16]struct{})
	if primary != 0 {
		ports[primary] = struct{}{}
	}
	for _, portRange := range ranges {
		begin, end, err := parsePortRange(portRange)
		if err != nil {
			return nil, err
		}
		for port := begin; port <= end; port++ {
			portNumber, err := uint16Port(port)
			if err != nil {
				return nil, err
			}
			ports[portNumber] = struct{}{}
			if len(ports) > maxPorts {
				return nil, fmt.Errorf("mieru supports at most %d unique ports", maxPorts)
			}
		}
	}
	if len(ports) == 0 {
		return nil, fmt.Errorf("at least one port must be set")
	}
	result := make([]uint16, 0, len(ports))
	for port := range ports {
		result = append(result, port)
	}
	sort.Slice(result, func(i, j int) bool { return result[i] < result[j] })
	return result, nil
}

func uint16Port(value int) (uint16, error) {
	if value < 1 || value > 65535 {
		return 0, fmt.Errorf("invalid port %d", value)
	}
	return uint16(value), nil // #nosec G115 -- value is bounded to the uint16 port range.
}

func parsePortRange(value string) (int, int, error) {
	if strings.TrimSpace(value) != value {
		return 0, 0, fmt.Errorf("invalid port range %q", value)
	}
	beginText, endText, found := strings.Cut(value, "-")
	if !found || beginText == "" || endText == "" || strings.Contains(endText, "-") {
		return 0, 0, fmt.Errorf("invalid port range %q", value)
	}
	begin, err := strconv.Atoi(beginText)
	if err != nil {
		return 0, 0, fmt.Errorf("invalid port range %q", value)
	}
	end, err := strconv.Atoi(endText)
	if err != nil {
		return 0, 0, fmt.Errorf("invalid port range %q", value)
	}
	if begin < 1 || begin > 65535 || end < 1 || end > 65535 || begin > end {
		return 0, 0, fmt.Errorf("invalid port range %q", value)
	}
	return begin, end, nil
}
