// SPDX-License-Identifier: GPL-3.0-or-later

package familyselector

import (
	"fmt"
	"strings"

	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
)

const Type = "family-selector"

type OutboundOptions struct {
	option.DialerOptions
	IPv4Outbound string                `json:"ipv4_outbound"`
	IPv6Outbound string                `json:"ipv6_outbound"`
	Strategy     option.DomainStrategy `json:"strategy"`
	Fallback     bool                  `json:"fallback"`
}

func (o OutboundOptions) validate() error {
	o.IPv4Outbound = strings.TrimSpace(o.IPv4Outbound)
	o.IPv6Outbound = strings.TrimSpace(o.IPv6Outbound)
	if o.IPv4Outbound == "" || o.IPv6Outbound == "" {
		return fmt.Errorf("family-selector requires ipv4_outbound and ipv6_outbound")
	}
	if o.IPv4Outbound == o.IPv6Outbound {
		return fmt.Errorf("family-selector child outbounds must be different")
	}
	switch C.DomainStrategy(o.Strategy) {
	case C.DomainStrategyPreferIPv4, C.DomainStrategyPreferIPv6:
	default:
		return fmt.Errorf("family-selector strategy must be prefer_ipv4 or prefer_ipv6")
	}
	if !o.Fallback {
		return fmt.Errorf("family-selector requires bounded family fallback")
	}
	if o.Detour != "" || o.BindInterface != "" || o.Inet4BindAddress != nil || o.Inet6BindAddress != nil {
		return fmt.Errorf("family-selector does not support detour, interface, or fixed bind options")
	}
	if o.NetworkStrategy != nil || len(o.NetworkType) > 0 || len(o.FallbackNetworkType) > 0 {
		return fmt.Errorf("family-selector does not support network strategy options")
	}
	return nil
}
