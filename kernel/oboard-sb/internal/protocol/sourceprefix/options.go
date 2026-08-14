// SPDX-License-Identifier: GPL-3.0-or-later

package sourceprefix

import (
	"fmt"
	"net/netip"
	"strings"

	"github.com/sagernet/sing-box/option"
)

const Type = "source-prefix"

type OutboundOptions struct {
	option.DialerOptions
	Prefix string `json:"prefix"`
}

func parsePrefix(value string) (netip.Prefix, error) {
	prefix, err := netip.ParsePrefix(strings.TrimSpace(value))
	if err != nil {
		return netip.Prefix{}, fmt.Errorf("source prefix: %w", err)
	}
	if !prefix.IsValid() {
		return netip.Prefix{}, fmt.Errorf("source prefix is invalid")
	}
	return prefix.Masked(), nil
}
