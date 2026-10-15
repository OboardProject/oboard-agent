// SPDX-License-Identifier: GPL-3.0-or-later

// Package vpngatepool implements a fail-closed exit backed by an ordered set
// of OpenVPN servers. The outbound in the kernel configuration only names the
// pool; its members are delivered at runtime by Agent so a member change never
// restarts the kernel. With no healthy member every dial fails: the pool never
// falls back to a direct or any other path.
package vpngatepool

import (
	"fmt"
	"regexp"

	"github.com/sagernet/sing-box/option"
)

const Type = "vpngate-pool"

const (
	defaultHotStandby     = 1
	maxHotStandby         = 2
	defaultHealthInterval = 10
	minHealthInterval     = 5
	maxHealthInterval     = 60
	MaxMembers            = 8
)

// TagPattern is the only outbound tag form a pool may use.
var TagPattern = regexp.MustCompile(`^vpngate-[1-9][0-9]{0,18}$`)

type OutboundOptions struct {
	option.DialerOptions
	PoolID                int64 `json:"pool_id"`
	HotStandby            *int  `json:"hot_standby,omitempty"`
	HealthIntervalSeconds int   `json:"health_interval_seconds,omitempty"`
}

func (o *OutboundOptions) normalize(tag string) error {
	if !TagPattern.MatchString(tag) {
		return fmt.Errorf("vpngate-pool tag must match vpngate-<pool_id>")
	}
	if o.PoolID <= 0 || tag != fmt.Sprintf("vpngate-%d", o.PoolID) {
		return fmt.Errorf("vpngate-pool pool_id must match its tag")
	}
	if o.HotStandby == nil {
		value := defaultHotStandby
		o.HotStandby = &value
	}
	if *o.HotStandby < 0 || *o.HotStandby > maxHotStandby {
		return fmt.Errorf("vpngate-pool hot_standby must be between 0 and %d", maxHotStandby)
	}
	if o.HealthIntervalSeconds == 0 {
		o.HealthIntervalSeconds = defaultHealthInterval
	}
	if o.HealthIntervalSeconds < minHealthInterval || o.HealthIntervalSeconds > maxHealthInterval {
		return fmt.Errorf("vpngate-pool health_interval_seconds must be between %d and %d", minHealthInterval, maxHealthInterval)
	}
	if o.Detour != "" {
		return fmt.Errorf("vpngate-pool does not support detour")
	}
	return nil
}
