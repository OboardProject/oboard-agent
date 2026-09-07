// SPDX-License-Identifier: GPL-3.0-or-later

package userselector

import (
	"fmt"
	"strings"
)

const Type = "user-selector"

// OutboundOptions maps an authenticated inbound user onto one already
// constructed outbound. Unknown users are denied. The map is replaced at
// runtime by /users/install; the configuration copy is only the baseline.
type OutboundOptions struct {
	Users map[string]string `json:"users,omitempty"`
}

func (o OutboundOptions) validate() error {
	for user, tag := range o.Users {
		if strings.TrimSpace(user) == "" || strings.TrimSpace(tag) == "" {
			return fmt.Errorf("user-selector entries require a non-empty user and outbound tag")
		}
	}
	return nil
}
