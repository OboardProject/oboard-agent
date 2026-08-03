// SPDX-License-Identifier: GPL-3.0-or-later

package mieru

import (
	"context"
	"time"

	mierucipher "github.com/enfein/mieru/v3/pkg/cipher"
	mieruprotocol "github.com/enfein/mieru/v3/pkg/protocol"
	"github.com/sagernet/sing/common/ntp"
	"github.com/sagernet/sing/service"
)

// applyRuntimeClock wires the box logical clock into the Mieru wire protocol.
// The Mieru fork derives wire-visible frame timestamps and cipher salts from
// an injectable clock; without this, a skewed wall clock with an active
// logical clock would stamp frames and salts the remote side rejects.
func applyRuntimeClock(ctx context.Context) {
	var f func() time.Time
	if clock := service.FromContext[ntp.TimeService](ctx); clock != nil {
		f = clock.TimeFunc()
	}
	mierucipher.SetTimeFunc(f)
	mieruprotocol.SetTimeFunc(f)
}
