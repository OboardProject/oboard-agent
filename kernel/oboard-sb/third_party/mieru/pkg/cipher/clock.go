// SPDX-License-Identifier: GPL-3.0-or-later
//
// OBoard fork addition: Mieru derives its wire-visible cipher salts from the
// wall clock. Hosts that run a corrected logical clock must inject it here so
// client and server keep deriving the same keys.

package cipher

import (
	"sync/atomic"
	"time"
)

var timeNow atomic.Pointer[func() time.Time]

// SetTimeFunc replaces the clock used for wire-visible cipher-salt
// derivation. A nil function restores the default wall clock.
func SetTimeFunc(f func() time.Time) {
	if f == nil {
		timeNow.Store(nil)
		return
	}
	timeNow.Store(&f)
}

func now() time.Time {
	if f := timeNow.Load(); f != nil {
		return (*f)()
	}
	return time.Now()
}
