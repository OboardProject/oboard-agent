// SPDX-License-Identifier: GPL-3.0-or-later
//
// OBoard fork addition: every Mieru metadata frame carries a wall-clock
// minute timestamp that the receiver validates within a one-minute window.
// Hosts that run a corrected logical clock must inject it here so frames are
// stamped with the same time base the remote side expects.

package protocol

import (
	"sync/atomic"
	"time"
)

var timeNow atomic.Pointer[func() time.Time]

// SetTimeFunc replaces the clock used for wire-visible metadata timestamps.
// A nil function restores the default wall clock.
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
