package minibox

import (
	"errors"
	"sync/atomic"
	"time"
)

type RuntimeClockConfig struct {
	Enabled       bool      `json:"enabled"`
	ReferenceTime time.Time `json:"reference_time"`
	Source        string    `json:"source"`
	CheckedAt     time.Time `json:"checked_at"`
}

type runtimeClockState struct {
	RuntimeClockConfig
	anchor time.Time
}

type RuntimeClock struct {
	state atomic.Pointer[runtimeClockState]
}

func NewRuntimeClock() *RuntimeClock {
	clock := new(RuntimeClock)
	clock.state.Store(&runtimeClockState{})
	return clock
}

func (c *RuntimeClock) Configure(config RuntimeClockConfig) error {
	if c == nil {
		return errors.New("runtime clock is unavailable")
	}
	if config.Enabled && config.ReferenceTime.IsZero() {
		return errors.New("enabled runtime clock requires reference_time")
	}
	if !config.Enabled {
		config.ReferenceTime = time.Time{}
	}
	config.ReferenceTime = config.ReferenceTime.UTC()
	config.CheckedAt = config.CheckedAt.UTC()
	c.state.Store(&runtimeClockState{RuntimeClockConfig: config, anchor: time.Now()})
	return nil
}

func (c *RuntimeClock) Now() time.Time {
	if c == nil {
		return time.Now()
	}
	state := c.state.Load()
	if state == nil || !state.Enabled || state.ReferenceTime.IsZero() {
		return time.Now()
	}
	return state.ReferenceTime.Add(time.Since(state.anchor))
}

func (c *RuntimeClock) TimeFunc() func() time.Time {
	return c.Now
}

func (c *RuntimeClock) Snapshot() RuntimeClockConfig {
	if c == nil {
		return RuntimeClockConfig{}
	}
	state := c.state.Load()
	if state == nil {
		return RuntimeClockConfig{}
	}
	result := state.RuntimeClockConfig
	if result.Enabled {
		result.ReferenceTime = c.Now().UTC()
	}
	return result
}
