package agent

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"time"
)

const runtimeClockStateFile = "runtime-clock.json"

type runtimeClockState struct {
	Enabled       bool      `json:"enabled"`
	ReferenceTime time.Time `json:"reference_time"`
	LocalTime     time.Time `json:"local_time"`
	Source        string    `json:"source"`
	CheckedAt     time.Time `json:"checked_at"`
}

type runtimeClock struct {
	mu        sync.RWMutex
	enabled   bool
	reference time.Time
	anchor    time.Time
	source    string
	checkedAt time.Time
	stateDir  string
}

func newRuntimeClock(stateDir string) *runtimeClock {
	clock := &runtimeClock{stateDir: stateDir}
	clock.restore()
	return clock
}

func (c *runtimeClock) Now() time.Time {
	if c == nil {
		return time.Now()
	}
	c.mu.RLock()
	enabled, reference, anchor := c.enabled, c.reference, c.anchor
	c.mu.RUnlock()
	if !enabled || reference.IsZero() || anchor.IsZero() {
		return time.Now()
	}
	return reference.Add(time.Since(anchor))
}

func (c *runtimeClock) Apply(enabled bool, reference time.Time, source string, checkedAt time.Time) error {
	anchor := time.Now()
	if !enabled || reference.IsZero() {
		enabled = false
		reference = time.Time{}
	}
	if checkedAt.IsZero() {
		checkedAt = reference
	}
	c.mu.Lock()
	c.enabled = enabled
	c.reference = reference.UTC()
	c.anchor = anchor
	c.source = source
	c.checkedAt = checkedAt.UTC()
	c.mu.Unlock()
	return c.persist()
}

func (c *runtimeClock) Snapshot() runtimeClockState {
	if c == nil {
		return runtimeClockState{}
	}
	c.mu.RLock()
	enabled, source, checkedAt := c.enabled, c.source, c.checkedAt
	c.mu.RUnlock()
	state := runtimeClockState{Enabled: enabled, Source: source, CheckedAt: checkedAt, LocalTime: time.Now().UTC()}
	if enabled {
		state.ReferenceTime = c.Now().UTC()
	}
	return state
}

func (c *runtimeClock) persist() error {
	if c == nil {
		return nil
	}
	if err := os.MkdirAll(c.stateDir, 0o700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(c.Snapshot(), "", "  ")
	if err != nil {
		return err
	}
	return atomicWriteFile(filepath.Join(c.stateDir, runtimeClockStateFile), data, 0o600)
}

func (c *runtimeClock) restore() {
	if c == nil {
		return
	}
	data, err := os.ReadFile(filepath.Join(c.stateDir, runtimeClockStateFile))
	if err != nil {
		return
	}
	var state runtimeClockState
	if json.Unmarshal(data, &state) != nil || !state.Enabled || state.ReferenceTime.IsZero() || state.LocalTime.IsZero() {
		return
	}
	anchor := time.Now()
	reference := state.ReferenceTime.Add(anchor.Sub(state.LocalTime))
	c.enabled = true
	c.reference = reference.UTC()
	c.anchor = anchor
	c.source = state.Source
	c.checkedAt = state.CheckedAt.UTC()
}

func (r *Runner) setControllerReference(reference time.Time) {
	if r == nil || reference.IsZero() {
		return
	}
	r.controllerClockMu.Lock()
	r.controllerReference = reference.UTC()
	r.controllerReferenceAnchor = time.Now()
	r.controllerClockMu.Unlock()
}

func (r *Runner) controllerReferenceNow() (time.Time, bool) {
	if r == nil {
		return time.Time{}, false
	}
	r.controllerClockMu.RLock()
	reference, anchor := r.controllerReference, r.controllerReferenceAnchor
	r.controllerClockMu.RUnlock()
	if reference.IsZero() || anchor.IsZero() {
		return time.Time{}, false
	}
	age := time.Since(anchor)
	if age < 0 || age > controllerTimeMaxAge {
		return time.Time{}, false
	}
	return reference.Add(age), true
}
