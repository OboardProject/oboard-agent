// Package logging is the Agent's leveled log front end. Every Agent process
// writes to one file that systemd or OpenRC appends to, so the level gate lives
// here rather than in each package: raising it must never require a rebuild or
// a second sink.
package logging

import (
	"log"
	"strings"
	"sync/atomic"
)

// Level orders the Agent's own diagnostics. It intentionally mirrors the
// sing-box level vocabulary so one panel control can drive Agent and kernel
// without translating names for the operator.
type Level int

const (
	LevelTrace Level = iota
	LevelDebug
	LevelInfo
	LevelWarn
	LevelError
)

// DefaultLevel is what an Agent runs at when nothing selected a level. It keeps
// lifecycle and task outcomes visible, which is what the existing installed
// base already writes.
const DefaultLevel = LevelInfo

var current atomic.Int32

func init() { current.Store(int32(DefaultLevel)) }

// ParseLevel resolves an operator-supplied name. An empty or unknown value is
// not an error here: configuration validation rejects those, and a logger that
// refused to log would hide the very failure being diagnosed.
func ParseLevel(value string) (Level, bool) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "trace":
		return LevelTrace, true
	case "debug":
		return LevelDebug, true
	case "info":
		return LevelInfo, true
	case "warn", "warning":
		return LevelWarn, true
	case "error":
		return LevelError, true
	default:
		return DefaultLevel, false
	}
}

func (l Level) String() string {
	switch l {
	case LevelTrace:
		return "trace"
	case LevelDebug:
		return "debug"
	case LevelWarn:
		return "warn"
	case LevelError:
		return "error"
	default:
		return "info"
	}
}

// Verbose reports the levels that can grow a log file fast enough to need the
// tightened rotation budget and the automatic expiry.
func (l Level) Verbose() bool { return l <= LevelDebug }

// SetLevel switches the active level for the whole process.
func SetLevel(level Level) { current.Store(int32(level)) }

// CurrentLevel is the active level.
func CurrentLevel() Level { return Level(current.Load()) }

// Enabled reports whether a record at this level would be written.
func Enabled(level Level) bool { return level >= CurrentLevel() }

func output(level Level, format string, args ...any) {
	if !Enabled(level) {
		return
	}
	log.Printf("["+level.String()+"] "+format, args...)
}

func Tracef(format string, args ...any) { output(LevelTrace, format, args...) }
func Debugf(format string, args ...any) { output(LevelDebug, format, args...) }
func Infof(format string, args ...any)  { output(LevelInfo, format, args...) }
func Warnf(format string, args ...any)  { output(LevelWarn, format, args...) }
func Errorf(format string, args ...any) { output(LevelError, format, args...) }
