package model

// Logger is the generic logger definition.
type Logger interface {
	// Debug emits a debug message.
	Debug(msg string)

	// Debugf formats and emits a debug message.
	Debugf(format string, v ...any)

	// Info emits an informational message.
	Info(msg string)

	// Infof formats and emits an informational message.
	Infof(format string, v ...any)

	// Warn emits a warning message.
	Warn(msg string)

	// Warnf formats and emits a warning message.
	Warnf(format string, v ...any)
}

// NoopLogger discards every message.
type NoopLogger struct{}

func (NoopLogger) Debug(string)          {}
func (NoopLogger) Debugf(string, ...any) {}
func (NoopLogger) Info(string)           {}
func (NoopLogger) Infof(string, ...any)  {}
func (NoopLogger) Warn(string)           {}
func (NoopLogger) Warnf(string, ...any)  {}
