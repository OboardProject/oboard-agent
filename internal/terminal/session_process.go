package terminal

import "io"

// Session is a running shell attached to a pseudo terminal: a Unix PTY on
// Linux and a ConPTY pseudo console on Windows.
type Session interface {
	io.Reader
	io.Writer
	// Resize changes the terminal window size.
	Resize(cols, rows int) error
	// Close releases the terminal and ends the shell together with every
	// process it started. It is safe to call more than once.
	Close() error
	// ExitCode reports the shell's exit status, or -1 while it is unknown.
	ExitCode() int
}
