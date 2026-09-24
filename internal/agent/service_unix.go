//go:build !windows

package agent

import (
	"errors"
	"time"
)

var errWindowsServiceManagerUnavailable = errors.New("windows service control manager is unavailable on this platform")

func windowsServiceActive(string) error                 { return errWindowsServiceManagerUnavailable }
func windowsServiceStart(string, time.Duration) error   { return errWindowsServiceManagerUnavailable }
func windowsServiceStop(string, time.Duration) error    { return errWindowsServiceManagerUnavailable }
func windowsServiceRestart(string, time.Duration) error { return errWindowsServiceManagerUnavailable }
func scheduleWindowsAgentRestart(string) error          { return errWindowsServiceManagerUnavailable }

func runDetachedPowerShell(string) error { return errWindowsServiceManagerUnavailable }
