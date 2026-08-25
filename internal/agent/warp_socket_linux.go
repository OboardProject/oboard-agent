//go:build linux

package agent

import (
	"syscall"

	"golang.org/x/sys/unix"
)

func warpBindToInterfaceControl(interfaceName string) func(string, string, syscall.RawConn) error {
	return func(_, _ string, raw syscall.RawConn) error {
		var socketErr error
		if err := raw.Control(func(fd uintptr) {
			socketErr = unix.SetsockoptString(int(fd), unix.SOL_SOCKET, unix.SO_BINDTODEVICE, interfaceName)
		}); err != nil {
			return err
		}
		return socketErr
	}
}
