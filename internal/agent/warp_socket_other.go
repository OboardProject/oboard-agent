//go:build !linux

package agent

import "syscall"

func warpBindToInterfaceControl(string) func(string, string, syscall.RawConn) error {
	return nil
}
