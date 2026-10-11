//go:build !linux && !darwin

package proxydscp

import (
	"errors"
	"syscall"
)

const supported = false

func setSocket(syscall.RawConn, bool) error {
	return errors.New("socket DSCP unsupported on this platform")
}
