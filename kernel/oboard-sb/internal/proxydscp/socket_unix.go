//go:build linux || darwin

package proxydscp

import (
	"golang.org/x/sys/unix"
	"syscall"
)

const supported = true

func setSocket(raw syscall.RawConn, enabled bool) error {
	var inner error
	err := raw.Control(func(fd uintptr) {
		sa, e := unix.Getsockname(int(fd))
		if e != nil {
			inner = e
			return
		}
		set := func(level, opt int) error {
			old, e := unix.GetsockoptInt(int(fd), level, opt)
			if e != nil {
				return e
			}
			next := old & 3
			if enabled {
				next |= Value << 2
			}
			if old == next {
				return nil
			}
			return unix.SetsockoptInt(int(fd), level, opt, next)
		}
		switch sa.(type) {
		case *unix.SockaddrInet4:
			inner = set(unix.IPPROTO_IP, unix.IP_TOS)
		case *unix.SockaddrInet6:
			inner = set(unix.IPPROTO_IPV6, unix.IPV6_TCLASS)
			// Dual-stack listeners also send IPv4-mapped traffic.
			only, _ := unix.GetsockoptInt(int(fd), unix.IPPROTO_IPV6, unix.IPV6_V6ONLY)
			if only == 0 && inner == nil {
				inner = set(unix.IPPROTO_IP, unix.IP_TOS)
			}
		}
	})
	if err != nil {
		return err
	}
	return inner
}
