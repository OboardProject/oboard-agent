//go:build linux || darwin

package proxydscp

import (
	"errors"
	"syscall"

	"golang.org/x/sys/unix"
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
			inner = setIPv6Options(set, func() (int, error) {
				return unix.GetsockoptInt(int(fd), unix.IPPROTO_IPV6, unix.IPV6_V6ONLY)
			}, func() bool { return isMPTCPSocket(int(fd)) })
		}
	})
	if err != nil {
		return err
	}
	return inner
}

// Both address families must be attempted: a dual-stack MPTCP listener can
// accept IPv4 TOS even when its IPv6 traffic-class option is unsupported.
func setIPv6Options(set func(int, int) error, v6Only func() (int, error), mptcp func() bool) error {
	err6 := set(unix.IPPROTO_IPV6, unix.IPV6_TCLASS)
	only, errOnly := v6Only()
	if errOnly != nil {
		return errors.Join(err6, errOnly)
	}
	if only == 0 {
		if err4 := set(unix.IPPROTO_IP, unix.IP_TOS); err4 != nil {
			return errors.Join(err6, err4)
		}
	}
	if errors.Is(err6, unix.EOPNOTSUPP) && mptcp() {
		return errIPv6MPTCPUnsupported
	}
	return err6
}
