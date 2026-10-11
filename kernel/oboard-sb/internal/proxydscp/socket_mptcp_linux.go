package proxydscp

import "golang.org/x/sys/unix"

func isMPTCPSocket(fd int) bool {
	protocol, err := unix.GetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_PROTOCOL)
	return err == nil && protocol == unix.IPPROTO_MPTCP
}
