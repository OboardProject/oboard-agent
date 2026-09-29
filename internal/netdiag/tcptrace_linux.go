//go:build linux

package netdiag

import (
	"context"
	"errors"
	"net/netip"
	"time"

	"golang.org/x/sys/unix"
)

// TCPTracer performs TTL-limited TCP SYN probes with native sockets.
var TCPTracer tcpTracer = tcpTraceProbe

// tcpTraceProbe opens a non-blocking TCP connection with a small TTL. A
// router answers with ICMP time exceeded (matched on the raw ICMP socket by
// our source port); the target answers with SYN-ACK or RST.
func tcpTraceProbe(ctx context.Context, transport probeTransport, dst netip.Addr, port, ttl int, timeout time.Duration) (tcpProbeOutcome, error) {
	family := unix.AF_INET
	if dst.Is6() {
		family = unix.AF_INET6
	}
	fd, err := unix.Socket(family, unix.SOCK_STREAM|unix.SOCK_NONBLOCK|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return tcpProbeOutcome{}, fail("failed", "cannot open TCP probe socket")
	}
	defer unix.Close(fd)
	if dst.Is6() {
		err = unix.SetsockoptInt(fd, unix.IPPROTO_IPV6, unix.IPV6_UNICAST_HOPS, ttl)
	} else {
		err = unix.SetsockoptInt(fd, unix.IPPROTO_IP, unix.IP_TTL, ttl)
	}
	if err != nil {
		return tcpProbeOutcome{}, fail("failed", "cannot set probe TTL")
	}
	var local, remote unix.Sockaddr
	if dst.Is6() {
		local = &unix.SockaddrInet6{}
		remote = &unix.SockaddrInet6{Port: port, Addr: dst.As16()}
	} else {
		local = &unix.SockaddrInet4{}
		remote = &unix.SockaddrInet4{Port: port, Addr: dst.As4()}
	}
	if err := unix.Bind(fd, local); err != nil {
		return tcpProbeOutcome{}, fail("failed", "cannot bind TCP probe socket")
	}
	bound, err := unix.Getsockname(fd)
	if err != nil {
		return tcpProbeOutcome{}, fail("failed", "cannot read probe port")
	}
	srcPort := 0
	switch address := bound.(type) {
	case *unix.SockaddrInet4:
		srcPort = address.Port
	case *unix.SockaddrInet6:
		srcPort = address.Port
	}
	sent := time.Now()
	if err := unix.Connect(fd, remote); err != nil && !errors.Is(err, unix.EINPROGRESS) {
		if errors.Is(err, unix.ECONNREFUSED) {
			return tcpProbeOutcome{reached: true, from: dst, rtt: time.Since(sent)}, nil
		}
		return tcpProbeOutcome{timeout: true}, nil
	}
	deadline := sent.Add(timeout)
	for time.Now().Before(deadline) && ctx.Err() == nil {
		fds := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLOUT}}
		if n, _ := unix.Poll(fds, 10); n > 0 && fds[0].Revents&(unix.POLLOUT|unix.POLLERR|unix.POLLHUP) != 0 {
			soErr, _ := unix.GetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_ERROR)
			switch unix.Errno(soErr) {
			case 0, unix.ECONNREFUSED, unix.ECONNRESET:
				return tcpProbeOutcome{reached: true, from: dst, rtt: time.Since(sent)}, nil
			}
		}
		wait := time.Now().Add(15 * time.Millisecond)
		if wait.After(deadline) {
			wait = deadline
		}
		got, at, err := transport.Receive(wait)
		if err != nil {
			continue
		}
		if got.proto != protocolTCP || got.srcPort != srcPort || got.dstPort != port || got.innerDst != dst {
			continue
		}
		switch got.kind {
		case replyTimeExceeded:
			return tcpProbeOutcome{from: got.from, rtt: at.Sub(sent)}, nil
		case replyUnreachable:
			return tcpProbeOutcome{from: got.from, rtt: at.Sub(sent), reached: got.from == dst}, nil
		}
	}
	return tcpProbeOutcome{timeout: true}, nil
}
