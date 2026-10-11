//go:build linux || darwin

package proxydscp

import (
	"context"
	"errors"
	"golang.org/x/sys/unix"
	"net"
	"slices"
	"syscall"
	"testing"
	"time"
)

func socketClass(t *testing.T, c syscall.Conn, ipv6 bool, set *int) int {
	t.Helper()
	raw, e := c.SyscallConn()
	if e != nil {
		t.Fatal(e)
	}
	level, opt := unix.IPPROTO_IP, unix.IP_TOS
	if ipv6 {
		level, opt = unix.IPPROTO_IPV6, unix.IPV6_TCLASS
	}
	var value int
	var inner error
	e = raw.Control(func(fd uintptr) {
		if set != nil {
			inner = unix.SetsockoptInt(int(fd), level, opt, *set)
		} else {
			value, inner = unix.GetsockoptInt(int(fd), level, opt)
		}
	})
	if e != nil || inner != nil {
		t.Fatal(e, inner)
	}
	return value
}
func TestLiveUDPSwitchPreservesECNAndManagementSockets(t *testing.T) {
	for _, network := range []string{"udp4", "udp6"} {
		t.Run(network, func(t *testing.T) {
			addr := "127.0.0.1:0"
			if network == "udp6" {
				addr = "[::1]:0"
			}
			proxy, err := net.ListenPacket(network, addr)
			if err != nil {
				t.Fatal(err)
			}
			defer proxy.Close()
			management, err := net.ListenPacket(network, addr)
			if err != nil {
				t.Fatal(err)
			}
			defer management.Close()
			pc := proxy.(*net.UDPConn)
			mc := management.(*net.UDPConn)
			v6 := network == "udp6"
			ecn := 3
			socketClass(t, pc, v6, &ecn)
			m, _ := New("", nil)
			m.Track(pc)
			if err = m.Configure(Policy{true, 1}); err != nil {
				t.Fatal(err)
			}
			if got := socketClass(t, pc, v6, nil); got != 46<<2|ecn {
				t.Fatalf("DSCP/ECN got=%d", got)
			}
			if got := socketClass(t, mc, v6, nil); got != 0 {
				t.Fatal("management socket marked", got)
			}
			if _, err = pc.WriteToUDP([]byte("probe"), mc.LocalAddr().(*net.UDPAddr)); err != nil {
				t.Fatal(err)
			}
			_ = mc.SetReadDeadline(time.Now().Add(time.Second))
			var b [16]byte
			if n, _, e := mc.ReadFromUDP(b[:]); e != nil || string(b[:n]) != "probe" {
				t.Fatal("UDP traffic interrupted", e)
			}
			if err = m.Configure(Policy{false, 2}); err != nil {
				t.Fatal(err)
			}
			if got := socketClass(t, pc, v6, nil); got != ecn {
				t.Fatal("disable lost ECN", got)
			}
		})
	}
}
func TestNewTCPUsesPolicyWithoutWrappingConnection(t *testing.T) {
	l, e := net.Listen("tcp4", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	defer l.Close()
	m, _ := New("", nil)
	m.Track(l.(*net.TCPListener))
	if e = m.Configure(Policy{true, 1}); e != nil {
		t.Fatal(e)
	}
	d := net.Dialer{Control: m.Control}
	c, e := d.DialContext(context.Background(), "tcp4", l.Addr().String())
	if e != nil {
		t.Fatal(e)
	}
	defer c.Close()
	accepted, e := l.Accept()
	if e != nil {
		t.Fatal(e)
	}
	defer accepted.Close()
	if _, ok := c.(*net.TCPConn); !ok {
		t.Fatal("connection wrapped")
	}
	if got := socketClass(t, c.(*net.TCPConn), false, nil) >> 2; got != 46 {
		t.Fatal("dial DSCP", got)
	}
	if got := socketClass(t, accepted.(*net.TCPConn), false, nil) >> 2; got != 46 {
		t.Fatal("accepted DSCP", got)
	}
	if e = m.Configure(Policy{false, 2}); e != nil {
		t.Fatal(e)
	}
	if got := socketClass(t, l.(*net.TCPListener), false, nil) >> 2; got != 0 {
		t.Fatal("listener not reset", got)
	}
	if got := socketClass(t, c.(*net.TCPConn), false, nil) >> 2; got != 46 {
		t.Fatal("existing TCP changed", got)
	}
}

func TestIPv6MPTCPFallbackDoesNotHideRealErrors(t *testing.T) {
	for _, tt := range []struct {
		name                    string
		only                    int
		err6, error4, onlyError error
		mptcp                   bool
		want4                   bool
		wantError               error
	}{
		{name: "dual MPTCP", err6: unix.EOPNOTSUPP, mptcp: true, want4: true, wantError: errIPv6MPTCPUnsupported},
		{name: "IPv6-only MPTCP", only: 1, err6: unix.EOPNOTSUPP, mptcp: true, wantError: errIPv6MPTCPUnsupported},
		{name: "ordinary TCP", err6: unix.EOPNOTSUPP, want4: true, wantError: unix.EOPNOTSUPP},
		{name: "IPv4 denied", err6: unix.EOPNOTSUPP, error4: unix.EPERM, mptcp: true, want4: true, wantError: unix.EPERM},
		{name: "both unsupported", err6: unix.EOPNOTSUPP, error4: unix.EOPNOTSUPP, mptcp: true, want4: true, wantError: unix.EOPNOTSUPP},
		{name: "IPv6 denied", err6: unix.EACCES, mptcp: true, want4: true, wantError: unix.EACCES},
		{name: "cannot read dual stack", err6: unix.EOPNOTSUPP, onlyError: unix.EBADF, mptcp: true, wantError: unix.EBADF},
		{name: "ordinary dual stack success", want4: true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			var options []int
			err := setIPv6Options(func(level, opt int) error {
				options = append(options, opt)
				if level == unix.IPPROTO_IPV6 {
					return tt.err6
				}
				if level != unix.IPPROTO_IP || opt != unix.IP_TOS {
					t.Fatal("unexpected socket option", level, opt)
				}
				return tt.error4
			}, func() (int, error) { return tt.only, tt.onlyError }, func() bool { return tt.mptcp })
			if !errors.Is(err, tt.wantError) {
				t.Fatalf("got %v want %v", err, tt.wantError)
			}
			if slices.Contains(options, unix.IP_TOS) != tt.want4 {
				t.Fatal("IPv4 fallback mismatch", options)
			}
			if len(options) == 0 || options[0] != unix.IPV6_TCLASS {
				t.Fatal("IPv6 was not attempted first", options)
			}
			if tt.wantError != errIPv6MPTCPUnsupported && errors.Is(err, errIPv6MPTCPUnsupported) {
				t.Fatal("real error hidden as limitation")
			}
		})
	}
}
