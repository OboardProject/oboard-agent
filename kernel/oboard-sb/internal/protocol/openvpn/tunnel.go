// SPDX-License-Identifier: GPL-3.0-or-later

package openvpn

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/ooni/minivpn/pkg/config"
	"github.com/ooni/minivpn/pkg/tunnel"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/transport/wireguard"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

// ErrTunnelClosed is returned by a tunnel that has shut down.
var ErrTunnelClosed = errors.New("openvpn tunnel closed")

// ErrIPv6Unsupported is returned for IPv6 destinations: the tunnel only carries
// IPv4 and an exit must never fall back to another path.
var ErrIPv6Unsupported = errors.New("openvpn exit does not carry IPv6")

// Tunnel is one established OpenVPN session bridged into a private gVisor
// network stack. All traffic it dials leaves through the VPN server; it has no
// path to the host network other than the encrypted session itself.
type Tunnel struct {
	spec      Spec
	device    wireguard.Device
	session   *tunnel.TUN
	resolver  *resolver
	localAddr netip.Addr
	handshake time.Duration
	done      chan struct{}
	closeOnce sync.Once
	closeErr  error
	errMu     sync.Mutex
}

type simpleDialer struct {
	dialer N.Dialer
}

func (d simpleDialer) DialContext(ctx context.Context, network, endpoint string) (net.Conn, error) {
	return d.dialer.DialContext(ctx, network, M.ParseSocksaddr(endpoint))
}

type loggerAdapter struct {
	logger log.ContextLogger
}

func (l loggerAdapter) Debug(string)          {}
func (l loggerAdapter) Debugf(string, ...any) {}
func (l loggerAdapter) Info(string)           {}
func (l loggerAdapter) Infof(string, ...any)  {}
func (l loggerAdapter) Warn(msg string) {
	if l.logger != nil {
		l.logger.Debug("openvpn: ", msg)
	}
}
func (l loggerAdapter) Warnf(format string, v ...any) {
	if l.logger != nil {
		l.logger.Debug("openvpn: ", fmt.Sprintf(format, v...))
	}
}

// Connect establishes a session described by an already normalized spec.
func Connect(ctx context.Context, dialer N.Dialer, spec Spec, logger log.ContextLogger) (*Tunnel, error) {
	options := &config.OpenVPNOptions{
		Remote:   spec.Server,
		Port:     strconv.Itoa(int(spec.ServerPort)),
		Proto:    config.ProtoTCP,
		Username: spec.Username,
		Password: spec.Password,
		CA:       []byte(spec.CA),
		Cert:     []byte(spec.Cert),
		Key:      []byte(spec.Key),
		Cipher:   spec.Cipher,
		Auth:     spec.Auth,
	}
	if spec.Network == "udp" {
		options.Proto = config.ProtoUDP
	}
	cfg := config.NewConfig(config.WithOpenVPNOptions(options), config.WithLogger(loggerAdapter{logger: logger}))
	started := time.Now()
	session, err := tunnel.Start(ctx, simpleDialer{dialer: dialer}, cfg)
	if err != nil {
		return nil, E.Cause(err, "openvpn handshake")
	}
	handshake := time.Since(started)
	localAddr, err := netip.ParseAddr(strings.TrimSpace(session.LocalAddr().String()))
	if err != nil || !localAddr.Unmap().Is4() {
		_ = session.Close()
		return nil, fmt.Errorf("openvpn server pushed an invalid tunnel address")
	}
	localAddr = localAddr.Unmap()
	device, err := wireguard.NewDevice(wireguard.DeviceOptions{
		Context: context.Background(),
		Logger:  logger,
		MTU:     uint32(spec.MTU),
		Address: []netip.Prefix{netip.PrefixFrom(localAddr, 32)},
	})
	if err != nil {
		_ = session.Close()
		return nil, E.Cause(err, "create openvpn network stack")
	}
	if err := device.Start(); err != nil {
		_ = device.Close()
		_ = session.Close()
		return nil, E.Cause(err, "start openvpn network stack")
	}
	t := &Tunnel{
		spec:      spec,
		device:    device,
		session:   session,
		localAddr: localAddr,
		handshake: handshake,
		done:      make(chan struct{}),
	}
	t.resolver = newResolver(t, spec.Resolvers)
	go t.pumpToServer()
	go t.pumpFromServer()
	go func() {
		select {
		case <-session.Done():
			t.closeWith(ErrTunnelClosed)
		case <-t.done:
		}
	}()
	return t, nil
}

func (t *Tunnel) pumpToServer() {
	bufs := [][]byte{make([]byte, 65535)}
	sizes := []int{0}
	for {
		n, err := t.device.Read(bufs, sizes, 0)
		if err != nil {
			t.closeWith(ErrTunnelClosed)
			return
		}
		for i := 0; i < n; i++ {
			packet := make([]byte, sizes[i])
			copy(packet, bufs[i][:sizes[i]])
			if _, err := t.session.Write(packet); err != nil {
				t.closeWith(ErrTunnelClosed)
				return
			}
		}
	}
}

func (t *Tunnel) pumpFromServer() {
	buffer := make([]byte, 65535)
	for {
		n, err := t.session.Read(buffer)
		if err != nil {
			t.closeWith(ErrTunnelClosed)
			return
		}
		if n == 0 {
			continue
		}
		if _, err := t.device.Write([][]byte{buffer[:n]}, 0); err != nil {
			t.closeWith(ErrTunnelClosed)
			return
		}
	}
}

func (t *Tunnel) closeWith(err error) {
	t.closeOnce.Do(func() {
		t.errMu.Lock()
		t.closeErr = err
		t.errMu.Unlock()
		close(t.done)
		_ = t.session.Close()
		_ = t.device.Close()
	})
}

// Close shuts the session and its network stack down.
func (t *Tunnel) Close() error {
	t.closeWith(ErrTunnelClosed)
	return nil
}

// Done is closed once the tunnel is unusable.
func (t *Tunnel) Done() <-chan struct{} {
	return t.done
}

// Alive reports whether the session is still established.
func (t *Tunnel) Alive() bool {
	select {
	case <-t.done:
		return false
	default:
		return true
	}
}

// HandshakeDuration is the time the OpenVPN handshake took.
func (t *Tunnel) HandshakeDuration() time.Duration {
	return t.handshake
}

// DialContext opens a connection through the tunnel. Domain names are
// resolved inside the tunnel; a resolution failure is a dial failure.
func (t *Tunnel) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	if !t.Alive() {
		return nil, ErrTunnelClosed
	}
	target, err := t.resolveDestination(ctx, destination)
	if err != nil {
		return nil, err
	}
	switch N.NetworkName(network) {
	case N.NetworkTCP, N.NetworkUDP:
	default:
		return nil, E.Extend(N.ErrUnknownNetwork, network)
	}
	return t.device.DialContext(ctx, network, target)
}

// ListenPacket opens a UDP socket inside the tunnel.
func (t *Tunnel) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	if !t.Alive() {
		return nil, ErrTunnelClosed
	}
	conn, err := t.device.ListenPacket(ctx, M.SocksaddrFrom(t.localAddr, 0))
	if err != nil {
		return nil, err
	}
	return &resolvingPacketConn{PacketConn: conn, tunnel: t}, nil
}

func (t *Tunnel) resolveDestination(ctx context.Context, destination M.Socksaddr) (M.Socksaddr, error) {
	if destination.IsFqdn() {
		addrs, err := t.resolver.lookupIPv4(ctx, destination.Fqdn)
		if err != nil {
			return M.Socksaddr{}, err
		}
		return M.SocksaddrFrom(addrs[0], destination.Port), nil
	}
	addr := destination.Addr.Unmap()
	if !addr.Is4() {
		return M.Socksaddr{}, ErrIPv6Unsupported
	}
	return M.SocksaddrFrom(addr, destination.Port), nil
}

type resolvingPacketConn struct {
	net.PacketConn
	tunnel *Tunnel
}

func (c *resolvingPacketConn) WriteTo(payload []byte, addr net.Addr) (int, error) {
	destination := M.SocksaddrFromNet(addr)
	ctx, cancel := context.WithTimeout(context.Background(), resolveTimeout)
	defer cancel()
	target, err := c.tunnel.resolveDestination(ctx, destination)
	if err != nil {
		return 0, err
	}
	return c.PacketConn.WriteTo(payload, target.UDPAddr())
}
