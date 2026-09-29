//go:build linux || darwin

package netdiag

import (
	"errors"
	"net"
	"net/netip"
	"os"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"

	"github.com/OboardProject/oboard-agent/internal/model"
)

// rawTransport uses one privileged raw ICMP socket for sending echo probes
// and for receiving every ICMP answer (echo replies and errors quoting UDP or
// TCP probes).
type rawTransport struct {
	v6   bool
	conn *icmp.PacketConn
}

// OpenRawTransport is the production transport factory.
func OpenRawTransport(v6 bool) (probeTransport, error) {
	network, address := "ip4:icmp", "0.0.0.0"
	if v6 {
		network, address = "ip6:ipv6-icmp", "::"
	}
	conn, err := icmp.ListenPacket(network, address)
	if err != nil {
		if errors.Is(err, os.ErrPermission) {
			return nil, fail(model.NetworkDiagnosticCodeUnsupported, "raw ICMP sockets are not permitted for this Agent")
		}
		return nil, fail(model.NetworkDiagnosticCodeUnsupported, "raw ICMP sockets are unavailable")
	}
	return &rawTransport{v6: v6, conn: conn}, nil
}

func (t *rawTransport) SendEcho(dst netip.Addr, id, seq, ttl, size int) error {
	var messageType icmp.Type = ipv4.ICMPTypeEcho
	if t.v6 {
		messageType = ipv6.ICMPTypeEchoRequest
		if err := t.conn.IPv6PacketConn().SetHopLimit(ttl); err != nil {
			return err
		}
	} else if err := t.conn.IPv4PacketConn().SetTTL(ttl); err != nil {
		return err
	}
	payload := make([]byte, size)
	copy(payload, "oboard-netdiag")
	message := icmp.Message{Type: messageType, Body: &icmp.Echo{ID: id, Seq: seq, Data: payload}}
	raw, err := message.Marshal(nil)
	if err != nil {
		return err
	}
	_, err = t.conn.WriteTo(raw, &net.IPAddr{IP: net.IP(dst.AsSlice())})
	return err
}

func (t *rawTransport) SendUDP(dst netip.Addr, port, ttl int) (int, error) {
	network := "udp4"
	if t.v6 {
		network = "udp6"
	}
	conn, err := net.ListenUDP(network, nil)
	if err != nil {
		return 0, err
	}
	defer conn.Close()
	if t.v6 {
		if err := ipv6.NewConn(conn).SetHopLimit(ttl); err != nil {
			return 0, err
		}
	} else if err := ipv4.NewConn(conn).SetTTL(ttl); err != nil {
		return 0, err
	}
	if _, err := conn.WriteToUDP([]byte("oboard-netdiag"), &net.UDPAddr{IP: net.IP(dst.AsSlice()), Port: port}); err != nil {
		return 0, err
	}
	local, ok := conn.LocalAddr().(*net.UDPAddr)
	if !ok {
		return 0, errors.New("unexpected local address")
	}
	return local.Port, nil
}

func (t *rawTransport) Receive(deadline time.Time) (reply, time.Time, error) {
	buffer := make([]byte, 1500)
	for {
		if err := t.conn.SetReadDeadline(deadline); err != nil {
			return reply{}, time.Time{}, err
		}
		n, peer, err := t.conn.ReadFrom(buffer)
		at := time.Now()
		if err != nil {
			return reply{}, at, errReceiveTimeout
		}
		addr, ok := peer.(*net.IPAddr)
		if !ok {
			continue
		}
		from, ok := netip.AddrFromSlice(addr.IP)
		if !ok {
			continue
		}
		if parsed, ok := parseReply(t.v6, buffer[:n], from); ok {
			return parsed, at, nil
		}
	}
}

func (t *rawTransport) Close() error { return t.conn.Close() }
