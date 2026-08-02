package agent

import (
	"bytes"
	"context"
	"io"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"
)

type fakeBadVPNPacketConn struct {
	reads     chan []byte
	writes    chan []byte
	closed    chan struct{}
	closeOnce sync.Once
}

func newFakeBadVPNPacketConn() *fakeBadVPNPacketConn {
	return &fakeBadVPNPacketConn{reads: make(chan []byte, 1), writes: make(chan []byte, 1), closed: make(chan struct{})}
}

func (c *fakeBadVPNPacketConn) Read(buffer []byte) (int, error) {
	select {
	case payload := <-c.reads:
		if len(payload) > len(buffer) {
			return 0, io.ErrShortBuffer
		}
		return copy(buffer, payload), nil
	case <-c.closed:
		return 0, net.ErrClosed
	}
}

func (c *fakeBadVPNPacketConn) Write(payload []byte) (int, error) {
	copyOfPayload := append([]byte(nil), payload...)
	select {
	case c.writes <- copyOfPayload:
		return len(payload), nil
	case <-c.closed:
		return 0, net.ErrClosed
	}
}

func (c *fakeBadVPNPacketConn) Close() error {
	c.closeOnce.Do(func() { close(c.closed) })
	return nil
}

func TestBadVPNFrameMatchesPacketProtoWireFormat(t *testing.T) {
	destination := netip.MustParseAddrPort("1.1.1.1:53")
	packet, err := marshalBadVPNFrame(badVPNFrame{connection: 0x1234, destination: destination, payload: []byte("abc")})
	if err != nil {
		t.Fatal(err)
	}
	want := []byte{0x0c, 0x00, 0x00, 0x34, 0x12, 0x01, 0x01, 0x01, 0x01, 0x00, 0x35, 'a', 'b', 'c'}
	if !bytes.Equal(packet, want) {
		t.Fatalf("BadVPN packet = %x, want %x", packet, want)
	}
	decoded, err := readBadVPNFrame(bytes.NewReader(packet))
	if err != nil {
		t.Fatal(err)
	}
	if decoded.flags != 0 || decoded.connection != 0x1234 || decoded.destination != destination || !bytes.Equal(decoded.payload, []byte("abc")) {
		t.Fatalf("decoded BadVPN packet = %#v", decoded)
	}
}

func TestBadVPNGatewayRelaysUDPAndCountsPayload(t *testing.T) {
	server, client := net.Pipe()
	defer client.Close()
	fakeUDP := newFakeBadVPNPacketConn()
	dialed := make(chan netip.AddrPort, 1)
	counter := &sshInboundCounter{}
	audit := newConnectionAuditAccumulator(true)
	gateway := &badVPNGateway{
		stream:       server,
		counter:      counter,
		audit:        audit,
		userID:       7,
		inboundID:    31,
		sourceIP:     "198.51.100.10",
		associations: make(map[uint16]*badVPNAssociation),
		dial: func(_ context.Context, destination netip.AddrPort) (badVPNPacketConn, error) {
			dialed <- destination
			return fakeUDP, nil
		},
	}
	done := make(chan struct{})
	go func() {
		gateway.serve()
		close(done)
	}()

	destination := netip.MustParseAddrPort("1.1.1.1:53")
	request, err := marshalBadVPNFrame(badVPNFrame{flags: badVPNFlagDNS, connection: 9, destination: destination, payload: []byte("request")})
	if err != nil {
		t.Fatal(err)
	}
	if err := writeAll(client, request); err != nil {
		t.Fatal(err)
	}
	select {
	case got := <-dialed:
		if got != destination {
			t.Fatalf("dialed destination = %s, want %s", got, destination)
		}
	case <-time.After(time.Second):
		t.Fatal("UDP destination was not dialed")
	}
	select {
	case got := <-fakeUDP.writes:
		if !bytes.Equal(got, []byte("request")) {
			t.Fatalf("UDP payload = %q", got)
		}
	case <-time.After(time.Second):
		t.Fatal("UDP payload was not relayed")
	}

	fakeUDP.reads <- []byte("response")
	response, err := readBadVPNFrame(client)
	if err != nil {
		t.Fatal(err)
	}
	if response.flags != 0 || response.connection != 9 || response.destination != destination || !bytes.Equal(response.payload, []byte("response")) {
		t.Fatalf("BadVPN response = %#v", response)
	}
	deadline := time.Now().Add(time.Second)
	for counter.download.Load() != int64(len("response")) && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if counter.upload.Load() != int64(len("request")) || counter.download.Load() != int64(len("response")) {
		t.Fatalf("traffic counters = upload %d download %d", counter.upload.Load(), counter.download.Load())
	}

	_ = client.Close()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("BadVPN gateway did not stop with its SSH channel")
	}
	auditItems := audit.drain()
	if len(auditItems) != 1 || auditItems[0].Network != "udp" || auditItems[0].Destination != destination.Addr().String() || auditItems[0].DestinationPort != int(destination.Port()) || auditItems[0].ClosedCount != 1 {
		t.Fatalf("BadVPN audit items = %#v", auditItems)
	}
}

func TestBadVPNGatewayEndpointDoesNotOpenOtherLoopbackDestinations(t *testing.T) {
	if !isBadVPNUDPGatewayDestination("127.0.0.1", 7300) || !isBadVPNUDPGatewayDestination("::1", 7300) {
		t.Fatal("fixed BadVPN UDP gateway endpoint was rejected")
	}
	for _, target := range []struct {
		host string
		port uint32
	}{{"127.0.0.1", 22}, {"localhost", 7300}, {"10.0.0.1", 7300}, {"::1", 22}} {
		if isBadVPNUDPGatewayDestination(target.host, target.port) {
			t.Fatalf("unexpected BadVPN gateway endpoint %s:%d", target.host, target.port)
		}
	}
}

func TestBadVPNGatewayRejectsPrivateUDPDestinations(t *testing.T) {
	server, client := net.Pipe()
	counter := &sshInboundCounter{}
	dialed := make(chan netip.AddrPort, 1)
	gateway := &badVPNGateway{
		stream:       server,
		counter:      counter,
		associations: make(map[uint16]*badVPNAssociation),
		dial: func(_ context.Context, destination netip.AddrPort) (badVPNPacketConn, error) {
			dialed <- destination
			return newFakeBadVPNPacketConn(), nil
		},
	}
	done := make(chan struct{})
	go func() {
		gateway.serve()
		close(done)
	}()
	request, err := marshalBadVPNFrame(badVPNFrame{connection: 1, destination: netip.MustParseAddrPort("10.0.0.1:53"), payload: []byte("blocked")})
	if err != nil {
		t.Fatal(err)
	}
	if err := writeAll(client, request); err != nil {
		t.Fatal(err)
	}
	_ = client.Close()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("BadVPN gateway did not stop")
	}
	select {
	case destination := <-dialed:
		t.Fatalf("private UDP destination was dialed: %s", destination)
	default:
	}
}
