package main

import (
	"bufio"
	"encoding/binary"
	"io"
	"net"
	"net/netip"
	"testing"

	"github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
)

func TestParseRouteRelayAddressesRejectsNonPublicTargets(t *testing.T) {
	for _, value := range []string{"127.0.0.1", "10.0.0.1", "::1", "fe80::1", "not-an-ip"} {
		if _, err := parseRouteRelayAddresses(value); err == nil {
			t.Fatalf("address %q was accepted", value)
		}
	}
	addresses, err := parseRouteRelayAddresses("1.1.1.1,2606:4700:4700::1111,1.1.1.1")
	if err != nil || len(addresses) != 2 || addresses[0] != netip.MustParseAddr("1.1.1.1") {
		t.Fatalf("public addresses=%v error=%v", addresses, err)
	}
}

func TestRouteRelayPacketConnPreservesDatagramFrames(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	destination := M.ParseSocksaddr("1.1.1.1:53")
	packetConn := &routeRelayPacketConn{Conn: server, reader: bufio.NewReader(server), destination: destination}

	go func() {
		_, _ = client.Write([]byte{0, 4, 'p', 'i', 'n', 'g'})
	}()
	packet := buf.NewPacket()
	gotDestination, err := packetConn.ReadPacket(packet)
	if err != nil || gotDestination != destination || string(packet.Bytes()) != "ping" {
		t.Fatalf("read destination=%v payload=%q error=%v", gotDestination, packet.Bytes(), err)
	}
	packet.Release()

	go func() {
		if err := packetConn.WritePacket(buf.As([]byte("pong")), destination); err != nil {
			t.Errorf("write packet: %v", err)
		}
	}()
	var size [2]byte
	if _, err := io.ReadFull(client, size[:]); err != nil {
		t.Fatal(err)
	}
	payload := make([]byte, binary.BigEndian.Uint16(size[:]))
	if _, err := io.ReadFull(client, payload); err != nil || string(payload) != "pong" {
		t.Fatalf("reply payload=%q error=%v", payload, err)
	}
}
