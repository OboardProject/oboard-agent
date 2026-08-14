package agent

import (
	"bufio"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"net/netip"
	"os"
	"testing"
)

func TestFramedRelayPacketConnWritePayloadBounds(t *testing.T) {
	for _, payload := range [][]byte{nil, make([]byte, 65536)} {
		conn := &framedRelayPacketConn{}
		if _, err := conn.Write(payload); err == nil {
			t.Fatalf("payload length %d was accepted", len(payload))
		}
	}

	writer, reader := net.Pipe()
	defer writer.Close()
	defer reader.Close()
	payload := make([]byte, 65535)
	readResult := make(chan error, 1)
	go func() {
		frame := make([]byte, len(payload)+2)
		if _, err := io.ReadFull(reader, frame); err != nil {
			readResult <- err
			return
		}
		if got := binary.BigEndian.Uint16(frame[:2]); got != math.MaxUint16 {
			readResult <- fmt.Errorf("relay frame size = %d, want %d", got, math.MaxUint16)
			return
		}
		readResult <- nil
	}()
	conn := &framedRelayPacketConn{Conn: writer}
	if n, err := conn.Write(payload); err != nil || n != len(payload) {
		t.Fatalf("write max payload = %d, %v", n, err)
	}
	if err := <-readResult; err != nil {
		t.Fatal(err)
	}
}

func TestDialCoreRouteRelayCarriesBranchIdentityAndResolvedAddresses(t *testing.T) {
	temporary, err := os.CreateTemp("", "oboard-route-relay-")
	if err != nil {
		t.Fatal(err)
	}
	socket := temporary.Name()
	if err := temporary.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(socket); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Remove(socket) })
	listener, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	type observedRequest struct {
		path    string
		headers http.Header
		err     error
	}
	observed := make(chan observedRequest, 1)
	go func() {
		connection, err := listener.Accept()
		if err != nil {
			observed <- observedRequest{err: err}
			return
		}
		defer connection.Close()
		request, err := http.ReadRequest(bufio.NewReader(connection))
		if err != nil {
			observed <- observedRequest{err: err}
			return
		}
		observed <- observedRequest{path: request.URL.Path, headers: request.Header.Clone()}
		_, _ = io.WriteString(connection, "HTTP/1.1 200 Connection Established\r\nContent-Length: 0\r\n\r\n")
	}()

	connection, err := dialCoreRouteRelay(context.Background(), socket, "tcp", "in-17", "alice__oboard_path_23", "example.com:443", []netip.Addr{netip.MustParseAddr("1.1.1.1"), netip.MustParseAddr("2606:4700:4700::1111")})
	if err != nil {
		t.Fatal(err)
	}
	_ = connection.Close()
	request := <-observed
	if request.err != nil {
		t.Fatal(request.err)
	}
	if request.path != "/routes/relay/tcp" || request.headers.Get("X-OBoard-Inbound-Tag") != "in-17" || request.headers.Get("X-OBoard-Auth-User") != "alice__oboard_path_23" || request.headers.Get("X-OBoard-Destination") != "example.com:443" || request.headers.Get("X-OBoard-Resolved-Addresses") != "1.1.1.1,2606:4700:4700::1111" {
		t.Fatalf("route relay request path=%q headers=%#v", request.path, request.headers)
	}
}
