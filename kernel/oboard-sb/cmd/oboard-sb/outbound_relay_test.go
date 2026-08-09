package main

import (
	"bufio"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"math"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

type testOutboundRelayDialer struct {
	conn net.Conn
}

func (d *testOutboundRelayDialer) DialContext(context.Context, string, M.Socksaddr) (net.Conn, error) {
	if d.conn == nil {
		return nil, errors.New("missing test connection")
	}
	conn := d.conn
	d.conn = nil
	return conn, nil
}

func (d *testOutboundRelayDialer) ListenPacket(context.Context, M.Socksaddr) (net.PacketConn, error) {
	return nil, errors.New("unused")
}

func connectRelayForTest(t *testing.T, handler http.Handler, network string) (net.Conn, *bufio.Reader) {
	t.Helper()
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)
	conn, err := net.DialTimeout("tcp", strings.TrimPrefix(server.URL, "http://"), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	request := "CONNECT /outbounds/relay/" + network + " HTTP/1.1\r\nHost: oboard-sb\r\nX-OBoard-Outbound-Tag: path-7-step-1\r\nX-OBoard-Destination: 1.1.1.1:53\r\n\r\n"
	if _, err := io.WriteString(conn, request); err != nil {
		_ = conn.Close()
		t.Fatal(err)
	}
	reader := bufio.NewReader(conn)
	response, err := http.ReadResponse(reader, &http.Request{Method: http.MethodConnect})
	if err != nil {
		_ = conn.Close()
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusOK {
		_ = conn.Close()
		t.Fatalf("relay status = %d", response.StatusCode)
	}
	return conn, reader
}

func TestOutboundRelayRejectsUnmanagedTagsBeforeLookup(t *testing.T) {
	lookups := 0
	handler := newOutboundRelayHandler("tcp", func(string) (N.Dialer, bool) {
		lookups++
		return nil, false
	})
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodConnect, "/outbounds/relay/tcp", nil)
	request.Header.Set("X-OBoard-Outbound-Tag", "direct")
	request.Header.Set("X-OBoard-Destination", "1.1.1.1:443")
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusBadRequest || lookups != 0 {
		t.Fatalf("response=%d lookups=%d", recorder.Code, lookups)
	}
}

func TestOutboundRelayTCPIsBidirectional(t *testing.T) {
	target, dialed := net.Pipe()
	handler := newOutboundRelayHandler("tcp", func(tag string) (N.Dialer, bool) {
		return &testOutboundRelayDialer{conn: dialed}, tag == "path-7-step-1"
	})
	client, reader := connectRelayForTest(t, handler, "tcp")
	defer client.Close()
	defer target.Close()
	if _, err := client.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	request := make([]byte, 4)
	if _, err := io.ReadFull(target, request); err != nil || string(request) != "ping" {
		t.Fatalf("target read %q, %v", request, err)
	}
	if _, err := target.Write([]byte("pong")); err != nil {
		t.Fatal(err)
	}
	reply := make([]byte, 4)
	if _, err := io.ReadFull(reader, reply); err != nil || string(reply) != "pong" {
		t.Fatalf("client read %q, %v", reply, err)
	}
}

func TestOutboundRelayUDPFramesDatagrams(t *testing.T) {
	target, dialed := net.Pipe()
	handler := newOutboundRelayHandler("udp", func(tag string) (N.Dialer, bool) {
		return &testOutboundRelayDialer{conn: dialed}, tag == "path-7-step-1"
	})
	client, reader := connectRelayForTest(t, handler, "udp")
	defer client.Close()
	defer target.Close()
	frame := []byte{0, 4, 'p', 'i', 'n', 'g'}
	if _, err := client.Write(frame); err != nil {
		t.Fatal(err)
	}
	payload := make([]byte, 4)
	if _, err := io.ReadFull(target, payload); err != nil || string(payload) != "ping" {
		t.Fatalf("target read %q, %v", payload, err)
	}
	if _, err := target.Write([]byte("pong")); err != nil {
		t.Fatal(err)
	}
	var size [2]byte
	if _, err := io.ReadFull(reader, size[:]); err != nil {
		t.Fatal(err)
	}
	if binary.BigEndian.Uint16(size[:]) != 4 {
		t.Fatalf("reply size = %d", binary.BigEndian.Uint16(size[:]))
	}
	if _, err := io.ReadFull(reader, payload); err != nil || string(payload) != "pong" {
		t.Fatalf("client read %q, %v", payload, err)
	}

	maxPayload := make([]byte, math.MaxUint16)
	maxPayload[0] = 'a'
	maxPayload[len(maxPayload)-1] = 'z'
	if _, err := target.Write(maxPayload); err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadFull(reader, size[:]); err != nil {
		t.Fatal(err)
	}
	if got := binary.BigEndian.Uint16(size[:]); got != math.MaxUint16 {
		t.Fatalf("max reply size = %d", got)
	}
	maxReply := make([]byte, math.MaxUint16)
	if _, err := io.ReadFull(reader, maxReply); err != nil {
		t.Fatal(err)
	}
	if maxReply[0] != 'a' || maxReply[len(maxReply)-1] != 'z' {
		t.Fatal("max reply payload was corrupted")
	}
}
