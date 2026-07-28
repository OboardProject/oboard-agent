package minibox

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	M "github.com/sagernet/sing/common/metadata"
)

func testTrustedReceiver(network string, listenPort, targetPort int, key []byte) RuntimeTrustedForwardReceiver {
	return RuntimeTrustedForwardReceiver{
		Version: 1, ID: "receiver-1", PathID: 7, InboundTag: "trusted-in", Network: network,
		Listen: "127.0.0.1", ListenPort: listenPort, Target: "127.0.0.1", TargetPort: targetPort,
		Key: base64.RawStdEncoding.EncodeToString(key), MaxClockSkewSeconds: 120,
	}
}

func testFreePort(t *testing.T, network string) int {
	t.Helper()
	if network == "tcp" {
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer listener.Close()
		return listener.Addr().(*net.TCPAddr).Port
	}
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	return conn.LocalAddr().(*net.UDPAddr).Port
}

func testAppendSource(frame []byte, source netip.AddrPort) []byte {
	addr := source.Addr().Unmap()
	if addr.Is4() {
		frame = append(frame, 4)
		raw := addr.As4()
		frame = append(frame, raw[:]...)
	} else {
		frame = append(frame, 6)
		raw := addr.As16()
		frame = append(frame, raw[:]...)
	}
	var port [2]byte
	binary.BigEndian.PutUint16(port[:], source.Port())
	return append(frame, port[:]...)
}

func testAppendMAC(frame, key []byte, size int) []byte {
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write(frame)
	return append(frame, mac.Sum(nil)[:size]...)
}

func testTCPFrameAt(key []byte, source netip.AddrPort, payload []byte, timestamp int64, nonce [16]byte) []byte {
	frame := append([]byte(nil), trustedForwardTCPMagic...)
	frame = append(frame, trustedForwardVersion, trustedForwardTCPData)
	var timestampBytes [8]byte
	binary.BigEndian.PutUint64(timestampBytes[:], uint64(timestamp))
	frame = append(frame, timestampBytes[:]...)
	frame = append(frame, nonce[:]...)
	frame = testAppendSource(frame, source)
	var size [2]byte
	binary.BigEndian.PutUint16(size[:], uint16(len(payload)))
	frame = append(frame, size[:]...)
	frame = append(frame, payload...)
	return testAppendMAC(frame, key, trustedForwardTCPMACSize)
}

func testTCPFrame(key []byte, source netip.AddrPort, payload []byte) []byte {
	var nonce [16]byte
	nonce[15] = 1
	return testTCPFrameAt(key, source, payload, time.Now().Unix(), nonce)
}

func testUDPFrameAt(key []byte, source netip.AddrPort, payload []byte, sessionID [8]byte, counter uint32, timestamp int64) []byte {
	frame := append([]byte(nil), trustedForwardUDPMagic...)
	frame = append(frame, trustedForwardVersion<<4|trustedForwardUDPData)
	var timestampBytes [4]byte
	binary.BigEndian.PutUint32(timestampBytes[:], uint32(timestamp))
	frame = append(frame, timestampBytes[:]...)
	frame = append(frame, sessionID[:]...)
	var sequence [4]byte
	binary.BigEndian.PutUint32(sequence[:], counter)
	frame = append(frame, sequence[:]...)
	frame = testAppendSource(frame, source)
	frame = append(frame, payload...)
	return testAppendMAC(frame, key, trustedForwardUDPMACSize)
}

func testUDPFrame(key []byte, source netip.AddrPort, payload []byte, sessionID [8]byte, counter uint32) []byte {
	return testUDPFrameAt(key, source, payload, sessionID, counter, time.Now().Unix())
}

func TestTrustedForwardTCPRestoresAuditSource(t *testing.T) {
	key := []byte("01234567890123456789012345678901")
	inner, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer inner.Close()
	receiver := testTrustedReceiver("tcp", testFreePort(t, "tcp"), inner.Addr().(*net.TCPAddr).Port, key)
	metadata := RuntimeMetadata{ConnectionAudit: &RuntimeConnectionAudit{Enabled: true}, TrustedForward: &RuntimeTrustedForward{Receivers: []RuntimeTrustedForwardReceiver{receiver}}}
	tracker := NewRateLimitTracker(metadata)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	manager, err := StartTrustedForwardReceivers(ctx, metadata.TrustedForward, tracker)
	if err != nil {
		t.Fatal(err)
	}
	defer manager.Close()

	verified := make(chan error, 1)
	go func() {
		conn, acceptErr := inner.Accept()
		if acceptErr != nil {
			verified <- acceptErr
			return
		}
		defer conn.Close()
		payload := make([]byte, 5)
		if _, readErr := io.ReadFull(conn, payload); readErr != nil {
			verified <- readErr
			return
		}
		actual, trusted, ok := tracker.trustedAuditSource(adapter.InboundContext{Inbound: receiver.InboundTag, Source: M.SocksaddrFromNet(conn.RemoteAddr())})
		if !ok || !trusted || actual.String() != "198.51.100.20" {
			verified <- fmt.Errorf("trusted source = %s, %t, %t", actual, trusted, ok)
			return
		}
		_, writeErr := conn.Write([]byte("world"))
		verified <- writeErr
	}()

	client, err := net.Dial("tcp", net.JoinHostPort(receiver.Listen, fmt.Sprint(receiver.ListenPort)))
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	source := netip.MustParseAddrPort("198.51.100.20:54321")
	if err := writeTrustedForward(client, testTCPFrame(key, source, []byte("hello"))); err != nil {
		t.Fatal(err)
	}
	reply := make([]byte, 5)
	if _, err := io.ReadFull(client, reply); err != nil || string(reply) != "world" {
		t.Fatalf("reply = %q, err=%v", reply, err)
	}
	if err := <-verified; err != nil {
		t.Fatal(err)
	}
}

func TestTrustedForwardUDPRestoresAuditSource(t *testing.T) {
	key := []byte("01234567890123456789012345678901")
	inner, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	defer inner.Close()
	receiver := testTrustedReceiver("udp", testFreePort(t, "udp"), inner.LocalAddr().(*net.UDPAddr).Port, key)
	metadata := RuntimeMetadata{ConnectionAudit: &RuntimeConnectionAudit{Enabled: true}, TrustedForward: &RuntimeTrustedForward{Receivers: []RuntimeTrustedForwardReceiver{receiver}}}
	tracker := NewRateLimitTracker(metadata)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	manager, err := StartTrustedForwardReceivers(ctx, metadata.TrustedForward, tracker)
	if err != nil {
		t.Fatal(err)
	}
	defer manager.Close()

	verified := make(chan error, 1)
	go func() {
		buffer := make([]byte, 64)
		n, remote, readErr := inner.ReadFromUDP(buffer)
		if readErr != nil {
			verified <- readErr
			return
		}
		actual, trusted, ok := tracker.trustedAuditSource(adapter.InboundContext{Inbound: receiver.InboundTag, Source: M.SocksaddrFromNet(remote)})
		if !ok || !trusted || actual.String() != "2001:db8::20" {
			verified <- fmt.Errorf("trusted source = %s, %t, %t", actual, trusted, ok)
			return
		}
		_, writeErr := inner.WriteToUDP(buffer[:n], remote)
		verified <- writeErr
	}()

	client, err := net.Dial("udp", net.JoinHostPort(receiver.Listen, fmt.Sprint(receiver.ListenPort)))
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	var sessionID [8]byte
	copy(sessionID[:], "session1")
	frame := testUDPFrame(key, netip.MustParseAddrPort("[2001:db8::20]:54321"), []byte("hello"), sessionID, 1)
	if _, err := client.Write(frame); err != nil {
		t.Fatal(err)
	}
	_ = client.SetReadDeadline(time.Now().Add(3 * time.Second))
	reply := make([]byte, 5)
	if _, err := io.ReadFull(client, reply); err != nil || string(reply) != "hello" {
		t.Fatalf("reply = %q, err=%v", reply, err)
	}
	if err := <-verified; err != nil {
		t.Fatal(err)
	}
}

func TestTrustedForwardDoesNotAllocateAuditSourcesWhileDisabled(t *testing.T) {
	tracker := NewRateLimitTracker(RuntimeMetadata{TrustedForward: &RuntimeTrustedForward{Receivers: []RuntimeTrustedForwardReceiver{{InboundTag: "trusted-in"}}}})
	tracker.RegisterTrustedSource(&net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 1234}, netip.MustParseAddr("198.51.100.20"))
	if tracker.trustedSources != nil {
		t.Fatalf("disabled audit allocated trusted sources: %#v", tracker.trustedSources)
	}
}

func TestTrustedForwardRejectsWrongMACAndExpiredTimestamp(t *testing.T) {
	key := []byte("01234567890123456789012345678901")
	source := netip.MustParseAddrPort("198.51.100.20:54321")
	tcpFrame := testTCPFrame(key, source, []byte("hello"))
	tcpFrame[len(tcpFrame)-1] ^= 0xff
	if _, _, _, _, _, err := readTrustedForwardTCP(bytes.NewReader(tcpFrame), key); err == nil {
		t.Fatal("TCP frame with a forged MAC was accepted")
	}

	var sessionID [8]byte
	copy(sessionID[:], "session1")
	udpFrame := testUDPFrame(key, source, []byte("hello"), sessionID, 1)
	udpFrame[len(udpFrame)-1] ^= 0xff
	if _, _, _, _, _, _, err := readTrustedForwardUDP(udpFrame, key); err == nil {
		t.Fatal("UDP frame with a forged MAC was accepted")
	}

	receiver := trustedForwardReceiver{config: RuntimeTrustedForwardReceiver{MaxClockSkewSeconds: 120}}
	expired := time.Now().Add(-121 * time.Second).Unix()
	var nonce [16]byte
	nonce[15] = 2
	_, _, _, _, timestamp, err := readTrustedForwardTCP(bytes.NewReader(testTCPFrameAt(key, source, []byte("hello"), expired, nonce)), key)
	if err != nil {
		t.Fatal(err)
	}
	if receiver.validTimestamp(timestamp) {
		t.Fatal("expired TCP timestamp was accepted")
	}
	_, _, _, _, _, timestamp, err = readTrustedForwardUDP(testUDPFrameAt(key, source, []byte("hello"), sessionID, 1, expired), key)
	if err != nil {
		t.Fatal(err)
	}
	if receiver.validTimestamp(timestamp) {
		t.Fatal("expired UDP timestamp was accepted")
	}
}

func TestTrustedForwardRejectsTCPNonceReplay(t *testing.T) {
	receiver := trustedForwardReceiver{config: RuntimeTrustedForwardReceiver{MaxClockSkewSeconds: 120}}
	var nonce [16]byte
	copy(nonce[:], "replayed-nonce")
	if !receiver.acceptNonce(nonce) {
		t.Fatal("first TCP nonce was rejected")
	}
	if receiver.acceptNonce(nonce) {
		t.Fatal("replayed TCP nonce was accepted")
	}
}

func TestTrustedForwardRejectsUDPCounterReplay(t *testing.T) {
	target, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	defer target.Close()
	receiver := trustedForwardReceiver{
		config:  RuntimeTrustedForwardReceiver{Target: "127.0.0.1", TargetPort: target.LocalAddr().(*net.UDPAddr).Port},
		tracker: NewRateLimitTracker(RuntimeMetadata{}),
	}
	defer receiver.close()
	var sessionID [8]byte
	copy(sessionID[:], "session1")
	relay := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 32000}
	source := netip.MustParseAddrPort("198.51.100.20:54321")
	if _, err := receiver.udpSession(relay, source, sessionID, 1); err != nil {
		t.Fatal(err)
	}
	if _, err := receiver.udpSession(relay, source, sessionID, 1); err == nil {
		t.Fatal("replayed UDP counter was accepted")
	}
	if _, err := receiver.udpSession(relay, source, sessionID, 2); err != nil {
		t.Fatalf("next UDP counter was rejected: %v", err)
	}
}
