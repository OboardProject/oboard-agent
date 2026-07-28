package agent

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/OboardProject/oboard-agent/internal/model"
)

func testTrustedSender() *model.TrustedForwardSender {
	return &model.TrustedForwardSender{
		Version: 1, ReceiverID: "receiver-1",
		Key:                 base64.RawStdEncoding.EncodeToString([]byte("01234567890123456789012345678901")),
		MaxClockSkewSeconds: 120,
	}
}

func TestTrustedForwardEncodingBindsSourceAndPayload(t *testing.T) {
	sender := testTrustedSender()
	source := netip.MustParseAddrPort("198.51.100.20:54321")
	tcpFrame, err := encodeTrustedForwardTCP(sender, source, []byte("hello"), trustedForwardTCPData)
	if err != nil {
		t.Fatal(err)
	}
	if string(tcpFrame[:4]) != "OBTF" || tcpFrame[4] != 1 || tcpFrame[5] != trustedForwardTCPData {
		t.Fatalf("TCP frame prefix = %x", tcpFrame[:6])
	}
	key, _ := trustedForwardKey(sender)
	tcpPayload := tcpFrame[:len(tcpFrame)-trustedForwardTCPMACSize]
	tcpMAC := hmac.New(sha256.New, key)
	_, _ = tcpMAC.Write(tcpPayload)
	if !hmac.Equal(tcpFrame[len(tcpPayload):], tcpMAC.Sum(nil)[:trustedForwardTCPMACSize]) {
		t.Fatal("TCP frame MAC does not cover the encoded frame")
	}

	var sessionID [8]byte
	copy(sessionID[:], "session1")
	udpFrame, err := encodeTrustedForwardUDP(sender, source, sessionID, 7, []byte("packet"), trustedForwardUDPData)
	if err != nil {
		t.Fatal(err)
	}
	if string(udpFrame[:3]) != "OBU" || udpFrame[3]>>4 != 1 || binary.BigEndian.Uint32(udpFrame[16:20]) != 7 {
		t.Fatalf("UDP frame prefix = %x", udpFrame[:20])
	}
	udpPayload := udpFrame[:len(udpFrame)-trustedForwardUDPMACSize]
	udpMAC := hmac.New(sha256.New, key)
	_, _ = udpMAC.Write(udpPayload)
	if !hmac.Equal(udpFrame[len(udpPayload):], udpMAC.Sum(nil)[:trustedForwardUDPMACSize]) {
		t.Fatal("UDP frame MAC does not cover the encoded frame")
	}
}

func TestTrustedForwardForcesBuiltinBackendAndRejectsBadKey(t *testing.T) {
	rule := model.PortForward{ID: 1, Name: "trusted", Protocol: model.ForwardProtocolUDP, Backend: model.ForwardBackendRealm, TrustedForward: testTrustedSender()}
	resolved, err := resolveForwardBackends([]model.PortForward{rule}, map[string]bool{"realm": true, "builtin": true})
	if err != nil {
		t.Fatal(err)
	}
	if len(resolved) != 1 || resolved[0].ResolvedBackend != model.ForwardBackendBuiltin {
		t.Fatalf("trusted backend = %#v", resolved)
	}
	rule.TrustedForward.Key = "invalid"
	if _, err := resolveForwardBackends([]model.PortForward{rule}, map[string]bool{"builtin": true}); err == nil {
		t.Fatal("invalid trusted key was accepted")
	}
}

func TestTrustedForwardProbeUsesAuthenticatedTCPAndUDPFrames(t *testing.T) {
	sender := testTrustedSender()
	key, err := trustedForwardKey(sender)
	if err != nil {
		t.Fatal(err)
	}
	tcpListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer tcpListener.Close()
	port := tcpListener.Addr().(*net.TCPAddr).Port
	udpListener, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: port})
	if err != nil {
		t.Fatal(err)
	}
	defer udpListener.Close()

	verified := make(chan error, 2)
	go func() {
		conn, acceptErr := tcpListener.Accept()
		if acceptErr != nil {
			verified <- acceptErr
			return
		}
		defer conn.Close()
		frame, readErr := readTestTrustedTCPFrame(conn)
		if readErr == nil {
			readErr = verifyTestTrustedFrame(frame, key, trustedForwardTCPMACSize)
		}
		if readErr == nil && (len(frame) < 6 || frame[5] != trustedForwardTCPProbe) {
			readErr = errors.New("TCP probe frame type is invalid")
		}
		if readErr == nil {
			_, readErr = conn.Write(trustedForwardProbeAck)
		}
		verified <- readErr
	}()
	go func() {
		packet := make([]byte, 512)
		n, remote, readErr := udpListener.ReadFromUDP(packet)
		if readErr == nil {
			packet = packet[:n]
			readErr = verifyTestTrustedFrame(packet, key, trustedForwardUDPMACSize)
		}
		if readErr == nil && (len(packet) < 4 || packet[3]&0x0f != trustedForwardUDPProbe) {
			readErr = errors.New("UDP probe frame type is invalid")
		}
		if readErr == nil {
			_, readErr = udpListener.WriteToUDP(trustedForwardProbeAck, remote)
		}
		verified <- readErr
	}()

	result := probeTrustedForward(model.PortForward{
		ID: 1, Protocol: model.ForwardProtocolTCPUDP, TargetAddress: "127.0.0.1", TargetPort: port, TrustedForward: sender,
	}, "manual")
	if !result.Available || result.Error != "" {
		t.Fatalf("trusted probe failed: %#v", result)
	}
	for range 2 {
		if err := <-verified; err != nil {
			t.Fatal(err)
		}
	}
}

func TestBuiltinTrustedForwardTCP(t *testing.T) {
	sender := testTrustedSender()
	key, err := trustedForwardKey(sender)
	if err != nil {
		t.Fatal(err)
	}
	target, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer target.Close()
	forwardPort := testFreeForwardPort(t, "tcp")
	stop, err := (&Runner{}).startBuiltinTCPForward(forwardRule{PortForward: model.PortForward{
		ID: 1, ListenIP: "127.0.0.1", ListenPort: forwardPort, TargetAddress: "127.0.0.1", TargetPort: target.Addr().(*net.TCPAddr).Port,
		Protocol: model.ForwardProtocolTCP, TrustedForward: sender,
	}})
	if err != nil {
		t.Fatal(err)
	}
	defer stop()

	verified := make(chan error, 1)
	go func() {
		conn, acceptErr := target.Accept()
		if acceptErr != nil {
			verified <- acceptErr
			return
		}
		defer conn.Close()
		frame, readErr := readTestTrustedTCPFrame(conn)
		if readErr == nil {
			readErr = verifyTestTrustedFrame(frame, key, trustedForwardTCPMACSize)
		}
		var source netip.AddrPort
		var payload []byte
		if readErr == nil {
			source, payload, readErr = parseTestTrustedTCPData(frame)
		}
		if readErr == nil && (!source.Addr().IsLoopback() || string(payload) != "hello") {
			readErr = errors.New("TCP trusted source or payload is invalid")
		}
		if readErr == nil {
			_, readErr = conn.Write([]byte("world"))
		}
		verified <- readErr
	}()

	client, err := net.Dial("tcp", net.JoinHostPort("127.0.0.1", fmt.Sprint(forwardPort)))
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	_ = client.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err := client.Write([]byte("hello")); err != nil {
		t.Fatal(err)
	}
	reply := make([]byte, 5)
	if _, err := io.ReadFull(client, reply); err != nil || string(reply) != "world" {
		t.Fatalf("TCP reply = %q, err=%v", reply, err)
	}
	if err := <-verified; err != nil {
		t.Fatal(err)
	}
}

func TestBuiltinTrustedForwardUDP(t *testing.T) {
	sender := testTrustedSender()
	key, err := trustedForwardKey(sender)
	if err != nil {
		t.Fatal(err)
	}
	target, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	defer target.Close()
	forwardPort := testFreeForwardPort(t, "udp")
	stop, err := (&Runner{}).startBuiltinUDPForward(forwardRule{PortForward: model.PortForward{
		ID: 2, ListenIP: "127.0.0.1", ListenPort: forwardPort, TargetAddress: "127.0.0.1", TargetPort: target.LocalAddr().(*net.UDPAddr).Port,
		Protocol: model.ForwardProtocolUDP, TrustedForward: sender,
	}})
	if err != nil {
		t.Fatal(err)
	}
	defer stop()

	verified := make(chan error, 1)
	go func() {
		packet := make([]byte, 512)
		n, remote, readErr := target.ReadFromUDP(packet)
		packet = packet[:n]
		if readErr == nil {
			readErr = verifyTestTrustedFrame(packet, key, trustedForwardUDPMACSize)
		}
		var source netip.AddrPort
		var payload []byte
		if readErr == nil {
			source, payload, readErr = parseTestTrustedUDPData(packet)
		}
		if readErr == nil && (!source.Addr().IsLoopback() || string(payload) != "hello") {
			readErr = errors.New("UDP trusted source or payload is invalid")
		}
		if readErr == nil {
			_, readErr = target.WriteToUDP([]byte("world"), remote)
		}
		verified <- readErr
	}()

	client, err := net.Dial("udp", net.JoinHostPort("127.0.0.1", fmt.Sprint(forwardPort)))
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	_ = client.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err := client.Write([]byte("hello")); err != nil {
		t.Fatal(err)
	}
	reply := make([]byte, 5)
	if _, err := io.ReadFull(client, reply); err != nil || string(reply) != "world" {
		t.Fatalf("UDP reply = %q, err=%v", reply, err)
	}
	if err := <-verified; err != nil {
		t.Fatal(err)
	}
}

func testFreeForwardPort(t *testing.T, network string) int {
	t.Helper()
	if network == "tcp" {
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer listener.Close()
		return listener.Addr().(*net.TCPAddr).Port
	}
	listener, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	return listener.LocalAddr().(*net.UDPAddr).Port
}

func readTestTrustedTCPFrame(reader io.Reader) ([]byte, error) {
	fixed := make([]byte, 4+1+1+8+16+1)
	if _, err := io.ReadFull(reader, fixed); err != nil {
		return nil, err
	}
	addressSize := 0
	switch fixed[len(fixed)-1] {
	case 4:
		addressSize = 4
	case 6:
		addressSize = 16
	default:
		return nil, errors.New("TCP probe address family is invalid")
	}
	rest := make([]byte, addressSize+2+2)
	if _, err := io.ReadFull(reader, rest); err != nil {
		return nil, err
	}
	payloadSize := int(binary.BigEndian.Uint16(rest[len(rest)-2:]))
	tail := make([]byte, payloadSize+trustedForwardTCPMACSize)
	if _, err := io.ReadFull(reader, tail); err != nil {
		return nil, err
	}
	return append(append(fixed, rest...), tail...), nil
}

func verifyTestTrustedFrame(frame, key []byte, macSize int) error {
	if len(frame) <= macSize {
		return io.ErrUnexpectedEOF
	}
	payload := frame[:len(frame)-macSize]
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write(payload)
	if !hmac.Equal(frame[len(payload):], mac.Sum(nil)[:macSize]) {
		return errors.New("trusted probe MAC is invalid")
	}
	if len(frame) >= 8 {
		var timestamp int64
		if bytes.Equal(frame[:4], trustedForwardTCPMagic) {
			timestamp = int64(binary.BigEndian.Uint64(frame[6:14]))
		} else {
			timestamp = int64(binary.BigEndian.Uint32(frame[4:8]))
		}
		if delta := time.Now().Unix() - timestamp; delta < -2 || delta > 2 {
			return errors.New("trusted probe timestamp is outside the test window")
		}
	}
	return nil
}

func parseTestTrustedTCPData(frame []byte) (netip.AddrPort, []byte, error) {
	if len(frame) < 31+2+2+trustedForwardTCPMACSize || frame[5] != trustedForwardTCPData {
		return netip.AddrPort{}, nil, errors.New("TCP trusted data frame is truncated")
	}
	addressSize := 4
	if frame[30] == 6 {
		addressSize = 16
	} else if frame[30] != 4 {
		return netip.AddrPort{}, nil, errors.New("TCP trusted data address family is invalid")
	}
	addressStart := 31
	headerEnd := addressStart + addressSize + 2 + 2
	address, ok := netip.AddrFromSlice(frame[addressStart : addressStart+addressSize])
	if !ok || len(frame) < headerEnd+trustedForwardTCPMACSize {
		return netip.AddrPort{}, nil, errors.New("TCP trusted data source is invalid")
	}
	port := binary.BigEndian.Uint16(frame[addressStart+addressSize : addressStart+addressSize+2])
	payloadSize := int(binary.BigEndian.Uint16(frame[headerEnd-2 : headerEnd]))
	if len(frame) != headerEnd+payloadSize+trustedForwardTCPMACSize {
		return netip.AddrPort{}, nil, errors.New("TCP trusted data payload length is invalid")
	}
	return netip.AddrPortFrom(address.Unmap(), port), frame[headerEnd : headerEnd+payloadSize], nil
}

func parseTestTrustedUDPData(frame []byte) (netip.AddrPort, []byte, error) {
	if len(frame) < 21+2+trustedForwardUDPMACSize || frame[3]&0x0f != trustedForwardUDPData {
		return netip.AddrPort{}, nil, errors.New("UDP trusted data frame is truncated")
	}
	addressSize := 4
	if frame[20] == 6 {
		addressSize = 16
	} else if frame[20] != 4 {
		return netip.AddrPort{}, nil, errors.New("UDP trusted data address family is invalid")
	}
	addressStart := 21
	headerEnd := addressStart + addressSize + 2
	address, ok := netip.AddrFromSlice(frame[addressStart : addressStart+addressSize])
	if !ok || len(frame) < headerEnd+trustedForwardUDPMACSize {
		return netip.AddrPort{}, nil, errors.New("UDP trusted data source is invalid")
	}
	port := binary.BigEndian.Uint16(frame[addressStart+addressSize : headerEnd])
	payloadEnd := len(frame) - trustedForwardUDPMACSize
	return netip.AddrPortFrom(address.Unmap(), port), frame[headerEnd:payloadEnd], nil
}
