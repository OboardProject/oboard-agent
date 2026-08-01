package minibox

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"net/netip"
	"sync"
	"time"
)

const (
	trustedForwardVersion       = 1
	trustedForwardTCPData       = 1
	trustedForwardTCPProbe      = 2
	trustedForwardUDPData       = 1
	trustedForwardUDPProbe      = 2
	trustedForwardTCPFirstBytes = 4096
	trustedForwardTCPMACSize    = 16
	trustedForwardUDPMACSize    = 12
	trustedForwardMaxSessions   = 4096
)

var (
	trustedForwardTCPMagic = []byte{'O', 'B', 'T', 'F'}
	trustedForwardUDPMagic = []byte{'O', 'B', 'U'}
	trustedForwardProbeAck = []byte("OBTF-ACK-1")
)

type TrustedForwardManager struct {
	mu        sync.Mutex
	receivers []*trustedForwardReceiver
	closed    bool
}

type trustedForwardReceiver struct {
	config  RuntimeTrustedForwardReceiver
	key     []byte
	tracker *RateLimitTracker

	mu          sync.Mutex
	nonces      map[[16]byte]time.Time
	udpSessions map[string]*trustedForwardUDPSession
	tcpListener net.Listener
	udpConn     net.PacketConn
	closed      bool
}

type trustedForwardUDPSession struct {
	conn        *net.UDPConn
	relay       net.Addr
	source      netip.AddrPort
	sessionID   [8]byte
	lastCounter uint32
	lastSeen    time.Time
}

func StartTrustedForwardReceivers(ctx context.Context, trusted *RuntimeTrustedForward, tracker *RateLimitTracker) (*TrustedForwardManager, error) {
	manager := &TrustedForwardManager{}
	if trusted == nil || len(trusted.Receivers) == 0 {
		return manager, nil
	}
	for _, config := range trusted.Receivers {
		key, err := decodeTrustedForwardKey(config.Key)
		if err != nil {
			_ = manager.Close()
			return nil, fmt.Errorf("trusted forward receiver %q: %w", config.ID, err)
		}
		receiver := &trustedForwardReceiver{config: config, key: key, tracker: tracker}
		if config.Network == "tcp" || config.Network == "tcp_udp" {
			if err := receiver.startTCP(); err != nil {
				_ = manager.Close()
				return nil, fmt.Errorf("start trusted forward TCP receiver %q: %w", config.ID, err)
			}
		}
		if config.Network == "udp" || config.Network == "tcp_udp" {
			if err := receiver.startUDP(ctx); err != nil {
				receiver.close()
				_ = manager.Close()
				return nil, fmt.Errorf("start trusted forward UDP receiver %q: %w", config.ID, err)
			}
		}
		manager.receivers = append(manager.receivers, receiver)
	}
	go func() {
		<-ctx.Done()
		_ = manager.Close()
	}()
	return manager, nil
}

func (m *TrustedForwardManager) Close() error {
	if m == nil {
		return nil
	}
	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		return nil
	}
	m.closed = true
	receivers := append([]*trustedForwardReceiver(nil), m.receivers...)
	m.receivers = nil
	m.mu.Unlock()
	for _, receiver := range receivers {
		receiver.close()
	}
	return nil
}

func decodeTrustedForwardKey(encoded string) ([]byte, error) {
	key, err := base64.RawStdEncoding.DecodeString(encoded)
	if err != nil {
		key, err = base64.StdEncoding.DecodeString(encoded)
	}
	if err != nil || len(key) != sha256.Size {
		return nil, errors.New("key is invalid")
	}
	return key, nil
}

func (r *trustedForwardReceiver) startTCP() error {
	listener, err := net.Listen("tcp", net.JoinHostPort(r.config.Listen, fmt.Sprint(r.config.ListenPort)))
	if err != nil {
		return err
	}
	r.tcpListener = listener
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go r.handleTCP(conn)
		}
	}()
	return nil
}

func (r *trustedForwardReceiver) handleTCP(conn net.Conn) {
	defer conn.Close()
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	frameType, source, payload, nonce, timestamp, err := readTrustedForwardTCP(conn, r.key)
	_ = conn.SetReadDeadline(time.Time{})
	if err != nil || !r.validTimestamp(timestamp) || !r.acceptNonce(nonce) {
		return
	}
	if frameType == trustedForwardTCPProbe {
		_, _ = conn.Write(trustedForwardProbeAck)
		return
	}
	if frameType != trustedForwardTCPData || len(payload) == 0 {
		return
	}
	target, err := net.DialTimeout("tcp", net.JoinHostPort(r.config.Target, fmt.Sprint(r.config.TargetPort)), 5*time.Second)
	if err != nil {
		return
	}
	defer target.Close()
	r.tracker.RegisterTrustedSource(target.LocalAddr(), source.Addr())
	defer r.tracker.RemoveTrustedSource(target.LocalAddr())
	if err := writeTrustedForward(target, payload); err != nil {
		return
	}
	go func() {
		_ = r.copyTrustedTCP(target, conn, source.Addr())
		_ = target.Close()
	}()
	_, _ = io.Copy(conn, target)
}

func (r *trustedForwardReceiver) copyTrustedTCP(dst net.Conn, src net.Conn, source netip.Addr) error {
	buffer := make([]byte, 32*1024)
	for {
		n, err := src.Read(buffer)
		if n > 0 {
			r.tracker.RegisterTrustedSource(dst.LocalAddr(), source)
			if writeErr := writeTrustedForward(dst, buffer[:n]); writeErr != nil {
				return writeErr
			}
		}
		if err != nil {
			return err
		}
	}
}

func readTrustedForwardTCP(reader io.Reader, key []byte) (byte, netip.AddrPort, []byte, [16]byte, int64, error) {
	var nonce [16]byte
	fixed := make([]byte, 4+1+1+8+16+1)
	if _, err := io.ReadFull(reader, fixed); err != nil {
		return 0, netip.AddrPort{}, nil, nonce, 0, err
	}
	if !bytes.Equal(fixed[:4], trustedForwardTCPMagic) || fixed[4] != trustedForwardVersion {
		return 0, netip.AddrPort{}, nil, nonce, 0, errors.New("trusted forward TCP prefix is invalid")
	}
	frameType := fixed[5]
	rawTimestamp := binary.BigEndian.Uint64(fixed[6:14])
	if rawTimestamp > math.MaxInt64 {
		return 0, netip.AddrPort{}, nil, nonce, 0, errors.New("trusted forward TCP timestamp is invalid")
	}
	timestamp := int64(rawTimestamp)
	copy(nonce[:], fixed[14:30])
	addressSize := 0
	switch fixed[30] {
	case 4:
		addressSize = 4
	case 6:
		addressSize = 16
	default:
		return 0, netip.AddrPort{}, nil, nonce, 0, errors.New("trusted forward TCP address family is invalid")
	}
	rest := make([]byte, addressSize+2+2)
	if _, err := io.ReadFull(reader, rest); err != nil {
		return 0, netip.AddrPort{}, nil, nonce, 0, err
	}
	payloadSize := int(binary.BigEndian.Uint16(rest[addressSize+2:]))
	if payloadSize > trustedForwardTCPFirstBytes {
		return 0, netip.AddrPort{}, nil, nonce, 0, errors.New("trusted forward TCP payload is too large")
	}
	tail := make([]byte, payloadSize+trustedForwardTCPMACSize)
	if _, err := io.ReadFull(reader, tail); err != nil {
		return 0, netip.AddrPort{}, nil, nonce, 0, err
	}
	signed := append(append(append([]byte(nil), fixed...), rest...), tail[:payloadSize]...)
	if !validTrustedForwardMAC(signed, tail[payloadSize:], key) {
		return 0, netip.AddrPort{}, nil, nonce, 0, errors.New("trusted forward TCP authentication failed")
	}
	addr, ok := netip.AddrFromSlice(rest[:addressSize])
	if !ok {
		return 0, netip.AddrPort{}, nil, nonce, 0, errors.New("trusted forward TCP source is invalid")
	}
	port := binary.BigEndian.Uint16(rest[addressSize : addressSize+2])
	if port == 0 {
		return 0, netip.AddrPort{}, nil, nonce, 0, errors.New("trusted forward TCP source port is invalid")
	}
	return frameType, netip.AddrPortFrom(addr.Unmap(), port), tail[:payloadSize], nonce, timestamp, nil
}

func (r *trustedForwardReceiver) startUDP(ctx context.Context) error {
	conn, err := net.ListenPacket("udp", net.JoinHostPort(r.config.Listen, fmt.Sprint(r.config.ListenPort)))
	if err != nil {
		return err
	}
	r.udpConn = conn
	go r.loopUDP(conn)
	go r.cleanupUDPSessions(ctx)
	return nil
}

func (r *trustedForwardReceiver) loopUDP(conn net.PacketConn) {
	buffer := make([]byte, 64*1024)
	for {
		n, relay, err := conn.ReadFrom(buffer)
		if err != nil {
			return
		}
		frameType, source, sessionID, counter, payload, timestamp, err := readTrustedForwardUDP(buffer[:n], r.key)
		if err != nil || !r.validTimestamp(timestamp) {
			continue
		}
		if frameType == trustedForwardUDPProbe {
			_, _ = conn.WriteTo(trustedForwardProbeAck, relay)
			continue
		}
		if frameType != trustedForwardUDPData || len(payload) == 0 {
			continue
		}
		session, err := r.udpSession(relay, source, sessionID, counter)
		if err != nil {
			continue
		}
		r.tracker.RegisterTrustedSource(session.conn.LocalAddr(), source.Addr())
		_, _ = session.conn.Write(payload)
	}
}

func readTrustedForwardUDP(packet, key []byte) (byte, netip.AddrPort, [8]byte, uint32, []byte, int64, error) {
	var sessionID [8]byte
	minimum := 3 + 1 + 4 + 8 + 4 + 1 + 2 + trustedForwardUDPMACSize
	if len(packet) < minimum || !bytes.Equal(packet[:3], trustedForwardUDPMagic) {
		return 0, netip.AddrPort{}, sessionID, 0, nil, 0, errors.New("trusted forward UDP prefix is invalid")
	}
	versionType := packet[3]
	if versionType>>4 != trustedForwardVersion {
		return 0, netip.AddrPort{}, sessionID, 0, nil, 0, errors.New("trusted forward UDP version is invalid")
	}
	frameType := versionType & 0x0f
	timestamp := int64(binary.BigEndian.Uint32(packet[4:8]))
	copy(sessionID[:], packet[8:16])
	counter := binary.BigEndian.Uint32(packet[16:20])
	addressSize := 0
	switch packet[20] {
	case 4:
		addressSize = 4
	case 6:
		addressSize = 16
	default:
		return 0, netip.AddrPort{}, sessionID, 0, nil, 0, errors.New("trusted forward UDP address family is invalid")
	}
	headerEnd := 21 + addressSize + 2
	if len(packet) < headerEnd+trustedForwardUDPMACSize {
		return 0, netip.AddrPort{}, sessionID, 0, nil, 0, errors.New("trusted forward UDP packet is truncated")
	}
	macStart := len(packet) - trustedForwardUDPMACSize
	if !validTrustedForwardMAC(packet[:macStart], packet[macStart:], key) {
		return 0, netip.AddrPort{}, sessionID, 0, nil, 0, errors.New("trusted forward UDP authentication failed")
	}
	addr, ok := netip.AddrFromSlice(packet[21 : 21+addressSize])
	if !ok {
		return 0, netip.AddrPort{}, sessionID, 0, nil, 0, errors.New("trusted forward UDP source is invalid")
	}
	port := binary.BigEndian.Uint16(packet[21+addressSize : headerEnd])
	if port == 0 || counter == 0 {
		return 0, netip.AddrPort{}, sessionID, 0, nil, 0, errors.New("trusted forward UDP source or counter is invalid")
	}
	return frameType, netip.AddrPortFrom(addr.Unmap(), port), sessionID, counter, packet[headerEnd:macStart], timestamp, nil
}

func validTrustedForwardMAC(payload, received, key []byte) bool {
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write(payload)
	expected := mac.Sum(nil)
	return len(received) <= len(expected) && hmac.Equal(received, expected[:len(received)])
}

func (r *trustedForwardReceiver) validTimestamp(timestamp int64) bool {
	now := r.tracker.timeNow().Unix()
	delta := now - timestamp
	if delta < 0 {
		delta = -delta
	}
	return delta <= int64(r.config.MaxClockSkewSeconds)
}

func (r *trustedForwardReceiver) acceptNonce(nonce [16]byte) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	now := time.Now()
	if _, exists := r.nonces[nonce]; exists {
		return false
	}
	if r.nonces == nil {
		r.nonces = make(map[[16]byte]time.Time)
	}
	if len(r.nonces) >= trustedForwardMaxSessions {
		cutoff := now.Add(-time.Duration(r.config.MaxClockSkewSeconds) * time.Second)
		for key, seenAt := range r.nonces {
			if seenAt.Before(cutoff) {
				delete(r.nonces, key)
			}
		}
		if len(r.nonces) >= trustedForwardMaxSessions {
			return false
		}
	}
	r.nonces[nonce] = now
	return true
}

func (r *trustedForwardReceiver) udpSession(relay net.Addr, source netip.AddrPort, sessionID [8]byte, counter uint32) (*trustedForwardUDPSession, error) {
	key := relay.String() + "\x00" + string(sessionID[:])
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return nil, net.ErrClosed
	}
	if session := r.udpSessions[key]; session != nil {
		if session.source != source || counter <= session.lastCounter {
			return nil, errors.New("trusted forward UDP replay rejected")
		}
		session.lastCounter = counter
		session.lastSeen = time.Now()
		return session, nil
	}
	if r.udpSessions == nil {
		r.udpSessions = make(map[string]*trustedForwardUDPSession)
	}
	if len(r.udpSessions) >= trustedForwardMaxSessions {
		return nil, errors.New("trusted forward UDP session limit reached")
	}
	target, err := net.ResolveUDPAddr("udp", net.JoinHostPort(r.config.Target, fmt.Sprint(r.config.TargetPort)))
	if err != nil {
		return nil, err
	}
	conn, err := net.DialUDP("udp", nil, target)
	if err != nil {
		return nil, err
	}
	session := &trustedForwardUDPSession{conn: conn, relay: relay, source: source, sessionID: sessionID, lastCounter: counter, lastSeen: time.Now()}
	r.udpSessions[key] = session
	go r.loopUDPResponses(key, session)
	return session, nil
}

func (r *trustedForwardReceiver) loopUDPResponses(key string, session *trustedForwardUDPSession) {
	buffer := make([]byte, 64*1024)
	for {
		n, err := session.conn.Read(buffer)
		if err != nil {
			break
		}
		if r.udpConn != nil {
			_, _ = r.udpConn.WriteTo(buffer[:n], session.relay)
		}
		r.mu.Lock()
		if r.udpSessions[key] == session {
			session.lastSeen = time.Now()
		}
		r.mu.Unlock()
	}
	r.mu.Lock()
	if r.udpSessions[key] == session {
		delete(r.udpSessions, key)
	}
	r.mu.Unlock()
	r.tracker.RemoveTrustedSource(session.conn.LocalAddr())
	_ = session.conn.Close()
}

func (r *trustedForwardReceiver) cleanupUDPSessions(ctx context.Context) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-ticker.C:
			r.mu.Lock()
			for key, session := range r.udpSessions {
				if now.Sub(session.lastSeen) > 2*time.Minute {
					delete(r.udpSessions, key)
					r.tracker.RemoveTrustedSource(session.conn.LocalAddr())
					_ = session.conn.Close()
				}
			}
			r.mu.Unlock()
		}
	}
}

func (r *trustedForwardReceiver) close() {
	r.mu.Lock()
	if r.closed {
		r.mu.Unlock()
		return
	}
	r.closed = true
	tcpListener, udpConn := r.tcpListener, r.udpConn
	sessions := r.udpSessions
	r.udpSessions = nil
	r.mu.Unlock()
	if tcpListener != nil {
		_ = tcpListener.Close()
	}
	if udpConn != nil {
		_ = udpConn.Close()
	}
	for _, session := range sessions {
		r.tracker.RemoveTrustedSource(session.conn.LocalAddr())
		_ = session.conn.Close()
	}
}

func writeTrustedForward(writer io.Writer, payload []byte) error {
	for len(payload) > 0 {
		n, err := writer.Write(payload)
		if err != nil {
			return err
		}
		if n <= 0 {
			return io.ErrShortWrite
		}
		payload = payload[n:]
	}
	return nil
}
