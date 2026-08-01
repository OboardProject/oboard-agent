package agent

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"net/netip"
	"strconv"
	"time"

	"github.com/OboardProject/oboard-agent/internal/model"
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
)

var (
	trustedForwardTCPMagic = []byte{'O', 'B', 'T', 'F'}
	trustedForwardUDPMagic = []byte{'O', 'B', 'U'}
	trustedForwardProbeAck = []byte("OBTF-ACK-1")
)

func trustedForwardKey(sender *model.TrustedForwardSender) ([]byte, error) {
	if sender == nil || sender.Version != trustedForwardVersion || sender.ReceiverID == "" {
		return nil, errors.New("trusted forward sender configuration is invalid")
	}
	key, err := base64.RawStdEncoding.DecodeString(sender.Key)
	if err != nil {
		key, err = base64.StdEncoding.DecodeString(sender.Key)
	}
	if err != nil || len(key) != sha256.Size {
		return nil, errors.New("trusted forward key is invalid")
	}
	return key, nil
}

func trustedForwardSource(address net.Addr) (netip.AddrPort, error) {
	if address == nil {
		return netip.AddrPort{}, errors.New("trusted forward source address is missing")
	}
	host, portText, err := net.SplitHostPort(address.String())
	if err != nil {
		return netip.AddrPort{}, err
	}
	addr, err := netip.ParseAddr(host)
	if err != nil {
		return netip.AddrPort{}, err
	}
	port, err := strconv.Atoi(portText)
	if err != nil || port < 1 || port > 65535 {
		return netip.AddrPort{}, errors.New("trusted forward source port is invalid")
	}
	return netip.AddrPortFrom(addr.Unmap(), uint16(port)), nil
}

func appendTrustedForwardAddress(dst []byte, source netip.AddrPort) ([]byte, error) {
	addr := source.Addr().Unmap()
	if !addr.IsValid() || addr.IsUnspecified() || addr.IsMulticast() {
		return nil, errors.New("trusted forward source IP is invalid")
	}
	if addr.Is4() {
		dst = append(dst, 4)
		raw := addr.As4()
		dst = append(dst, raw[:]...)
	} else {
		dst = append(dst, 6)
		raw := addr.As16()
		dst = append(dst, raw[:]...)
	}
	var port [2]byte
	binary.BigEndian.PutUint16(port[:], source.Port())
	return append(dst, port[:]...), nil
}

func appendTrustedForwardMAC(frame, key []byte, size int) []byte {
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write(frame)
	return append(frame, mac.Sum(nil)[:size]...)
}

func encodeTrustedForwardTCP(sender *model.TrustedForwardSender, source netip.AddrPort, payload []byte, frameType byte) ([]byte, error) {
	return encodeTrustedForwardTCPAt(sender, source, payload, frameType, time.Now())
}

func encodeTrustedForwardTCPAt(sender *model.TrustedForwardSender, source netip.AddrPort, payload []byte, frameType byte, now time.Time) ([]byte, error) {
	key, err := trustedForwardKey(sender)
	if err != nil {
		return nil, err
	}
	if len(payload) > trustedForwardTCPFirstBytes || len(payload) > math.MaxUint16 {
		return nil, errors.New("trusted forward TCP preface payload is too large")
	}
	unixSeconds := now.Unix()
	if unixSeconds < 0 {
		return nil, errors.New("trusted forward TCP timestamp is invalid")
	}
	frame := make([]byte, 0, 64+len(payload))
	frame = append(frame, trustedForwardTCPMagic...)
	frame = append(frame, trustedForwardVersion, frameType)
	var timestamp [8]byte
	binary.BigEndian.PutUint64(timestamp[:], uint64(unixSeconds))
	frame = append(frame, timestamp[:]...)
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return nil, err
	}
	frame = append(frame, nonce[:]...)
	frame, err = appendTrustedForwardAddress(frame, source)
	if err != nil {
		return nil, err
	}
	var size [2]byte
	var payloadSize uint16
	for range payload {
		payloadSize++
	}
	binary.BigEndian.PutUint16(size[:], payloadSize)
	frame = append(frame, size[:]...)
	frame = append(frame, payload...)
	return appendTrustedForwardMAC(frame, key, trustedForwardTCPMACSize), nil
}

func encodeTrustedForwardUDP(sender *model.TrustedForwardSender, source netip.AddrPort, sessionID [8]byte, counter uint32, payload []byte, frameType byte) ([]byte, error) {
	return encodeTrustedForwardUDPAt(sender, source, sessionID, counter, payload, frameType, time.Now())
}

func encodeTrustedForwardUDPAt(sender *model.TrustedForwardSender, source netip.AddrPort, sessionID [8]byte, counter uint32, payload []byte, frameType byte, now time.Time) ([]byte, error) {
	key, err := trustedForwardKey(sender)
	if err != nil {
		return nil, err
	}
	unixSeconds := now.Unix()
	if unixSeconds < 0 || unixSeconds > math.MaxUint32 {
		return nil, errors.New("trusted forward UDP timestamp is invalid")
	}
	frame := make([]byte, 0, 48+len(payload))
	frame = append(frame, trustedForwardUDPMagic...)
	frame = append(frame, trustedForwardVersion<<4|frameType)
	var timestamp [4]byte
	binary.BigEndian.PutUint32(timestamp[:], uint32(unixSeconds))
	frame = append(frame, timestamp[:]...)
	frame = append(frame, sessionID[:]...)
	var sequence [4]byte
	binary.BigEndian.PutUint32(sequence[:], counter)
	frame = append(frame, sequence[:]...)
	frame, err = appendTrustedForwardAddress(frame, source)
	if err != nil {
		return nil, err
	}
	frame = append(frame, payload...)
	return appendTrustedForwardMAC(frame, key, trustedForwardUDPMACSize), nil
}

func writeTrustedForward(w io.Writer, payload []byte) error {
	for len(payload) > 0 {
		n, err := w.Write(payload)
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

func probeTrustedForward(rule model.PortForward, mode string) model.PortForwardProbeResult {
	return probeTrustedForwardAt(rule, mode, time.Now)
}

func probeTrustedForwardAt(rule model.PortForward, mode string, now func() time.Time) model.PortForwardProbeResult {
	result := model.PortForwardProbeResult{PortForwardID: rule.ID, Mode: mode, SampleCount: 1, ResultJSON: "{}"}
	target := net.JoinHostPort(rule.TargetAddress, fmt.Sprint(rule.TargetPort))
	started := time.Now()
	var checks []string
	probeTCP := rule.Protocol == model.ForwardProtocolTCP || rule.Protocol == model.ForwardProtocolTCPUDP
	probeUDP := rule.Protocol == model.ForwardProtocolUDP || rule.Protocol == model.ForwardProtocolTCPUDP
	if probeTCP {
		conn, err := net.DialTimeout("tcp", target, 5*time.Second)
		if err == nil {
			_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
			var source netip.AddrPort
			source, err = trustedForwardSource(conn.LocalAddr())
			if err == nil {
				var frame []byte
				frame, err = encodeTrustedForwardTCPAt(rule.TrustedForward, source, nil, trustedForwardTCPProbe, now())
				if err == nil {
					err = writeTrustedForward(conn, frame)
				}
			}
			if err == nil {
				ack := make([]byte, len(trustedForwardProbeAck))
				_, err = io.ReadFull(conn, ack)
				if err == nil && !bytes.Equal(ack, trustedForwardProbeAck) {
					err = errors.New("trusted forward TCP probe acknowledgement is invalid")
				}
			}
			_ = conn.Close()
		}
		if err != nil {
			result.Error = err.Error()
			result.ResultJSON = marshalProbeDetails(map[string]any{"kind": "trusted_forward", "target": target, "tcp": false})
			return result
		}
		checks = append(checks, "tcp")
	}
	if probeUDP {
		conn, err := net.DialTimeout("udp", target, 5*time.Second)
		if err == nil {
			_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
			var source netip.AddrPort
			source, err = trustedForwardSource(conn.LocalAddr())
			if err == nil {
				var sessionID [8]byte
				_, err = rand.Read(sessionID[:])
				if err == nil {
					var frame []byte
					frame, err = encodeTrustedForwardUDPAt(rule.TrustedForward, source, sessionID, 1, nil, trustedForwardUDPProbe, now())
					if err == nil {
						err = writeTrustedForward(conn, frame)
					}
				}
			}
			if err == nil {
				ack := make([]byte, len(trustedForwardProbeAck))
				_, err = io.ReadFull(conn, ack)
				if err == nil && !bytes.Equal(ack, trustedForwardProbeAck) {
					err = errors.New("trusted forward UDP probe acknowledgement is invalid")
				}
			}
			_ = conn.Close()
		}
		if err != nil {
			result.Error = err.Error()
			result.ResultJSON = marshalProbeDetails(map[string]any{"kind": "trusted_forward", "target": target, "udp": false})
			return result
		}
		checks = append(checks, "udp")
	}
	result.Available = true
	result.LatencyMS = time.Since(started).Milliseconds()
	result.ResultJSON = marshalProbeDetails(map[string]any{"kind": "trusted_forward", "target": target, "networks": checks, "authenticated": true})
	return result
}
