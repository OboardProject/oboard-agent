package agent

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strings"
	"sync"
	"time"
)

const (
	badVPNUDPGatewayPort        = uint32(7300)
	badVPNMaxFrameSize          = 65535
	badVPNMaxAssociations       = 256
	badVPNFlagKeepalive   uint8 = 1 << 0
	badVPNFlagRebind      uint8 = 1 << 1
	badVPNFlagDNS         uint8 = 1 << 2
	badVPNFlagIPv6        uint8 = 1 << 3
)

type badVPNGatewayStream interface {
	io.Reader
	io.Writer
	io.Closer
}

type badVPNPacketConn interface {
	Read([]byte) (int, error)
	Write([]byte) (int, error)
	Close() error
}

type badVPNDialFunc func(context.Context, netip.AddrPort) (badVPNPacketConn, error)

type badVPNFrame struct {
	flags       uint8
	connection  uint16
	destination netip.AddrPort
	payload     []byte
}

type badVPNGateway struct {
	stream          badVPNGatewayStream
	counter         *sshInboundCounter
	audit           *connectionAuditAccumulator
	userID          int64
	inboundID       int64
	pathID          int64
	deviceIDHash    string
	credentialEpoch int64
	outboundTag     string
	sourceIP        string
	dial            badVPNDialFunc

	mu           sync.Mutex
	writeMu      sync.Mutex
	associations map[uint16]*badVPNAssociation
	wg           sync.WaitGroup
}

type badVPNAssociation struct {
	gateway      *badVPNGateway
	connection   uint16
	destination  netip.AddrPort
	conn         badVPNPacketConn
	lastUsed     time.Time
	auditSession *connectionAuditSession
	closeOnce    sync.Once
}

func isBadVPNUDPGatewayDestination(host string, port uint32) bool {
	host = strings.TrimSpace(host)
	return port == badVPNUDPGatewayPort && (host == "127.0.0.1" || host == "::1")
}

func serveBadVPNUDPGateway(stream badVPNGatewayStream, counter *sshInboundCounter, audit *connectionAuditAccumulator, userID, inboundID, pathID int64, deviceIDHash string, credentialEpoch int64, outboundTag, sourceIP string, dial badVPNDialFunc) {
	gateway := &badVPNGateway{
		stream:          stream,
		counter:         counter,
		audit:           audit,
		userID:          userID,
		inboundID:       inboundID,
		pathID:          pathID,
		deviceIDHash:    deviceIDHash,
		credentialEpoch: credentialEpoch,
		outboundTag:     outboundTag,
		sourceIP:        sourceIP,
		dial:            dial,
		associations:    make(map[uint16]*badVPNAssociation),
	}
	gateway.serve()
}

func (g *badVPNGateway) serve() {
	defer g.close()
	for {
		if !g.counter.allowTransfer() {
			return
		}
		frame, err := readBadVPNFrame(g.stream)
		if err != nil {
			return
		}
		if frame.flags&badVPNFlagKeepalive != 0 {
			continue
		}
		if !isPermittedSSHDestination(frame.destination.Addr()) {
			continue
		}
		association, err := g.association(frame)
		if err != nil {
			continue
		}
		written, err := association.conn.Write(frame.payload)
		g.counter.addTraffic(true, int64(written))
		association.auditSession.addTraffic(true, int64(written))
		if err != nil || written != len(frame.payload) {
			g.removeAssociation(association)
		}
	}
}

func (g *badVPNGateway) association(frame badVPNFrame) (*badVPNAssociation, error) {
	g.mu.Lock()
	existing := g.associations[frame.connection]
	if existing != nil && frame.flags&badVPNFlagRebind == 0 && existing.destination == frame.destination {
		existing.lastUsed = time.Now()
		g.mu.Unlock()
		return existing, nil
	}
	if existing != nil {
		delete(g.associations, frame.connection)
	}
	g.mu.Unlock()
	if existing != nil {
		existing.close()
	}
	if !g.counter.allowNewConnection() {
		return nil, errors.New("user traffic quota is exhausted")
	}

	conn, err := g.dial(context.Background(), frame.destination)
	if err != nil {
		return nil, err
	}
	association := &badVPNAssociation{
		gateway:     g,
		connection:  frame.connection,
		destination: frame.destination,
		conn:        conn,
		lastUsed:    time.Now(),
		auditSession: g.audit.startSession(connectionAuditSnapshotItem{
			UserID:          g.userID,
			InboundID:       g.inboundID,
			PathID:          g.pathID,
			DeviceIDHash:    g.deviceIDHash,
			CredentialEpoch: g.credentialEpoch,
			SourceIP:        g.sourceIP,
			Network:         "udp",
			Destination:     frame.destination.Addr().String(),
			DestinationPort: int(frame.destination.Port()),
			OutboundTag:     g.outboundTag,
			OutboundType:    map[bool]string{true: "direct", false: "outbound"}[g.outboundTag == "direct"],
		}),
	}

	g.mu.Lock()
	if len(g.associations) >= badVPNMaxAssociations {
		oldest := g.oldestAssociationLocked()
		if oldest != nil {
			delete(g.associations, oldest.connection)
			defer oldest.close()
		}
	}
	g.associations[association.connection] = association
	g.wg.Add(1)
	g.mu.Unlock()
	go association.readReplies()
	return association, nil
}

func (g *badVPNGateway) oldestAssociationLocked() *badVPNAssociation {
	var oldest *badVPNAssociation
	for _, association := range g.associations {
		if oldest == nil || association.lastUsed.Before(oldest.lastUsed) {
			oldest = association
		}
	}
	return oldest
}

func (g *badVPNGateway) removeAssociation(association *badVPNAssociation) {
	g.mu.Lock()
	if g.associations[association.connection] == association {
		delete(g.associations, association.connection)
	}
	g.mu.Unlock()
	association.close()
}

func (g *badVPNGateway) writeReply(association *badVPNAssociation, payload []byte) error {
	if !g.counter.allowTransfer() {
		return errors.New("user traffic quota is exhausted")
	}
	packet, err := marshalBadVPNFrame(badVPNFrame{connection: association.connection, destination: association.destination, payload: payload})
	if err != nil {
		return err
	}
	g.writeMu.Lock()
	err = writeAll(g.stream, packet)
	g.writeMu.Unlock()
	if err == nil {
		g.counter.addTraffic(false, int64(len(payload)))
		association.auditSession.addTraffic(false, int64(len(payload)))
	}
	return err
}

func (g *badVPNGateway) close() {
	_ = g.stream.Close()
	g.mu.Lock()
	associations := make([]*badVPNAssociation, 0, len(g.associations))
	for _, association := range g.associations {
		associations = append(associations, association)
	}
	g.associations = make(map[uint16]*badVPNAssociation)
	g.mu.Unlock()
	for _, association := range associations {
		association.close()
	}
	g.wg.Wait()
}

func (a *badVPNAssociation) readReplies() {
	defer a.gateway.wg.Done()
	defer a.gateway.removeAssociation(a)
	buffer := make([]byte, badVPNMaxFrameSize)
	for {
		n, err := a.conn.Read(buffer)
		if err != nil {
			return
		}
		if err := a.gateway.writeReply(a, buffer[:n]); err != nil {
			return
		}
	}
}

func (a *badVPNAssociation) close() {
	a.closeOnce.Do(func() {
		_ = a.conn.Close()
		a.auditSession.finish()
	})
}

func dialBadVPNPacketConn(ctx context.Context, destination netip.AddrPort) (badVPNPacketConn, error) {
	network := "udp4"
	if destination.Addr().Is6() {
		network = "udp6"
	}
	dialer := net.Dialer{Timeout: 10 * time.Second}
	return dialer.DialContext(ctx, network, destination.String())
}

func readBadVPNFrame(reader io.Reader) (badVPNFrame, error) {
	var sizeBytes [2]byte
	if _, err := io.ReadFull(reader, sizeBytes[:]); err != nil {
		return badVPNFrame{}, err
	}
	size := int(binary.LittleEndian.Uint16(sizeBytes[:]))
	if size < 3 || size > badVPNMaxFrameSize {
		return badVPNFrame{}, errors.New("invalid BadVPN frame size")
	}
	packet := make([]byte, size)
	if _, err := io.ReadFull(reader, packet); err != nil {
		return badVPNFrame{}, err
	}
	frame := badVPNFrame{flags: packet[0], connection: binary.LittleEndian.Uint16(packet[1:3])}
	if frame.flags&badVPNFlagKeepalive != 0 {
		return frame, nil
	}
	addressSize := 4
	if frame.flags&badVPNFlagIPv6 != 0 {
		addressSize = 16
	}
	if len(packet) < 3+addressSize+2 {
		return badVPNFrame{}, errors.New("BadVPN frame is missing its destination")
	}
	addressBytes := packet[3 : 3+addressSize]
	var address netip.Addr
	if addressSize == 4 {
		address = netip.AddrFrom4([4]byte(addressBytes))
	} else {
		address = netip.AddrFrom16([16]byte(addressBytes))
	}
	portOffset := 3 + addressSize
	port := binary.BigEndian.Uint16(packet[portOffset : portOffset+2])
	if port == 0 {
		return badVPNFrame{}, errors.New("BadVPN frame has an invalid destination port")
	}
	frame.destination = netip.AddrPortFrom(address.Unmap(), port)
	frame.payload = packet[portOffset+2:]
	return frame, nil
}

func marshalBadVPNFrame(frame badVPNFrame) ([]byte, error) {
	if !frame.destination.IsValid() || frame.destination.Port() == 0 {
		return nil, errors.New("BadVPN frame has an invalid destination")
	}
	address := frame.destination.Addr().Unmap()
	addressSize := 4
	flags := frame.flags &^ badVPNFlagIPv6
	if address.Is6() {
		addressSize = 16
		flags |= badVPNFlagIPv6
	}
	payloadSize := 3 + addressSize + 2 + len(frame.payload)
	if payloadSize > badVPNMaxFrameSize {
		return nil, fmt.Errorf("BadVPN frame payload is too large: %d", len(frame.payload))
	}
	packet := make([]byte, 2+payloadSize)
	binary.LittleEndian.PutUint16(packet[:2], uint16(payloadSize))
	packet[2] = flags
	binary.LittleEndian.PutUint16(packet[3:5], frame.connection)
	if addressSize == 4 {
		addressBytes := address.As4()
		copy(packet[5:9], addressBytes[:])
	} else {
		addressBytes := address.As16()
		copy(packet[5:21], addressBytes[:])
	}
	portOffset := 5 + addressSize
	binary.BigEndian.PutUint16(packet[portOffset:portOffset+2], frame.destination.Port())
	copy(packet[portOffset+2:], frame.payload)
	return packet, nil
}

func writeAll(writer io.Writer, data []byte) error {
	for len(data) > 0 {
		written, err := writer.Write(data)
		if err != nil {
			return err
		}
		if written <= 0 {
			return io.ErrShortWrite
		}
		data = data[written:]
	}
	return nil
}
