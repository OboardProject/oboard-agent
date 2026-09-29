package netdiag

import (
	"encoding/binary"
	"net/netip"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

const (
	protocolICMP   = 1
	protocolTCP    = 6
	protocolUDP    = 17
	protocolICMPv6 = 58
)

type replyKind int

const (
	replyEcho replyKind = iota + 1
	replyTimeExceeded
	replyUnreachable
)

// reply is one parsed ICMP message relevant to ping or trace. For errors
// (time exceeded, unreachable) the fields describe the embedded original
// packet so a reply can be matched to the probe that caused it.
type reply struct {
	kind     replyKind
	from     netip.Addr
	proto    int
	id       int
	seq      int
	srcPort  int
	dstPort  int
	innerDst netip.Addr
}

// parseReply decodes an ICMP or ICMPv6 message (without the outer IP header).
func parseReply(v6 bool, data []byte, from netip.Addr) (reply, bool) {
	proto := protocolICMP
	if v6 {
		proto = protocolICMPv6
	}
	message, err := icmp.ParseMessage(proto, data)
	if err != nil {
		return reply{}, false
	}
	out := reply{from: from.Unmap()}
	switch message.Type {
	case ipv4.ICMPTypeEchoReply, ipv6.ICMPTypeEchoReply:
		echo, ok := message.Body.(*icmp.Echo)
		if !ok {
			return reply{}, false
		}
		out.kind, out.proto, out.id, out.seq = replyEcho, proto, echo.ID, echo.Seq
		return out, true
	case ipv4.ICMPTypeTimeExceeded, ipv6.ICMPTypeTimeExceeded:
		body, ok := message.Body.(*icmp.TimeExceeded)
		if !ok {
			return reply{}, false
		}
		out.kind = replyTimeExceeded
		return withInner(out, v6, body.Data)
	case ipv4.ICMPTypeDestinationUnreachable, ipv6.ICMPTypeDestinationUnreachable:
		body, ok := message.Body.(*icmp.DstUnreach)
		if !ok {
			return reply{}, false
		}
		out.kind = replyUnreachable
		return withInner(out, v6, body.Data)
	default:
		return reply{}, false
	}
}

// withInner decodes the original datagram quoted inside an ICMP error.
func withInner(out reply, v6 bool, quoted []byte) (reply, bool) {
	var upper []byte
	if v6 {
		if len(quoted) < 40+8 || quoted[0]>>4 != 6 {
			return reply{}, false
		}
		out.proto = int(quoted[6])
		out.innerDst, _ = netip.AddrFromSlice(quoted[24:40])
		upper = quoted[40:]
	} else {
		if len(quoted) < 20 || quoted[0]>>4 != 4 {
			return reply{}, false
		}
		headerLength := int(quoted[0]&0x0f) * 4
		if headerLength < 20 || len(quoted) < headerLength+8 {
			return reply{}, false
		}
		out.proto = int(quoted[9])
		out.innerDst, _ = netip.AddrFromSlice(quoted[16:20])
		upper = quoted[headerLength:]
	}
	switch out.proto {
	case protocolICMP, protocolICMPv6:
		out.id = int(binary.BigEndian.Uint16(upper[4:6]))
		out.seq = int(binary.BigEndian.Uint16(upper[6:8]))
	case protocolUDP, protocolTCP:
		out.srcPort = int(binary.BigEndian.Uint16(upper[0:2]))
		out.dstPort = int(binary.BigEndian.Uint16(upper[2:4]))
	default:
		return reply{}, false
	}
	return out, true
}
