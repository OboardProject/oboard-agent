package main

import (
	"bufio"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"regexp"
	"strings"

	box "github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
)

var (
	routeInboundTagPattern = regexp.MustCompile(`^in-[1-9][0-9]*$`)
	routeAuthUserPattern   = regexp.MustCompile(`^.{1,192}__oboard_path_[1-9][0-9]*$`)
)

func registerRouteRelayHandlers(mux *http.ServeMux, listen string, instance *box.Box) {
	if !strings.HasPrefix(listen, "unix:") || instance == nil {
		return
	}
	mux.Handle("/routes/relay/tcp", newRouteRelayHandler("tcp", instance.Router()))
	mux.Handle("/routes/relay/udp", newRouteRelayHandler("udp", instance.Router()))
}

func newRouteRelayHandler(network string, router adapter.Router) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodConnect {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		inboundTag := strings.TrimSpace(r.Header.Get("X-OBoard-Inbound-Tag"))
		authUser := strings.TrimSpace(r.Header.Get("X-OBoard-Auth-User"))
		if !routeInboundTagPattern.MatchString(inboundTag) || !routeAuthUserPattern.MatchString(authUser) {
			http.Error(w, "invalid route identity", http.StatusBadRequest)
			return
		}
		destination := M.ParseSocksaddr(strings.TrimSpace(r.Header.Get("X-OBoard-Destination")))
		if !destination.IsValid() || destination.Port == 0 {
			http.Error(w, "invalid destination", http.StatusBadRequest)
			return
		}
		resolved, err := parseRouteRelayAddresses(r.Header.Get("X-OBoard-Resolved-Addresses"))
		if err != nil || destination.IsDomain() && len(resolved) == 0 {
			http.Error(w, "invalid resolved addresses", http.StatusBadRequest)
			return
		}
		if destination.IsIP() {
			address := destination.Addr.Unmap()
			if !isPublicRouteRelayAddress(address) {
				http.Error(w, "destination is not public", http.StatusBadRequest)
				return
			}
			if len(resolved) == 0 {
				resolved = []netip.Addr{address}
			}
		}
		hijacker, ok := w.(http.Hijacker)
		if !ok {
			http.Error(w, "connection hijacking unavailable", http.StatusInternalServerError)
			return
		}
		client, buffered, err := hijacker.Hijack()
		if err != nil {
			return
		}
		_, _ = buffered.WriteString("HTTP/1.1 200 Connection Established\r\n\r\n")
		if err := buffered.Flush(); err != nil {
			_ = client.Close()
			return
		}
		metadata := adapter.InboundContext{
			Inbound:              inboundTag,
			InboundType:          "ssh",
			Network:              network,
			Destination:          destination,
			DestinationAddresses: resolved,
			User:                 authUser,
		}
		ctx := context.Background()
		if network == "udp" {
			packetConn := &routeRelayPacketConn{Conn: client, reader: buffered.Reader, destination: destination}
			router.RoutePacketConnectionEx(ctx, packetConn, metadata, func(error) { _ = packetConn.Close() })
			return
		}
		stream := &routeRelayStream{Conn: client, reader: buffered.Reader}
		router.RouteConnectionEx(ctx, stream, metadata, func(error) { _ = stream.Close() })
	})
}

type routeRelayStream struct {
	net.Conn
	reader *bufio.Reader
}

func (c *routeRelayStream) Read(p []byte) (int, error) { return c.reader.Read(p) }

func parseRouteRelayAddresses(value string) ([]netip.Addr, error) {
	parts := strings.Split(strings.TrimSpace(value), ",")
	if len(parts) == 1 && parts[0] == "" {
		return nil, nil
	}
	if len(parts) > 32 {
		return nil, errors.New("too many resolved addresses")
	}
	addresses := make([]netip.Addr, 0, len(parts))
	seen := map[netip.Addr]bool{}
	for _, part := range parts {
		address, err := netip.ParseAddr(strings.TrimSpace(part))
		if err != nil {
			return nil, err
		}
		address = address.Unmap()
		if !isPublicRouteRelayAddress(address) {
			return nil, errors.New("resolved address is not public")
		}
		if !seen[address] {
			seen[address] = true
			addresses = append(addresses, address)
		}
	}
	return addresses, nil
}

func isPublicRouteRelayAddress(address netip.Addr) bool {
	return address.IsValid() && address.IsGlobalUnicast() && !address.IsPrivate() && !address.IsLoopback() && !address.IsLinkLocalUnicast() && !address.IsLinkLocalMulticast() && !address.IsMulticast() && !address.IsUnspecified()
}

type routeRelayPacketConn struct {
	net.Conn
	reader      *bufio.Reader
	destination M.Socksaddr
}

func (c *routeRelayPacketConn) ReadPacket(buffer *buf.Buffer) (M.Socksaddr, error) {
	var size [2]byte
	if _, err := io.ReadFull(c.reader, size[:]); err != nil {
		return M.Socksaddr{}, err
	}
	length := int(binary.BigEndian.Uint16(size[:]))
	if length == 0 || length > buffer.FreeLen() {
		return M.Socksaddr{}, io.ErrShortBuffer
	}
	if _, err := buffer.ReadFullFrom(c.reader, length); err != nil {
		return M.Socksaddr{}, err
	}
	return c.destination, nil
}

func (c *routeRelayPacketConn) WritePacket(buffer *buf.Buffer, _ M.Socksaddr) error {
	defer buffer.Release()
	if buffer.Len() == 0 || buffer.Len() > 65535 {
		return errors.New("invalid UDP route relay payload")
	}
	var size [2]byte
	binary.BigEndian.PutUint16(size[:], uint16(buffer.Len())) // #nosec G115 -- length is bounded above.
	return writeRelayParts(c.Conn, size[:], buffer.Bytes())
}
