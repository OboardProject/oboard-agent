package agent

import (
	"bufio"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"time"
)

const outboundRelayCapability = "outbound_relay_v1"

const routeRelayCapability = "route_relay_v1"

type outboundRelayDialFunc func(context.Context, string, string, string) (net.Conn, error)
type routeRelayDialFunc func(context.Context, string, string, string, string, []netip.Addr) (net.Conn, error)

type bufferedRelayConn struct {
	net.Conn
	reader *bufio.Reader
}

func (c *bufferedRelayConn) Read(p []byte) (int, error) { return c.reader.Read(p) }

type framedRelayPacketConn struct {
	net.Conn
	readMu    sync.Mutex
	writeMu   sync.Mutex
	remaining int
}

func (c *framedRelayPacketConn) Read(p []byte) (int, error) {
	c.readMu.Lock()
	defer c.readMu.Unlock()
	if c.remaining == 0 {
		var size [2]byte
		if _, err := io.ReadFull(c.Conn, size[:]); err != nil {
			return 0, err
		}
		c.remaining = int(binary.BigEndian.Uint16(size[:]))
		if c.remaining == 0 {
			return 0, nil
		}
	}
	if len(p) < c.remaining {
		return 0, errors.New("UDP relay read buffer is too small")
	}
	n, err := io.ReadFull(c.Conn, p[:c.remaining])
	c.remaining = 0
	return n, err
}

func (c *framedRelayPacketConn) Write(p []byte) (int, error) {
	if len(p) == 0 || len(p) > math.MaxUint16 {
		return 0, errors.New("invalid UDP relay payload size")
	}
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	var size [2]byte
	binary.BigEndian.PutUint16(size[:], uint16(len(p))) // #nosec G115 -- the payload length is bounded above.
	if err := writeAll(c.Conn, size[:]); err != nil {
		return 0, err
	}
	if err := writeAll(c.Conn, p); err != nil {
		return 0, err
	}
	return len(p), nil
}

func (r *Runner) validateOutboundRelayCapability(ctx context.Context) error {
	return r.validateKernelCapability(ctx, outboundRelayCapability)
}

func (r *Runner) validateRouteRelayCapability(ctx context.Context) error {
	return r.validateKernelCapability(ctx, routeRelayCapability)
}

func (r *Runner) validateKernelCapability(ctx context.Context, required string) error {
	client := r.coreClient
	if client == nil {
		client = unixHTTPClient(coreAPISocket)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://oboard-sb/version", nil)
	if err != nil {
		return err
	}
	res, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("query kernel relay capability: %w", err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return fmt.Errorf("query kernel relay capability: status %d", res.StatusCode)
	}
	var payload struct {
		Capabilities []string `json:"capabilities"`
	}
	if err := json.NewDecoder(io.LimitReader(res.Body, 64<<10)).Decode(&payload); err != nil {
		return fmt.Errorf("decode kernel relay capability: %w", err)
	}
	for _, capability := range payload.Capabilities {
		if capability == required {
			return nil
		}
	}
	return fmt.Errorf("kernel does not support %s", required)
}

func (r *Runner) dialSSHOutboundRelay(ctx context.Context, network, outboundTag, destination string) (net.Conn, error) {
	if r.sshOutboundRelayDial != nil {
		return r.sshOutboundRelayDial(ctx, network, outboundTag, destination)
	}
	return dialCoreOutboundRelay(ctx, coreAPISocket, network, outboundTag, destination)
}

func dialCoreOutboundRelay(ctx context.Context, socket, network, outboundTag, destination string) (net.Conn, error) {
	if network != "tcp" && network != "udp" {
		return nil, errors.New("unsupported outbound relay network")
	}
	dialer := net.Dialer{Timeout: 3 * time.Second}
	conn, err := dialer.DialContext(ctx, "unix", socket)
	if err != nil {
		return nil, err
	}
	deadline := time.Now().Add(10 * time.Second)
	_ = conn.SetDeadline(deadline)
	req, err := http.NewRequest(http.MethodConnect, "http://oboard-sb/outbounds/relay/"+network, nil)
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	req.Header.Set("X-OBoard-Outbound-Tag", outboundTag)
	req.Header.Set("X-OBoard-Destination", destination)
	if err := req.Write(conn); err != nil {
		_ = conn.Close()
		return nil, err
	}
	reader := bufio.NewReader(conn)
	response, err := http.ReadResponse(reader, req)
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	if response.StatusCode != http.StatusOK {
		message, _ := io.ReadAll(io.LimitReader(response.Body, 1024))
		_ = response.Body.Close()
		_ = conn.Close()
		return nil, fmt.Errorf("kernel outbound relay status %d: %s", response.StatusCode, strings.TrimSpace(string(message)))
	}
	_ = conn.SetDeadline(time.Time{})
	stream := &bufferedRelayConn{Conn: conn, reader: reader}
	if network == "udp" {
		return &framedRelayPacketConn{Conn: stream}, nil
	}
	return stream, nil
}

func (r *Runner) dialSSHRouteRelay(ctx context.Context, network, inboundTag, authUser, destination string, resolved []netip.Addr) (net.Conn, error) {
	if r.sshRouteRelayDial != nil {
		return r.sshRouteRelayDial(ctx, network, inboundTag, authUser, destination, resolved)
	}
	return dialCoreRouteRelay(ctx, coreAPISocket, network, inboundTag, authUser, destination, resolved)
}

func dialCoreRouteRelay(ctx context.Context, socket, network, inboundTag, authUser, destination string, resolved []netip.Addr) (net.Conn, error) {
	if network != "tcp" && network != "udp" {
		return nil, errors.New("unsupported route relay network")
	}
	dialer := net.Dialer{Timeout: 3 * time.Second}
	conn, err := dialer.DialContext(ctx, "unix", socket)
	if err != nil {
		return nil, err
	}
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	req, err := http.NewRequest(http.MethodConnect, "http://oboard-sb/routes/relay/"+network, nil)
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	req.Header.Set("X-OBoard-Inbound-Tag", inboundTag)
	req.Header.Set("X-OBoard-Auth-User", authUser)
	req.Header.Set("X-OBoard-Destination", destination)
	addresses := make([]string, 0, len(resolved))
	for _, address := range resolved {
		addresses = append(addresses, address.Unmap().String())
	}
	req.Header.Set("X-OBoard-Resolved-Addresses", strings.Join(addresses, ","))
	if err := req.Write(conn); err != nil {
		_ = conn.Close()
		return nil, err
	}
	reader := bufio.NewReader(conn)
	response, err := http.ReadResponse(reader, req)
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	if response.StatusCode != http.StatusOK {
		message, _ := io.ReadAll(io.LimitReader(response.Body, 1024))
		_ = response.Body.Close()
		_ = conn.Close()
		return nil, fmt.Errorf("kernel route relay status %d: %s", response.StatusCode, strings.TrimSpace(string(message)))
	}
	_ = conn.SetDeadline(time.Time{})
	stream := &bufferedRelayConn{Conn: conn, reader: reader}
	if network == "udp" {
		return &framedRelayPacketConn{Conn: stream}, nil
	}
	return stream, nil
}
