// SPDX-License-Identifier: GPL-3.0-or-later

package mieru

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"

	"github.com/enfein/mieru/v3/apis/common"
	mieruconstant "github.com/enfein/mieru/v3/apis/constant"
	"github.com/enfein/mieru/v3/apis/model"
	"github.com/enfein/mieru/v3/apis/server"
	"github.com/enfein/mieru/v3/apis/trafficpattern"
	mierupb "github.com/enfein/mieru/v3/pkg/appctl/appctlpb"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/inbound"
	boxlistener "github.com/sagernet/sing-box/common/listener"
	"github.com/sagernet/sing-box/common/uot"
	"github.com/sagernet/sing-box/log"
	boxoption "github.com/sagernet/sing-box/option"
	boxcommon "github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/buf"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"google.golang.org/protobuf/proto"
)

func RegisterInbound(registry *inbound.Registry) {
	inbound.Register[InboundOptions](registry, Type, NewInbound)
}

type Inbound struct {
	inbound.Adapter
	ctx           context.Context
	cancel        context.CancelFunc
	router        adapter.ConnectionRouterEx
	logger        log.ContextLogger
	listen        boxoption.ListenOptions
	server        server.Server
	stateMu       sync.Mutex
	started       bool
	closed        bool
	acceptWG      sync.WaitGroup
	handlerWG     sync.WaitGroup
	connectionsMu sync.Mutex
	connections   map[io.Closer]struct{}
}

var _ adapter.Inbound = (*Inbound)(nil)

func NewInbound(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options InboundOptions) (adapter.Inbound, error) {
	inboundCtx, cancel := context.WithCancel(ctx)
	factory := &listenerFactory{ctx: inboundCtx, logger: logger, options: options.ListenOptions}
	config, err := buildServerConfig(options, factory)
	if err != nil {
		cancel()
		return nil, fmt.Errorf("build mieru server config: %w", err)
	}
	mieruServer := server.NewServer()
	if err := mieruServer.Store(config); err != nil {
		cancel()
		return nil, fmt.Errorf("store mieru server config: %w", err)
	}
	return &Inbound{
		Adapter:     inbound.NewAdapter(Type, tag),
		ctx:         inboundCtx,
		cancel:      cancel,
		router:      uot.NewRouter(router, logger),
		logger:      logger,
		listen:      options.ListenOptions,
		server:      mieruServer,
		connections: make(map[io.Closer]struct{}),
	}, nil
}

func (h *Inbound) Start(stage adapter.StartStage) error {
	if stage != adapter.StartStateStart {
		return nil
	}
	h.stateMu.Lock()
	defer h.stateMu.Unlock()
	if h.closed {
		return net.ErrClosed
	}
	if h.started {
		return nil
	}
	if err := h.server.Start(); err != nil {
		_ = h.server.Stop()
		return fmt.Errorf("start mieru server: %w", err)
	}
	h.started = true
	h.acceptWG.Add(1)
	go h.acceptLoop()
	h.logger.Info("mieru server started")
	return nil
}

func (h *Inbound) Close() error {
	h.stateMu.Lock()
	if h.closed {
		h.stateMu.Unlock()
		return nil
	}
	h.closed = true
	started := h.started
	h.stateMu.Unlock()

	h.cancel()
	var closeErrors []error
	if started && h.server.IsRunning() {
		if err := h.server.Stop(); err != nil {
			closeErrors = append(closeErrors, err)
		}
	}
	h.connectionsMu.Lock()
	connections := make([]io.Closer, 0, len(h.connections))
	for connection := range h.connections {
		connections = append(connections, connection)
	}
	h.connections = make(map[io.Closer]struct{})
	h.connectionsMu.Unlock()
	for _, connection := range connections {
		if err := connection.Close(); err != nil && !E.IsClosed(err) {
			closeErrors = append(closeErrors, err)
		}
	}
	h.acceptWG.Wait()
	h.handlerWG.Wait()
	return E.Errors(closeErrors...)
}

func (h *Inbound) acceptLoop() {
	defer h.acceptWG.Done()
	for {
		connection, request, err := h.server.Accept()
		if err != nil {
			if !h.server.IsRunning() || h.ctx.Err() != nil {
				return
			}
			h.logger.Debug("accept mieru connection: ", err)
			continue
		}
		h.handlerWG.Add(1)
		go func() {
			defer h.handlerWG.Done()
			h.handleConnection(connection, request)
		}()
	}
}

func (h *Inbound) handleConnection(connection net.Conn, request *model.Request) {
	ctx := log.ContextWithNewID(h.ctx)
	response := &model.Response{
		Reply: mieruconstant.Socks5ReplySuccess,
		BindAddr: model.AddrSpec{
			IP: net.IPv4zero,
		},
	}
	if err := response.WriteToSocks5(connection); err != nil {
		_ = connection.Close()
		h.logger.DebugContext(ctx, "write mieru response: ", err)
		return
	}

	metadata := adapter.InboundContext{
		Inbound:                   h.Tag(),
		InboundType:               h.Type(),
		InboundDetour:             h.listen.Detour,
		UDPDisableDomainUnmapping: h.listen.UDPDisableDomainUnmapping,
	}
	if remoteAddress := connection.RemoteAddr(); remoteAddress != nil {
		metadata.Source = M.SocksaddrFromNet(remoteAddress)
	}
	destination, err := addrSpecToSocksaddr(request.DstAddr)
	if err != nil {
		_ = connection.Close()
		h.logger.DebugContext(ctx, "convert mieru destination: ", err)
		return
	}
	metadata.Destination = destination
	if userContext, ok := connection.(common.UserContext); ok {
		metadata.User = userContext.UserName()
	}

	switch request.Command {
	case mieruconstant.Socks5ConnectCmd:
		onClose, ok := h.trackConnection(connection)
		if !ok {
			return
		}
		h.logger.InfoContext(ctx, "inbound TCP connection from ", metadata.Source, " to ", metadata.Destination)
		h.router.RouteConnectionEx(ctx, connection, metadata, onClose)
	case mieruconstant.Socks5UDPAssociateCmd:
		packetConnection := &mieruPacketConn{
			PacketConn:  common.NewPacketOverStreamTunnel(connection),
			destination: metadata.Destination,
		}
		onClose, ok := h.trackConnection(packetConnection)
		if !ok {
			return
		}
		h.logger.InfoContext(ctx, "inbound UDP connection from ", metadata.Source, " to ", metadata.Destination)
		h.router.RoutePacketConnectionEx(ctx, packetConnection, metadata, onClose)
	default:
		_ = connection.Close()
		h.logger.WarnContext(ctx, "unsupported mieru command: ", request.Command)
	}
}

func (h *Inbound) trackConnection(connection io.Closer) (N.CloseHandlerFunc, bool) {
	h.connectionsMu.Lock()
	defer h.connectionsMu.Unlock()
	h.stateMu.Lock()
	closed := h.closed
	h.stateMu.Unlock()
	if closed {
		_ = connection.Close()
		return nil, false
	}
	h.connections[connection] = struct{}{}
	return N.OnceClose(func(error) {
		h.connectionsMu.Lock()
		delete(h.connections, connection)
		h.connectionsMu.Unlock()
	}), true
}

func addrSpecToSocksaddr(address model.AddrSpec) (M.Socksaddr, error) {
	port, err := uint16Port(address.Port)
	if err != nil {
		return M.Socksaddr{}, err
	}
	if address.FQDN != "" {
		return M.Socksaddr{Fqdn: address.FQDN, Port: port}, nil
	}
	if ip, ok := netip.AddrFromSlice(address.IP); ok {
		return M.Socksaddr{Addr: ip.Unmap(), Port: port}, nil
	}
	return M.Socksaddr{}, fmt.Errorf("destination address is empty")
}

type mieruPacketConn struct {
	net.PacketConn
	destination M.Socksaddr
}

var _ N.PacketConn = (*mieruPacketConn)(nil)

func (c *mieruPacketConn) ReadPacket(buffer *buf.Buffer) (M.Socksaddr, error) {
	n, _, err := c.PacketConn.ReadFrom(buffer.FreeBytes())
	if err != nil {
		return M.Socksaddr{}, err
	}
	buffer.Truncate(n)
	if buffer.Len() < 3 {
		return M.Socksaddr{}, io.ErrShortBuffer
	}
	buffer.Advance(3)
	var address model.AddrSpec
	if err := address.ReadFromSocks5(buffer); err != nil {
		return M.Socksaddr{}, err
	}
	return addrSpecToSocksaddr(address)
}

func (c *mieruPacketConn) WritePacket(buffer *buf.Buffer, destination M.Socksaddr) error {
	header := buf.NewSize(3 + M.MaxSocksaddrLength)
	defer header.Release()
	boxcommon.Must(header.WriteZeroN(3))
	address := model.AddrSpec{Port: int(destination.Port)}
	if destination.Fqdn != "" {
		address.FQDN = destination.Fqdn
	} else {
		address.IP = destination.Addr.AsSlice()
	}
	if err := address.WriteToSocks5(header); err != nil {
		return err
	}
	packet := buf.NewSize(header.Len() + buffer.Len())
	defer packet.Release()
	boxcommon.Must1(packet.Write(header.Bytes()))
	boxcommon.Must1(packet.Write(buffer.Bytes()))
	_, err := c.PacketConn.WriteTo(packet.Bytes(), nil)
	return err
}

func buildServerConfig(options InboundOptions, factory *listenerFactory) (*server.ServerConfig, error) {
	transport, err := parseTransport(options.Transport)
	if err != nil {
		return nil, err
	}
	ports, err := expandPorts(options.ListenPort, options.ListenPortRanges)
	if err != nil {
		return nil, err
	}
	if len(options.Users) == 0 {
		return nil, fmt.Errorf("users must not be empty")
	}
	users := make([]*mierupb.User, 0, len(options.Users))
	seenUsers := make(map[string]struct{}, len(options.Users))
	for _, user := range options.Users {
		if strings.TrimSpace(user.Name) == "" {
			return nil, fmt.Errorf("username must not be empty")
		}
		if len([]byte(user.Name)) > 64 {
			return nil, fmt.Errorf("username %q exceeds 64 bytes", user.Name)
		}
		if user.Password == "" {
			return nil, fmt.Errorf("password for user %q must not be empty", user.Name)
		}
		if len([]byte(user.Password)) > 64 {
			return nil, fmt.Errorf("password for user %q exceeds 64 bytes", user.Name)
		}
		if _, exists := seenUsers[user.Name]; exists {
			return nil, fmt.Errorf("duplicate username %q", user.Name)
		}
		seenUsers[user.Name] = struct{}{}
		users = append(users, &mierupb.User{Name: proto.String(user.Name), Password: proto.String(user.Password)})
	}
	bindings := make([]*mierupb.PortBinding, 0, len(ports))
	for _, port := range ports {
		bindings = append(bindings, &mierupb.PortBinding{Port: proto.Int32(int32(port)), Protocol: transport.Enum()})
	}
	var pattern *mierupb.TrafficPattern
	if options.TrafficPattern != "" {
		pattern, err = trafficpattern.Decode(options.TrafficPattern)
		if err != nil {
			return nil, fmt.Errorf("decode traffic pattern: %w", err)
		}
		if err := trafficpattern.Validate(pattern); err != nil {
			return nil, fmt.Errorf("validate traffic pattern: %w", err)
		}
	}
	config := &server.ServerConfig{
		Config: &mierupb.ServerConfig{
			PortBindings:   bindings,
			Users:          users,
			TrafficPattern: pattern,
		},
		StreamListenerFactory: factory,
		PacketListenerFactory: factory,
	}
	if options.UserHintIsMandatory {
		config.Config.AdvancedSettings = &mierupb.ServerAdvancedSettings{UserHintIsMandatory: proto.Bool(true)}
	}
	return config, nil
}

func parseTransport(value string) (mierupb.TransportProtocol, error) {
	switch strings.ToUpper(strings.TrimSpace(value)) {
	case "TCP":
		return mierupb.TransportProtocol_TCP, nil
	case "UDP":
		return mierupb.TransportProtocol_UDP, nil
	default:
		return mierupb.TransportProtocol_UNKNOWN_TRANSPORT_PROTOCOL, fmt.Errorf("transport must be TCP or UDP")
	}
}

type listenerFactory struct {
	ctx     context.Context
	logger  log.ContextLogger
	options boxoption.ListenOptions
}

var (
	_ common.StreamListenerFactory = (*listenerFactory)(nil)
	_ common.PacketListenerFactory = (*listenerFactory)(nil)
)

func (f *listenerFactory) Listen(_ context.Context, network, address string) (net.Listener, error) {
	if !strings.HasPrefix(network, "tcp") {
		return nil, fmt.Errorf("unsupported stream network %q", network)
	}
	protocolListener, err := f.listenerFor(address, []string{N.NetworkTCP})
	if err != nil {
		return nil, err
	}
	return protocolListener.ListenTCP()
}

func (f *listenerFactory) ListenPacket(_ context.Context, network, address string) (net.PacketConn, error) {
	if !strings.HasPrefix(network, "udp") {
		return nil, fmt.Errorf("unsupported packet network %q", network)
	}
	protocolListener, err := f.listenerFor(address, []string{N.NetworkUDP})
	if err != nil {
		return nil, err
	}
	return protocolListener.ListenUDP()
}

func (f *listenerFactory) listenerFor(address string, networks []string) (*boxlistener.Listener, error) {
	_, portText, err := net.SplitHostPort(address)
	if err != nil {
		return nil, fmt.Errorf("parse listener address %q: %w", address, err)
	}
	port, err := strconv.ParseUint(portText, 10, 16)
	if err != nil || port == 0 {
		return nil, fmt.Errorf("invalid listener port in %q", address)
	}
	options := f.options
	options.ListenPort = uint16(port)
	return boxlistener.New(boxlistener.Options{
		Context: f.ctx,
		Logger:  f.logger,
		Network: networks,
		Listen:  options,
	}), nil
}
