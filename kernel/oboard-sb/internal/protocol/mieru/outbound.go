// SPDX-License-Identifier: GPL-3.0-or-later

package mieru

import (
	"context"
	"fmt"
	"net"
	"os"
	"strings"

	"github.com/enfein/mieru/v3/apis/client"
	"github.com/enfein/mieru/v3/apis/common"
	"github.com/enfein/mieru/v3/apis/model"
	"github.com/enfein/mieru/v3/apis/trafficpattern"
	mierupb "github.com/enfein/mieru/v3/pkg/appctl/appctlpb"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/common/dialer"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/service"
	"google.golang.org/protobuf/proto"
)

func RegisterOutbound(registry *outbound.Registry) {
	outbound.Register[OutboundOptions](registry, Type, NewOutbound)
}

type Outbound struct {
	outbound.Adapter
	logger log.ContextLogger
	client client.Client
}

var _ adapter.Outbound = (*Outbound)(nil)

func NewOutbound(ctx context.Context, _ adapter.Router, logger log.ContextLogger, tag string, options OutboundOptions) (adapter.Outbound, error) {
	outboundDialer, err := dialer.New(ctx, options.DialerOptions, options.ServerIsDomain())
	if err != nil {
		return nil, err
	}
	dnsRouter := service.FromContext[adapter.DNSRouter](ctx)
	if options.ServerIsDomain() && dnsRouter == nil {
		return nil, fmt.Errorf("missing DNS router for mieru server domain")
	}
	config, err := buildClientConfig(options, mieruDialer{dialer: outboundDialer}, dnsResolver{router: dnsRouter})
	if err != nil {
		return nil, fmt.Errorf("build mieru client config: %w", err)
	}
	mieruClient := client.NewClient()
	if err := mieruClient.Store(config); err != nil {
		return nil, fmt.Errorf("store mieru client config: %w", err)
	}
	if err := mieruClient.Start(); err != nil {
		_ = mieruClient.Stop()
		return nil, fmt.Errorf("start mieru client: %w", err)
	}
	return &Outbound{
		Adapter: outbound.NewAdapterWithDialerOptions(Type, tag, []string{N.NetworkTCP, N.NetworkUDP}, options.DialerOptions),
		logger:  logger,
		client:  mieruClient,
	}, nil
}

func (o *Outbound) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	ctx, metadata := adapter.ExtendContext(ctx)
	metadata.Outbound = o.Tag()
	metadata.Destination = destination
	switch N.NetworkName(network) {
	case N.NetworkTCP:
		o.logger.InfoContext(ctx, "outbound connection to ", destination)
		address, err := socksaddrToNetAddrSpec(destination, "tcp")
		if err != nil {
			return nil, E.Cause(err, "convert destination address")
		}
		return o.client.DialContext(ctx, address)
	case N.NetworkUDP:
		o.logger.InfoContext(ctx, "outbound UoT connection to ", destination)
		address, err := socksaddrToNetAddrSpec(destination, "udp")
		if err != nil {
			return nil, E.Cause(err, "convert destination address")
		}
		streamConnection, err := o.client.DialContext(ctx, address)
		if err != nil {
			return nil, err
		}
		return &packetStreamer{
			PacketConn: common.NewUDPAssociateWrapper(common.NewPacketOverStreamTunnel(streamConnection)),
			remote:     destination,
		}, nil
	default:
		return nil, os.ErrInvalid
	}
}

func (o *Outbound) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	ctx, metadata := adapter.ExtendContext(ctx)
	metadata.Outbound = o.Tag()
	metadata.Destination = destination
	o.logger.InfoContext(ctx, "outbound UoT packet connection to ", destination)
	address, err := socksaddrToNetAddrSpec(destination, "udp")
	if err != nil {
		return nil, E.Cause(err, "convert destination address")
	}
	streamConnection, err := o.client.DialContext(ctx, address)
	if err != nil {
		return nil, err
	}
	return common.NewUDPAssociateWrapper(common.NewPacketOverStreamTunnel(streamConnection)), nil
}

func (o *Outbound) Close() error {
	return o.client.Stop()
}

type mieruDialer struct {
	dialer N.Dialer
}

var (
	_ common.Dialer       = mieruDialer{}
	_ common.PacketDialer = mieruDialer{}
)

func (d mieruDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	return d.dialer.DialContext(ctx, network, M.ParseSocksaddr(address))
}

func (d mieruDialer) ListenPacket(ctx context.Context, _ string, _ string, remoteAddress string) (net.PacketConn, error) {
	return d.dialer.ListenPacket(ctx, M.ParseSocksaddr(remoteAddress))
}

type dnsResolver struct {
	router adapter.DNSRouter
}

var _ common.DNSResolver = dnsResolver{}

func (r dnsResolver) LookupIP(ctx context.Context, network, host string) ([]net.IP, error) {
	if r.router == nil {
		return nil, fmt.Errorf("DNS router is unavailable")
	}
	queryOptions := adapter.DNSQueryOptions{}
	switch network {
	case "", "ip":
	case "ip4":
		queryOptions.Strategy = C.DomainStrategyIPv4Only
	case "ip6":
		queryOptions.Strategy = C.DomainStrategyIPv6Only
	default:
		return nil, net.UnknownNetworkError(network)
	}
	addresses, err := r.router.Lookup(ctx, host, queryOptions)
	if err != nil {
		return nil, err
	}
	result := make([]net.IP, 0, len(addresses))
	for _, address := range addresses {
		result = append(result, append(net.IP(nil), address.AsSlice()...))
	}
	return result, nil
}

type packetStreamer struct {
	net.PacketConn
	remote net.Addr
}

var _ net.Conn = (*packetStreamer)(nil)

func (s *packetStreamer) Read(buffer []byte) (int, error) {
	n, _, err := s.PacketConn.ReadFrom(buffer)
	return n, err
}

func (s *packetStreamer) Write(buffer []byte) (int, error) {
	return s.PacketConn.WriteTo(buffer, s.remote)
}

func (s *packetStreamer) RemoteAddr() net.Addr {
	return s.remote
}

func socksaddrToNetAddrSpec(address M.Socksaddr, network string) (model.NetAddrSpec, error) {
	var result model.NetAddrSpec
	if err := result.From(address); err != nil {
		return result, err
	}
	result.Net = network
	return result, nil
}

func buildClientConfig(options OutboundOptions, protocolDialer mieruDialer, resolver common.DNSResolver) (*client.ClientConfig, error) {
	transport, err := parseTransport(options.Transport)
	if err != nil {
		return nil, err
	}
	ports, err := expandPorts(options.ServerPort, options.ServerPortRanges)
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(options.Server) == "" {
		return nil, fmt.Errorf("server must not be empty")
	}
	if strings.TrimSpace(options.Username) == "" {
		return nil, fmt.Errorf("username must not be empty")
	}
	if len([]byte(options.Username)) > 64 {
		return nil, fmt.Errorf("username exceeds 64 bytes")
	}
	if options.Password == "" {
		return nil, fmt.Errorf("password must not be empty")
	}
	if len([]byte(options.Password)) > 64 {
		return nil, fmt.Errorf("password exceeds 64 bytes")
	}
	serverEndpoint := &mierupb.ServerEndpoint{}
	for _, port := range ports {
		serverEndpoint.PortBindings = append(serverEndpoint.PortBindings, &mierupb.PortBinding{
			Port:     proto.Int32(int32(port)),
			Protocol: transport.Enum(),
		})
	}
	if M.IsDomainName(options.Server) {
		serverEndpoint.DomainName = proto.String(options.Server)
	} else {
		serverEndpoint.IpAddress = proto.String(options.Server)
	}
	profile := &mierupb.ClientProfile{
		ProfileName: proto.String("oboard-sb"),
		User: &mierupb.User{
			Name:     proto.String(options.Username),
			Password: proto.String(options.Password),
		},
		Servers: []*mierupb.ServerEndpoint{serverEndpoint},
	}
	if options.Multiplexing != "" {
		multiplexing, exists := mierupb.MultiplexingLevel_value[options.Multiplexing]
		if !exists {
			return nil, fmt.Errorf("invalid multiplexing level %q", options.Multiplexing)
		}
		profile.Multiplexing = &mierupb.MultiplexingConfig{Level: mierupb.MultiplexingLevel(multiplexing).Enum()}
	}
	if options.TrafficPattern != "" {
		pattern, err := trafficpattern.Decode(options.TrafficPattern)
		if err != nil {
			return nil, fmt.Errorf("decode traffic pattern: %w", err)
		}
		if err := trafficpattern.Validate(pattern); err != nil {
			return nil, fmt.Errorf("validate traffic pattern: %w", err)
		}
		profile.TrafficPattern = pattern
	}
	return &client.ClientConfig{
		Profile:      profile,
		Dialer:       protocolDialer,
		PacketDialer: protocolDialer,
		Resolver:     resolver,
		DNSConfig:    &common.ClientDNSConfig{BypassDialerDNS: true},
	}, nil
}
