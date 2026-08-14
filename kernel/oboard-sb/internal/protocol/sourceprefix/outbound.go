// SPDX-License-Identifier: GPL-3.0-or-later

package sourceprefix

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"sort"
	"strings"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/common/dialer"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/json/badoption"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/service"
)

func RegisterOutbound(registry *outbound.Registry) {
	outbound.Register[OutboundOptions](registry, Type, NewOutbound)
}

type Outbound struct {
	outbound.Adapter
	logger     log.ContextLogger
	prefix     netip.Prefix
	options    option.DialerOptions
	dnsRouter  adapter.DNSRouter
	dnsOptions adapter.DNSQueryOptions
}

var _ adapter.Outbound = (*Outbound)(nil)

func NewOutbound(ctx context.Context, _ adapter.Router, logger log.ContextLogger, tag string, options OutboundOptions) (adapter.Outbound, error) {
	prefix, err := parsePrefix(options.Prefix)
	if err != nil {
		return nil, err
	}
	if options.Detour != "" || options.BindInterface != "" || options.Inet4BindAddress != nil || options.Inet6BindAddress != nil {
		return nil, fmt.Errorf("source-prefix does not support detour, interface, or fixed bind options")
	}
	if options.NetworkStrategy != nil || len(options.NetworkType) > 0 || len(options.FallbackNetworkType) > 0 {
		return nil, fmt.Errorf("source-prefix does not support network strategy options")
	}
	baseOptions := options.DialerOptions
	dnsOptions, err := adapter.DNSQueryOptionsFrom(ctx, options.DomainResolver)
	if err != nil {
		return nil, err
	}
	baseOptions.DomainResolver = nil
	baseOptions.DomainStrategy = option.DomainStrategy(C.DomainStrategyAsIS)
	return &Outbound{
		Adapter:    outbound.NewAdapter(Type, tag, []string{N.NetworkTCP, N.NetworkUDP}, nil),
		logger:     logger,
		prefix:     prefix,
		options:    baseOptions,
		dnsRouter:  service.FromContext[adapter.DNSRouter](ctx),
		dnsOptions: *dnsOptions,
	}, nil
}

func (o *Outbound) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	ctx, metadata := adapter.ExtendContext(ctx)
	metadata.Outbound = o.Tag()
	metadata.Destination = destination
	addresses, err := o.resolve(ctx, destination)
	if err != nil {
		return nil, err
	}
	source, err := selectSource(o.prefix, localAddresses)
	if err != nil {
		return nil, err
	}
	var dialErrors []error
	for _, address := range addresses {
		dialer, err := o.newDialer(ctx, source)
		if err != nil {
			return nil, err
		}
		resolved := M.SocksaddrFrom(address, destination.Port)
		o.logger.InfoContext(ctx, "source-prefix outbound ", o.prefix, " via ", source, " to ", resolved)
		conn, dialErr := dialer.DialContext(ctx, N.NetworkName(network), resolved)
		if dialErr == nil {
			return conn, nil
		}
		dialErrors = append(dialErrors, dialErr)
	}
	return nil, E.Cause(E.Errors(dialErrors...), "source-prefix outbound could not connect to ", destination, " via ", source)
}

func (o *Outbound) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	ctx, metadata := adapter.ExtendContext(ctx)
	metadata.Outbound = o.Tag()
	metadata.Destination = destination
	addresses, err := o.resolve(ctx, destination)
	if err != nil {
		return nil, err
	}
	source, err := selectSource(o.prefix, localAddresses)
	if err != nil {
		return nil, err
	}
	dialer, err := o.newDialer(ctx, source)
	if err != nil {
		return nil, err
	}
	return dialer.ListenPacket(ctx, M.SocksaddrFrom(addresses[0], destination.Port))
}

func (o *Outbound) resolve(ctx context.Context, destination M.Socksaddr) ([]netip.Addr, error) {
	if destination.IsIP() {
		if o.prefix.Addr().Is4() == destination.Addr.Is4() {
			return []netip.Addr{destination.Addr}, nil
		}
		return nil, fmt.Errorf("source-prefix %s cannot connect to a different address family", o.prefix)
	}
	if o.dnsRouter == nil {
		return nil, fmt.Errorf("source-prefix outbound requires a DNS router for %s", destination.Fqdn)
	}
	strategy := C.DomainStrategyIPv4Only
	if o.prefix.Addr().Is6() {
		strategy = C.DomainStrategyIPv6Only
	}
	queryOptions := o.dnsOptions
	queryOptions.Strategy = strategy
	queryOptions.LookupStrategy = strategy
	addresses, err := o.dnsRouter.Lookup(ctx, destination.Fqdn, queryOptions)
	if err != nil {
		return nil, E.Cause(err, "resolve source-prefix destination")
	}
	if len(addresses) == 0 {
		return nil, fmt.Errorf("source-prefix destination %s has no matching addresses", destination.Fqdn)
	}
	return addresses, nil
}

func (o *Outbound) newDialer(ctx context.Context, source netip.Addr) (N.Dialer, error) {
	options := o.options
	if source.Is4() {
		address := badoption.Addr(source)
		options.Inet4BindAddress = &address
	} else {
		address := badoption.Addr(source)
		options.Inet6BindAddress = &address
	}
	return dialer.NewWithOptions(dialer.Options{Context: ctx, Options: options, RemoteIsDomain: false, DirectOutbound: true})
}

var localAddresses = func() ([]netip.Addr, error) {
	addresses, err := net.InterfaceAddrs()
	if err != nil {
		return nil, err
	}
	result := make([]netip.Addr, 0, len(addresses))
	for _, raw := range addresses {
		if prefix, err := netip.ParsePrefix(raw.String()); err == nil {
			result = append(result, prefix.Addr())
			continue
		}
		if address, err := netip.ParseAddr(strings.TrimSpace(raw.String())); err == nil {
			result = append(result, address)
		}
	}
	return result, nil
}

func selectSource(prefix netip.Prefix, sourceFunc func() ([]netip.Addr, error)) (netip.Addr, error) {
	addresses, err := sourceFunc()
	if err != nil {
		return netip.Addr{}, fmt.Errorf("scan local source addresses: %w", err)
	}
	return selectSourceFromAddresses(prefix, addresses)
}

func selectSourceFromAddresses(prefix netip.Prefix, addresses []netip.Addr) (netip.Addr, error) {
	candidates := make([]netip.Addr, 0, len(addresses))
	for _, address := range addresses {
		if address.IsValid() && address.IsGlobalUnicast() && prefix.Contains(address) {
			candidates = append(candidates, address)
		}
	}
	if len(candidates) == 0 {
		return netip.Addr{}, fmt.Errorf("source-prefix %s has no active global-unicast address", prefix)
	}
	sort.Slice(candidates, func(i, j int) bool { return candidates[i].Compare(candidates[j]) < 0 })
	return candidates[0], nil
}
