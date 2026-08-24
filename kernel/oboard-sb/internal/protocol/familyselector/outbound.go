// SPDX-License-Identifier: GPL-3.0-or-later

package familyselector

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"os"
	"strings"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/outbound"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/service"
)

const maxAddressesPerFamily = 8

type SelectionObserver interface {
	FamilySelectorSelected(ctx context.Context, selectorTag, childTag, childType string)
}

func RegisterOutbound(registry *outbound.Registry) {
	outbound.Register[OutboundOptions](registry, Type, NewOutbound)
}

type Outbound struct {
	outbound.Adapter
	logger        log.ContextLogger
	ipv4          adapter.Outbound
	ipv6          adapter.Outbound
	dnsRouter     adapter.DNSRouter
	dnsOptions    adapter.DNSQueryOptions
	preferIPv6    bool
	allowFallback bool
}

var _ adapter.Outbound = (*Outbound)(nil)

func NewOutbound(ctx context.Context, _ adapter.Router, logger log.ContextLogger, tag string, options OutboundOptions) (adapter.Outbound, error) {
	if err := options.validate(); err != nil {
		return nil, err
	}
	manager := service.FromContext[adapter.OutboundManager](ctx)
	if manager == nil {
		return nil, fmt.Errorf("family-selector requires an outbound manager")
	}
	ipv4Tag := strings.TrimSpace(options.IPv4Outbound)
	ipv6Tag := strings.TrimSpace(options.IPv6Outbound)
	ipv4Outbound, ipv4OK := manager.Outbound(ipv4Tag)
	if !ipv4OK {
		return nil, fmt.Errorf("family-selector IPv4 outbound %q not found", ipv4Tag)
	}
	ipv6Outbound, ipv6OK := manager.Outbound(ipv6Tag)
	if !ipv6OK {
		return nil, fmt.Errorf("family-selector IPv6 outbound %q not found", ipv6Tag)
	}
	dnsOptions, err := adapter.DNSQueryOptionsFrom(ctx, options.DomainResolver)
	if err != nil {
		return nil, err
	}
	strategy := C.DomainStrategy(options.Strategy)
	dnsOptions.Strategy = strategy
	dnsOptions.LookupStrategy = strategy
	return &Outbound{
		Adapter:       outbound.NewAdapter(Type, tag, []string{N.NetworkTCP, N.NetworkUDP}, []string{ipv4Tag, ipv6Tag}),
		logger:        logger,
		ipv4:          ipv4Outbound,
		ipv6:          ipv6Outbound,
		dnsRouter:     service.FromContext[adapter.DNSRouter](ctx),
		dnsOptions:    dnsOptions,
		preferIPv6:    strategy == C.DomainStrategyPreferIPv6,
		allowFallback: options.Fallback,
	}, nil
}

func (o *Outbound) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	network = N.NetworkName(network)
	if network != N.NetworkTCP && network != N.NetworkUDP {
		return nil, os.ErrInvalid
	}
	ipv4, ipv6, literal, err := o.candidates(ctx, destination)
	if err != nil {
		return nil, err
	}
	if literal {
		if destination.IsIPv4() {
			return o.dialOne(ctx, o.ipv4, network, destination)
		}
		return o.dialOne(ctx, o.ipv6, network, destination)
	}
	primary, secondary := o.ordered(ipv4, ipv6)
	if network == N.NetworkUDP {
		selected := primary
		if len(selected.addresses) == 0 {
			selected = secondary
		}
		if len(selected.addresses) == 0 {
			return nil, fmt.Errorf("family-selector destination %s has no usable A or AAAA record", destination.Fqdn)
		}
		return o.dialOne(ctx, selected.outbound, network, M.SocksaddrFrom(selected.addresses[0], destination.Port))
	}
	var dialErrors []error
	if len(primary.addresses) > 0 {
		connection, errors := o.dialFamily(ctx, primary, network, destination.Port)
		if connection != nil {
			return connection, nil
		}
		dialErrors = append(dialErrors, errors...)
	}
	if o.allowFallback && len(secondary.addresses) > 0 {
		if o.logger != nil {
			o.logger.DebugContext(ctx, "family-selector bounded fallback from ", primary.name, " to ", secondary.name, " for ", destination.Fqdn)
		}
		connection, errors := o.dialFamily(ctx, secondary, network, destination.Port)
		if connection != nil {
			return connection, nil
		}
		dialErrors = append(dialErrors, errors...)
	}
	if len(dialErrors) == 0 {
		return nil, fmt.Errorf("family-selector destination %s has no usable A or AAAA record", destination.Fqdn)
	}
	return nil, E.Cause(E.Errors(dialErrors...), "family-selector could not connect to ", destination)
}

func (o *Outbound) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	ipv4, ipv6, literal, err := o.candidates(ctx, destination)
	if err != nil {
		return nil, err
	}
	if literal {
		if destination.IsIPv4() {
			return o.listenOne(ctx, o.ipv4, destination)
		}
		return o.listenOne(ctx, o.ipv6, destination)
	}
	primary, secondary := o.ordered(ipv4, ipv6)
	selected := primary
	if len(selected.addresses) == 0 {
		selected = secondary
	}
	if len(selected.addresses) == 0 {
		return nil, fmt.Errorf("family-selector destination %s has no usable A or AAAA record", destination.Fqdn)
	}
	return o.listenOne(ctx, selected.outbound, M.SocksaddrFrom(selected.addresses[0], destination.Port))
}

type familyCandidates struct {
	name      string
	outbound  adapter.Outbound
	addresses []netip.Addr
}

func (o *Outbound) ordered(ipv4, ipv6 []netip.Addr) (familyCandidates, familyCandidates) {
	v4 := familyCandidates{name: "IPv4", outbound: o.ipv4, addresses: ipv4}
	v6 := familyCandidates{name: "IPv6", outbound: o.ipv6, addresses: ipv6}
	if o.preferIPv6 {
		return v6, v4
	}
	return v4, v6
}

func (o *Outbound) candidates(ctx context.Context, destination M.Socksaddr) (ipv4, ipv6 []netip.Addr, literal bool, err error) {
	if destination.IsIP() {
		if destination.IsIPv4() {
			return []netip.Addr{destination.Addr}, nil, true, nil
		}
		return nil, []netip.Addr{destination.Addr}, true, nil
	}
	if o.dnsRouter == nil {
		return nil, nil, false, fmt.Errorf("family-selector requires a DNS router for %s", destination.Fqdn)
	}
	addresses, err := o.dnsRouter.Lookup(ctx, destination.Fqdn, o.dnsOptions)
	if err != nil {
		return nil, nil, false, E.Cause(err, "resolve family-selector destination")
	}
	seen := make(map[netip.Addr]bool, len(addresses))
	for _, address := range addresses {
		address = address.Unmap()
		if !address.IsValid() || seen[address] {
			continue
		}
		seen[address] = true
		if address.Is4() {
			if len(ipv4) < maxAddressesPerFamily {
				ipv4 = append(ipv4, address)
			}
		} else if address.Is6() && len(ipv6) < maxAddressesPerFamily {
			ipv6 = append(ipv6, address)
		}
	}
	if len(ipv4) == 0 && len(ipv6) == 0 {
		return nil, nil, false, fmt.Errorf("family-selector destination %s has no A or AAAA record", destination.Fqdn)
	}
	return ipv4, ipv6, false, nil
}

func (o *Outbound) dialFamily(ctx context.Context, family familyCandidates, network string, port uint16) (net.Conn, []error) {
	errors := make([]error, 0, len(family.addresses))
	for _, address := range family.addresses {
		connection, err := o.dialOne(ctx, family.outbound, network, M.SocksaddrFrom(address, port))
		if err == nil {
			return connection, nil
		}
		errors = append(errors, err)
	}
	return nil, errors
}

func (o *Outbound) dialOne(ctx context.Context, child adapter.Outbound, network string, destination M.Socksaddr) (net.Conn, error) {
	childCtx, metadata := adapter.ExtendContext(ctx)
	metadata.Outbound = child.Tag()
	metadata.Destination = destination
	if o.logger != nil {
		o.logger.DebugContext(childCtx, "family-selector ", o.Tag(), " uses ", child.Tag(), " for ", destination)
	}
	connection, err := child.DialContext(childCtx, network, destination)
	if err == nil {
		o.notifySelection(ctx, child)
	}
	return connection, err
}

func (o *Outbound) listenOne(ctx context.Context, child adapter.Outbound, destination M.Socksaddr) (net.PacketConn, error) {
	childCtx, metadata := adapter.ExtendContext(ctx)
	metadata.Outbound = child.Tag()
	metadata.Destination = destination
	if o.logger != nil {
		o.logger.DebugContext(childCtx, "family-selector ", o.Tag(), " uses ", child.Tag(), " for UDP ", destination)
	}
	packetConn, err := child.ListenPacket(childCtx, destination)
	if err == nil {
		o.notifySelection(ctx, child)
	}
	return packetConn, err
}

func (o *Outbound) notifySelection(ctx context.Context, child adapter.Outbound) {
	observer := service.FromContext[SelectionObserver](ctx)
	if observer != nil {
		observer.FamilySelectorSelected(ctx, o.Tag(), child.Tag(), child.Type())
	}
}
