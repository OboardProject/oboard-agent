// SPDX-License-Identifier: GPL-3.0-or-later

package familyselector

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"strconv"
	"testing"

	"github.com/miekg/dns"
	"github.com/sagernet/sing-box/adapter"
	adapterOutbound "github.com/sagernet/sing-box/adapter/outbound"
	C "github.com/sagernet/sing-box/constant"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

func TestTCPDomainFallbackSwitchesOutboundOnce(t *testing.T) {
	ipv4 := &testOutbound{tag: "path-v4", failDial: true}
	ipv6 := &testOutbound{tag: "path-v6"}
	resolver := &testDNSRouter{addresses: []netip.Addr{
		netip.MustParseAddr("198.51.100.4"),
		netip.MustParseAddr("198.51.100.5"),
		netip.MustParseAddr("2001:db8::6"),
	}}
	selector := testSelector(ipv4, ipv6, resolver, false)
	connection, err := selector.DialContext(context.Background(), N.NetworkTCP, M.Socksaddr{Fqdn: "dual.example", Port: 443})
	if err != nil {
		t.Fatal(err)
	}
	_ = connection.Close()
	if len(ipv4.dials) != 2 || len(ipv6.dials) != 1 {
		t.Fatalf("dial attempts v4=%v v6=%v", ipv4.dials, ipv6.dials)
	}
	if !ipv4.dials[0].IsIPv4() || !ipv4.dials[1].IsIPv4() || !ipv6.dials[0].IsIPv6() {
		t.Fatalf("family routing mismatch v4=%v v6=%v", ipv4.dials, ipv6.dials)
	}
	if ipv4.metadataTags[0] != ipv4.tag || ipv6.metadataTags[0] != ipv6.tag {
		t.Fatalf("selected child audit tags v4=%v v6=%v", ipv4.metadataTags, ipv6.metadataTags)
	}
	if resolver.lookups != 1 || resolver.lastOptions.Strategy != C.DomainStrategyPreferIPv4 {
		t.Fatalf("DNS lookups=%d strategy=%d", resolver.lookups, resolver.lastOptions.Strategy)
	}
}

func TestLiteralFailureNeverCrossesFamily(t *testing.T) {
	ipv4 := &testOutbound{tag: "path-v4", failDial: true}
	ipv6 := &testOutbound{tag: "path-v6"}
	selector := testSelector(ipv4, ipv6, &testDNSRouter{}, false)
	_, err := selector.DialContext(context.Background(), N.NetworkTCP, M.SocksaddrFrom(netip.MustParseAddr("198.51.100.8"), 443))
	if err == nil {
		t.Fatal("IPv4 literal failure unexpectedly succeeded")
	}
	if len(ipv4.dials) != 1 || len(ipv6.dials) != 0 {
		t.Fatalf("literal crossed family: v4=%v v6=%v", ipv4.dials, ipv6.dials)
	}
}

func TestUDPSelectsOneFamilyAtAssociationCreation(t *testing.T) {
	ipv4 := &testOutbound{tag: "path-v4"}
	ipv6 := &testOutbound{tag: "path-v6"}
	resolver := &testDNSRouter{addresses: []netip.Addr{netip.MustParseAddr("198.51.100.8"), netip.MustParseAddr("2001:db8::8")}}
	selector := testSelector(ipv4, ipv6, resolver, true)
	packetConn, err := selector.ListenPacket(context.Background(), M.Socksaddr{Fqdn: "udp.example", Port: 53})
	if err != nil {
		t.Fatal(err)
	}
	_ = packetConn.Close()
	if len(ipv4.packets) != 0 || len(ipv6.packets) != 1 || !ipv6.packets[0].IsIPv6() {
		t.Fatalf("UDP family selection v4=%v v6=%v", ipv4.packets, ipv6.packets)
	}
}

func TestCandidateResolutionRetainsBothFamiliesAndBoundsResults(t *testing.T) {
	addresses := make([]netip.Addr, 0, 24)
	for index := 1; index <= 12; index++ {
		addresses = append(addresses, netip.MustParseAddr("198.51.100."+strconv.Itoa(index)))
		addresses = append(addresses, netip.MustParseAddr("2001:db8::"+strconv.Itoa(index)))
	}
	addresses = append(addresses, addresses[0])
	selector := testSelector(&testOutbound{tag: "v4"}, &testOutbound{tag: "v6"}, &testDNSRouter{addresses: addresses}, false)
	ipv4, ipv6, literal, err := selector.candidates(context.Background(), M.Socksaddr{Fqdn: "bounded.example", Port: 443})
	if err != nil {
		t.Fatal(err)
	}
	if literal || len(ipv4) != maxAddressesPerFamily || len(ipv6) != maxAddressesPerFamily {
		t.Fatalf("bounded candidates literal=%v v4=%d v6=%d", literal, len(ipv4), len(ipv6))
	}
}

func testSelector(ipv4, ipv6 *testOutbound, resolver *testDNSRouter, preferIPv6 bool) *Outbound {
	strategy := C.DomainStrategyPreferIPv4
	if preferIPv6 {
		strategy = C.DomainStrategyPreferIPv6
	}
	return &Outbound{
		Adapter:       adapterOutbound.NewAdapter(Type, "family", []string{N.NetworkTCP, N.NetworkUDP}, []string{ipv4.tag, ipv6.tag}),
		ipv4:          ipv4,
		ipv6:          ipv6,
		dnsRouter:     resolver,
		dnsOptions:    adapter.DNSQueryOptions{Strategy: strategy, LookupStrategy: strategy},
		preferIPv6:    preferIPv6,
		allowFallback: true,
	}
}

type testOutbound struct {
	tag          string
	failDial     bool
	dials        []M.Socksaddr
	packets      []M.Socksaddr
	metadataTags []string
}

func (o *testOutbound) Type() string           { return "test" }
func (o *testOutbound) Tag() string            { return o.tag }
func (o *testOutbound) Network() []string      { return []string{N.NetworkTCP, N.NetworkUDP} }
func (o *testOutbound) Dependencies() []string { return nil }
func (o *testOutbound) DialContext(ctx context.Context, _ string, destination M.Socksaddr) (net.Conn, error) {
	o.dials = append(o.dials, destination)
	if metadata := adapter.ContextFrom(ctx); metadata != nil {
		o.metadataTags = append(o.metadataTags, metadata.Outbound)
	}
	if o.failDial {
		return nil, errors.New("dial failed")
	}
	local, remote := net.Pipe()
	_ = remote.Close()
	return local, nil
}
func (o *testOutbound) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	o.packets = append(o.packets, destination)
	if metadata := adapter.ContextFrom(ctx); metadata != nil {
		o.metadataTags = append(o.metadataTags, metadata.Outbound)
	}
	return net.ListenPacket("udp", "127.0.0.1:0")
}

type testDNSRouter struct {
	addresses   []netip.Addr
	lookups     int
	lastOptions adapter.DNSQueryOptions
}

func (r *testDNSRouter) Start(adapter.StartStage) error { return nil }
func (r *testDNSRouter) Close() error                   { return nil }
func (r *testDNSRouter) Exchange(context.Context, *dns.Msg, adapter.DNSQueryOptions) (*dns.Msg, error) {
	return nil, errors.New("not implemented")
}
func (r *testDNSRouter) ExchangeAsync(_ context.Context, _ *dns.Msg, _ adapter.DNSQueryOptions, callback func(*dns.Msg, error)) {
	callback(nil, errors.New("not implemented"))
}
func (r *testDNSRouter) Lookup(_ context.Context, _ string, options adapter.DNSQueryOptions) ([]netip.Addr, error) {
	r.lookups++
	r.lastOptions = options
	return append([]netip.Addr(nil), r.addresses...), nil
}
func (r *testDNSRouter) ClearCache()                                    {}
func (r *testDNSRouter) LookupReverseMapping(netip.Addr) (string, bool) { return "", false }
func (r *testDNSRouter) ResetNetwork()                                  {}
