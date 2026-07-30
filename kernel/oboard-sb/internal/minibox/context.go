package minibox

import (
	"context"

	box "github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/adapter/endpoint"
	"github.com/sagernet/sing-box/adapter/inbound"
	"github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/adapter/service"
	"github.com/sagernet/sing-box/dns"
	dnsTransport "github.com/sagernet/sing-box/dns/transport"
	dnsHosts "github.com/sagernet/sing-box/dns/transport/hosts"
	dnsLocal "github.com/sagernet/sing-box/dns/transport/local"
	"github.com/sagernet/sing-box/protocol/anytls"
	"github.com/sagernet/sing-box/protocol/block"
	"github.com/sagernet/sing-box/protocol/direct"
	outboundDNS "github.com/sagernet/sing-box/protocol/dns"
	"github.com/sagernet/sing-box/protocol/hysteria2"
	"github.com/sagernet/sing-box/protocol/shadowsocks"
	"github.com/sagernet/sing-box/protocol/socks"
	"github.com/sagernet/sing-box/protocol/vless"
	"github.com/sagernet/sing-box/protocol/wireguard"

	"github.com/OboardProject/oboard-agent/kernel/oboard-sb/internal/protocol/mieru"
)

// SupportedProtocols is the intentionally small protocol surface exposed by the
// OBoard sing-box kernel. Do not add protocols here unless the Controller can
// generate, validate, audit, and subscribe them.
var SupportedProtocols = []string{"vless", "hysteria2", "anytls", "shadowsocks", "mieru", "socks", "wireguard"}

// Context returns a sing-box context with only the inbounds/outbounds that
// OBoard supports in the first kernel line: VLESS, HY2, AnyTLS, and SS.
//
// This mirrors the mini-sb-agent optimisation approach: instead of importing
// sing-box's full command and default registry, we construct a minimal registry.
func Context(parent context.Context) context.Context {
	inbounds := inbound.NewRegistry()
	vless.RegisterInbound(inbounds)
	hysteria2.RegisterInbound(inbounds)
	anytls.RegisterInbound(inbounds)
	shadowsocks.RegisterInbound(inbounds)
	mieru.RegisterInbound(inbounds)

	outbounds := outbound.NewRegistry()
	direct.RegisterOutbound(outbounds)
	block.RegisterOutbound(outbounds)
	outboundDNS.RegisterOutbound(outbounds)
	vless.RegisterOutbound(outbounds)
	hysteria2.RegisterOutbound(outbounds)
	anytls.RegisterOutbound(outbounds)
	shadowsocks.RegisterOutbound(outbounds)
	mieru.RegisterOutbound(outbounds)
	socks.RegisterOutbound(outbounds)

	endpoints := endpoint.NewRegistry()
	wireguard.RegisterEndpoint(endpoints)

	dnsTransports := dns.NewTransportRegistry()
	dnsTransport.RegisterUDP(dnsTransports)
	dnsTransport.RegisterTCP(dnsTransports)
	dnsTransport.RegisterTLS(dnsTransports)
	dnsTransport.RegisterHTTPS(dnsTransports)
	dnsLocal.RegisterTransport(dnsTransports)
	dnsHosts.RegisterTransport(dnsTransports)

	return box.Context(parent, inbounds, outbounds, endpoints, dnsTransports, service.NewRegistry())
}
