// SPDX-License-Identifier: GPL-3.0-or-later

package mieru

import (
	"context"
	"errors"
	"net"
	"testing"

	boxoption "github.com/sagernet/sing-box/option"
	M "github.com/sagernet/sing/common/metadata"
)

func TestBuildServerConfigExpandsEveryPort(t *testing.T) {
	factory := &listenerFactory{}
	config, err := buildServerConfig(InboundOptions{
		ListenPortRanges:    []string{"8965-8966"},
		Users:               []User{{Name: "oboard-u7", Password: "secret"}},
		Transport:           "TCP",
		UserHintIsMandatory: true,
		ListenOptions:       boxoption.ListenOptions{ListenPort: 8964},
	}, factory)
	if err != nil {
		t.Fatal(err)
	}
	bindings := config.Config.GetPortBindings()
	if len(bindings) != 3 || bindings[0].GetPort() != 8964 || bindings[2].GetPort() != 8966 {
		t.Fatalf("port bindings = %#v", bindings)
	}
	if config.StreamListenerFactory != factory || config.PacketListenerFactory != factory {
		t.Fatal("sing-box listener factory was not installed")
	}
	if !config.Config.GetAdvancedSettings().GetUserHintIsMandatory() {
		t.Fatal("mandatory user hint was not retained")
	}
}

func TestBuildClientConfigSupportsDomainAndMultiplePorts(t *testing.T) {
	config, err := buildClientConfig(OutboundOptions{
		ServerOptions:    boxoption.ServerOptions{Server: "edge.example.com", ServerPort: 8964},
		ServerPortRanges: []string{"8965-8966"},
		Transport:        "UDP",
		Username:         "oboard-u7",
		Password:         "secret",
		Multiplexing:     "MULTIPLEXING_HIGH",
	}, mieruDialer{dialer: stubDialer{}}, dnsResolver{})
	if err != nil {
		t.Fatal(err)
	}
	server := config.Profile.GetServers()[0]
	if server.GetDomainName() != "edge.example.com" || len(server.GetPortBindings()) != 3 {
		t.Fatalf("client server = %#v", server)
	}
	if config.Resolver == nil || config.DNSConfig == nil || !config.DNSConfig.BypassDialerDNS {
		t.Fatalf("client DNS integration missing: %#v", config)
	}
	if got := config.Profile.GetMultiplexing().GetLevel().String(); got != "MULTIPLEXING_HIGH" {
		t.Fatalf("multiplexing = %s", got)
	}
}

type stubDialer struct{}

func (stubDialer) DialContext(context.Context, string, M.Socksaddr) (net.Conn, error) {
	return nil, errors.New("not implemented")
}

func (stubDialer) ListenPacket(context.Context, M.Socksaddr) (net.PacketConn, error) {
	return nil, errors.New("not implemented")
}
