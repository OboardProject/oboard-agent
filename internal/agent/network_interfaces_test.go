package agent

import (
	"errors"
	"net"
	"strings"
	"testing"

	"github.com/OboardProject/oboard-agent/internal/model"
)

type testNetworkAddress string

func (address testNetworkAddress) Network() string { return "ip" }
func (address testNetworkAddress) String() string  { return string(address) }

func TestCollectNetworkInterfacesNormalizesAndSorts(t *testing.T) {
	interfaces := []net.Interface{
		{Index: 1, Name: "lo", Flags: net.FlagUp | net.FlagLoopback | net.FlagRunning},
		{Index: 3, Name: "eth1"},
		{Index: 2, Name: "eth0", Flags: net.FlagUp | net.FlagRunning},
	}
	addresses := map[int][]net.Addr{
		1: {testNetworkAddress("127.0.0.1/8")},
		2: {testNetworkAddress("2001:db8::10/64"), testNetworkAddress("192.0.2.10/24"), testNetworkAddress("192.0.2.10/24")},
	}
	got, err := collectNetworkInterfaces(interfaces, func(iface net.Interface) ([]net.Addr, error) {
		return addresses[iface.Index], nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 || got[0].Name != "eth0" || got[1].Name != "eth1" || got[2].Name != "lo" {
		t.Fatalf("unexpected interface order: %#v", got)
	}
	if !got[0].Up || !got[0].Running || got[0].Loopback {
		t.Fatalf("unexpected eth0 state: %#v", got[0])
	}
	wantAddresses := []string{"192.0.2.10/24", "2001:db8::10/64"}
	if strings.Join(got[0].Addresses, ",") != strings.Join(wantAddresses, ",") {
		t.Fatalf("eth0 addresses = %#v, want %#v", got[0].Addresses, wantAddresses)
	}
}

func TestCollectNetworkInterfacesRejectsInvalidData(t *testing.T) {
	if _, err := collectNetworkInterfaces([]net.Interface{{Name: "eth0;id"}}, func(net.Interface) ([]net.Addr, error) { return nil, nil }); err == nil {
		t.Fatal("invalid interface name was accepted")
	}
	if _, err := collectNetworkInterfaces([]net.Interface{{Name: "eth0"}}, func(net.Interface) ([]net.Addr, error) {
		return nil, errors.New("address lookup failed")
	}); err == nil || !strings.Contains(err.Error(), "address lookup failed") {
		t.Fatalf("address lookup error = %v", err)
	}
}

func TestListNetworkInterfacesTask(t *testing.T) {
	r := New(Config{})
	status, result := r.ExecuteAgentTask(model.AgentTask{Type: model.AgentTaskTypeListNetworkInterfaces, PayloadJSON: `{}`})
	if status != "succeeded" || !strings.Contains(result, `"interfaces"`) {
		t.Fatalf("network interface task status=%q result=%s", status, result)
	}
}
