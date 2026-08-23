package agent

import (
	"encoding/json"
	"net"
	"testing"
	"time"

	"github.com/OboardProject/oboard-agent/internal/model"
)

func TestProbeLocalInboundTCPAndUDP(t *testing.T) {
	tcpListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer tcpListener.Close()
	go acceptAndClose(tcpListener)
	tcpPort := tcpListener.Addr().(*net.TCPAddr).Port
	tcpResult := probeLocalInbound(model.InboundProbeTarget{InboundID: 1, Protocol: model.ProtocolVLESS, ListenIP: "127.0.0.1", Port: tcpPort, Transport: "tcp"}, 10, 3, time.Millisecond, time.Second)
	if !tcpResult.Available || !tcpResult.Confirmed || tcpResult.SuccessCount != 3 {
		t.Fatalf("unexpected TCP result: %#v", tcpResult)
	}

	udpListener, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	defer udpListener.Close()
	udpPort := udpListener.LocalAddr().(*net.UDPAddr).Port
	udpResult := probeLocalInbound(model.InboundProbeTarget{InboundID: 2, Protocol: model.ProtocolHY2, ListenIP: "127.0.0.1", Port: udpPort, Transport: "udp"}, 10, 3, time.Millisecond, time.Second)
	if !udpResult.Available || !udpResult.Confirmed || udpResult.SuccessCount != 1 {
		t.Fatalf("unexpected UDP result: %#v", udpResult)
	}
}

func TestProbeForwardUsesMultipleTargetSamples(t *testing.T) {
	listen, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listen.Close()
	go acceptAndClose(listen)
	target, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer target.Close()
	go acceptAndClose(target)

	result := probeForward(model.PortForward{
		ID: 7, Protocol: model.ForwardProtocolTCP, ListenIP: "127.0.0.1",
		ListenPort: listen.Addr().(*net.TCPAddr).Port, TargetAddress: "127.0.0.1", TargetPort: target.Addr().(*net.TCPAddr).Port,
		UpdatedAt: time.Date(2026, time.August, 24, 8, 30, 0, 123000000, time.UTC),
	}, "task")
	if !result.Available || result.SampleCount != defaultProbeSamples {
		t.Fatalf("unexpected forward result: %#v", result)
	}
	var details map[string]any
	if err := json.Unmarshal([]byte(result.ResultJSON), &details); err != nil {
		t.Fatal(err)
	}
	if details["success_count"] != float64(defaultProbeSamples) || details["listener_ok"] != true {
		t.Fatalf("missing multi-sample details: %#v", details)
	}
	if details["forward_updated_at"] != "2026-08-24T08:30:00.123Z" {
		t.Fatalf("missing forward revision marker: %#v", details)
	}
}

func acceptAndClose(listener net.Listener) {
	for {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		_ = conn.Close()
	}
}
