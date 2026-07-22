package agent

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"testing"
	"time"

	"github.com/OboardProject/oboard-agent/internal/model"
	"golang.org/x/net/dns/dnsmessage"
)

func TestResolveDNSBenchmarkHostOverUDPAndTCP(t *testing.T) {
	for _, network := range []string{"udp", "tcp"} {
		t.Run(network, func(t *testing.T) {
			address, closeServer := startDNSBenchmarkTestServer(t, network)
			defer closeServer()
			host, portText, err := net.SplitHostPort(address)
			if err != nil {
				t.Fatal(err)
			}
			port, _ := net.LookupPort(network, portText)
			candidate := model.DNSCandidate{Tag: network, Transport: model.DNSTransport(network), Server: host, Port: port}
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			got, err := resolveDNSBenchmarkHost(ctx, candidate, "resolver.example", time.Second)
			if err != nil {
				t.Fatal(err)
			}
			if got != "203.0.113.9" {
				t.Fatalf("resolved address = %q", got)
			}
		})
	}
}

func TestDNSBenchmarkPlanKeyIncludesEveryRevision(t *testing.T) {
	base := testDNSBenchmarkPlan()
	keys := map[string]bool{dnsBenchmarkPlanKey(base): true}
	variants := []model.DNSBenchmarkPlan{base, base, base}
	variants[0].PolicyRevision++
	variants[1].EncryptedListRevision++
	variants[2].BootstrapListRevision++
	for _, variant := range variants {
		key := dnsBenchmarkPlanKey(variant)
		if keys[key] {
			t.Fatalf("revision change reused state key %q", key)
		}
		keys[key] = true
	}
}

func TestDNSBenchmarkNeverClearsPeriodicState(t *testing.T) {
	runner := New(Config{StateDir: t.TempDir(), ResourceProfile: "large"})
	periodic := testDNSBenchmarkPlan()
	periodic.Mode = model.DNSAutoTestPeriodic
	state := dnsBenchmarkLocalState{
		LastRun: map[string]time.Time{dnsBenchmarkPlanKey(periodic): time.Now().UTC()},
		Policy:  &periodic,
		Best:    map[string]model.DNSBenchmarkGroup{"old": {BestTags: []string{"old"}}},
	}
	if err := runner.saveDNSBenchmarkState(state); err != nil {
		t.Fatal(err)
	}
	if _, err := runner.runDNSBenchmarkTask(context.Background(), model.DNSBenchmarkPlan{ServerID: periodic.ServerID, Mode: model.DNSAutoTestNever}, true); err != nil {
		t.Fatal(err)
	}
	stored, err := runner.loadDNSBenchmarkState()
	if err != nil {
		t.Fatal(err)
	}
	if stored.Policy != nil || len(stored.LastRun) != 0 || len(stored.Best) != 0 {
		t.Fatalf("periodic state was not cleared: %#v", stored)
	}
}

func startDNSBenchmarkTestServer(t *testing.T, network string) (string, func()) {
	t.Helper()
	if network == "udp" {
		conn, err := net.ListenPacket("udp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		go func() {
			buffer := make([]byte, 4096)
			n, peer, err := conn.ReadFrom(buffer)
			if err != nil {
				return
			}
			response, err := dnsBenchmarkTestResponse(buffer[:n])
			if err == nil {
				_, _ = conn.WriteTo(response, peer)
			}
		}()
		return conn.LocalAddr().String(), func() { _ = conn.Close() }
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		var size [2]byte
		if _, err := io.ReadFull(conn, size[:]); err != nil {
			return
		}
		query := make([]byte, int(binary.BigEndian.Uint16(size[:])))
		if _, err := io.ReadFull(conn, query); err != nil {
			return
		}
		response, err := dnsBenchmarkTestResponse(query)
		if err != nil {
			return
		}
		packet := make([]byte, len(response)+2)
		binary.BigEndian.PutUint16(packet, uint16(len(response)))
		copy(packet[2:], response)
		_, _ = conn.Write(packet)
	}()
	return listener.Addr().String(), func() { _ = listener.Close() }
}

func dnsBenchmarkTestResponse(query []byte) ([]byte, error) {
	var parser dnsmessage.Parser
	header, err := parser.Start(query)
	if err != nil {
		return nil, err
	}
	question, err := parser.Question()
	if err != nil {
		return nil, err
	}
	builder := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: header.ID, Response: true, RecursionAvailable: true})
	builder.EnableCompression()
	if err := builder.StartQuestions(); err != nil {
		return nil, err
	}
	if err := builder.Question(question); err != nil {
		return nil, err
	}
	if err := builder.StartAnswers(); err != nil {
		return nil, err
	}
	if err := builder.AResource(dnsmessage.ResourceHeader{Name: question.Name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET, TTL: 60}, dnsmessage.AResource{A: [4]byte{203, 0, 113, 9}}); err != nil {
		return nil, err
	}
	return builder.Finish()
}
