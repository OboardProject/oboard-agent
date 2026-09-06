package minibox

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	mDNS "github.com/miekg/dns"
	"github.com/sagernet/quic-go"
	box "github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/dns/transport"
	"github.com/sagernet/sing/service"
)

func TestDoQActiveKernelQuery(t *testing.T) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cert := &x509.Certificate{SerialNumber: big.NewInt(1), DNSNames: []string{"dns.test"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, cert, cert, public, private)
	if err != nil {
		t.Fatal(err)
	}
	listener, err := quic.ListenAddr("127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: private}}, NextProtos: []string{"doq"}, MinVersion: tls.VersionTLS13}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	served := make(chan error, 1)
	go func() {
		conn, err := listener.Accept(ctx)
		if err != nil {
			served <- err
			return
		}
		stream, err := conn.AcceptStream(ctx)
		if err != nil {
			served <- err
			return
		}
		defer stream.Close()
		request, err := transport.ReadMessage(stream)
		if err != nil {
			served <- err
			return
		}
		response := new(mDNS.Msg).SetReply(request)
		response.Answer = []mDNS.RR{&mDNS.A{Hdr: mDNS.RR_Header{Name: request.Question[0].Name, Rrtype: mDNS.TypeA, Class: mDNS.ClassINET, Ttl: 60}, A: net.IPv4(192, 0, 2, 42)}}
		wire, err := response.Pack()
		if err != nil {
			served <- err
			return
		}
		frame := binary.BigEndian.AppendUint16(nil, uint16(len(wire)))
		_, err = stream.Write(append(frame, wire...))
		served <- err
	}()
	defer func() {
		cancel()
		listener.Close()
		if err := <-served; err != nil && !t.Failed() {
			t.Error(err)
		}
	}()
	raw, err := json.Marshal(map[string]any{"dns": map[string]any{"servers": []any{map[string]any{"type": "quic", "tag": "test-doq", "server": "127.0.0.1", "server_port": listener.Addr().(*net.UDPAddr).Port, "tls": map[string]any{"enabled": true, "server_name": "dns.test", "certificate": []string{string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))}}}}, "final": "test-doq"}, "outbounds": []any{map[string]any{"type": "direct", "tag": "direct"}}})
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	opts, _, err := LoadConfig(path, HY2Tuning{})
	if err != nil {
		t.Fatal(err)
	}
	kernelCtx := Context(ctx)
	instance, err := box.New(box.Options{Context: kernelCtx, Options: opts})
	if err != nil {
		t.Fatal(err)
	}
	defer instance.Close()
	if err := instance.Start(); err != nil {
		t.Fatal(err)
	}
	answer, err := service.FromContext[adapter.DNSRouter](kernelCtx).Exchange(ctx, new(mDNS.Msg).SetQuestion("service.test.", mDNS.TypeA), adapter.DNSQueryOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if len(answer.Answer) != 1 || answer.Answer[0].(*mDNS.A).A.String() != "192.0.2.42" {
		t.Fatalf("unexpected DNS answer: %v", answer)
	}
}
