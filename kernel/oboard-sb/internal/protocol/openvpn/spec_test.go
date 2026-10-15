package openvpn

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"strings"
	"testing"
	"time"
)

func testPEM(t *testing.T) (string, string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "t"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, _ := x509.MarshalPKCS8PrivateKey(key)
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})), string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}))
}

func validSpec(t *testing.T) Spec {
	cert, key := testPEM(t)
	return Spec{Server: "219.100.37.14", ServerPort: 443, Network: "TCP", Cipher: "aes-128-cbc", Auth: "sha1", CA: cert, Cert: cert, Key: key}
}

func TestSpecNormalizeDefaults(t *testing.T) {
	spec := validSpec(t)
	if err := spec.Normalize(); err != nil {
		t.Fatal(err)
	}
	if spec.Network != "tcp" || spec.Cipher != "AES-128-CBC" || spec.Auth != "SHA1" || spec.MTU != DefaultMTU || len(spec.Resolvers) != 2 {
		t.Fatalf("defaults not applied: %+v", spec)
	}
}

func TestSpecNormalizeRejects(t *testing.T) {
	cases := map[string]func(*Spec){
		"domain server":     func(s *Spec) { s.Server = "vpn.example.com" },
		"private server":    func(s *Spec) { s.Server = "10.0.0.1" },
		"loopback server":   func(s *Spec) { s.Server = "127.0.0.1" },
		"ipv6 server":       func(s *Spec) { s.Server = "2001:db8::1" },
		"zero port":         func(s *Spec) { s.ServerPort = 0 },
		"bad network":       func(s *Spec) { s.Network = "sctp" },
		"bad cipher":        func(s *Spec) { s.Cipher = "BF-CBC" },
		"bad auth":          func(s *Spec) { s.Auth = "MD5" },
		"bad ca":            func(s *Spec) { s.CA = "not pem" },
		"mismatched key":    func(s *Spec) { _, other := testPEM(t); s.Key = other },
		"credential cr":     func(s *Spec) { s.Username = "vpn\r\nx" },
		"credential length": func(s *Spec) { s.Password = strings.Repeat("x", 200) },
		"tiny mtu":          func(s *Spec) { s.MTU = 100 },
		"ipv6 resolver":     func(s *Spec) { s.Resolvers = []string{"2001:4860:4860::8888"} },
		"too many resolver": func(s *Spec) { s.Resolvers = []string{"1.1.1.1", "1.0.0.1", "8.8.8.8", "8.8.4.4", "9.9.9.9"} },
	}
	for name, mutate := range cases {
		spec := validSpec(t)
		mutate(&spec)
		if err := spec.Normalize(); err == nil {
			t.Errorf("%s: expected rejection", name)
		}
	}
}
