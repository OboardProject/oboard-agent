package tlssession

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"math/big"
	"net"
	"testing"
	"time"
)

func TestTLSVerifiesConfiguredCA(t *testing.T) {
	now := time.Now()
	issue := func(template, parent *x509.Certificate, signer *ecdsa.PrivateKey) (*x509.Certificate, *ecdsa.PrivateKey) {
		t.Helper()
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		if parent == nil {
			parent, signer = template, key
		}
		der, err := x509.CreateCertificate(rand.Reader, template, parent, &key.PublicKey, signer)
		if err != nil {
			t.Fatal(err)
		}
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			t.Fatal(err)
		}
		return cert, key
	}
	root, rootKey := issue(&x509.Certificate{SerialNumber: big.NewInt(1), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour)}, nil, nil)
	intermediate, intermediateKey := issue(&x509.Certificate{SerialNumber: big.NewInt(2), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour)}, root, rootKey)
	template := &x509.Certificate{SerialNumber: big.NewInt(3), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour)}
	leaf, leafKey := issue(template, intermediate, intermediateKey)
	template.SerialNumber = big.NewInt(4)
	template.NotAfter = now.Add(-time.Minute)
	expired, expiredKey := issue(template, intermediate, intermediateKey)
	template.SerialNumber = big.NewInt(5)
	template.NotAfter = now.Add(time.Hour)
	template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	wrongUsage, wrongKey := issue(template, intermediate, intermediateKey)
	roots := x509.NewCertPool()
	roots.AddCert(root)
	for _, tc := range []struct {
		name     string
		roots    *x509.CertPool
		chain    [][]byte
		key      *ecdsa.PrivateKey
		accepted bool
	}{
		{"trusted chain without DNS name", roots, [][]byte{leaf.Raw, intermediate.Raw}, leafKey, true},
		{"untrusted CA", x509.NewCertPool(), [][]byte{leaf.Raw, intermediate.Raw}, leafKey, false},
		{"missing CA", nil, [][]byte{leaf.Raw, intermediate.Raw}, leafKey, false},
		{"missing intermediate", roots, [][]byte{leaf.Raw}, leafKey, false},
		{"expired", roots, [][]byte{expired.Raw, intermediate.Raw}, expiredKey, false},
		{"wrong key usage", roots, [][]byte{wrongUsage.Raw, intermediate.Raw}, wrongKey, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := initTLS(&certConfig{ca: tc.roots})
			if err != nil {
				t.Fatal(err)
			}
			clientSide, serverSide := net.Pipe()
			defer clientSide.Close()
			defer serverSide.Close()
			_ = clientSide.SetDeadline(time.Now().Add(5 * time.Second))
			_ = serverSide.SetDeadline(time.Now().Add(5 * time.Second))
			done := make(chan struct{})
			go func() {
				defer close(done)
				server := tls.Server(serverSide, &tls.Config{Certificates: []tls.Certificate{{Certificate: tc.chain, PrivateKey: tc.key}}, MinVersion: tls.VersionTLS12})
				_ = server.Handshake()
				_ = serverSide.Close()
			}()
			err = tls.Client(clientSide, cfg).Handshake()
			_ = clientSide.Close()
			<-done
			if (err == nil) != tc.accepted {
				t.Fatalf("handshake error = %v, want accepted=%v", err, tc.accepted)
			}
		})
	}
	verify := customVerifyFactory(&certConfig{ca: roots})
	for _, raw := range [][][]byte{nil, {[]byte("invalid")}, {leaf.Raw, []byte("invalid")}} {
		if err := verify(raw, nil); !errors.Is(err, ErrCannotVerifyCertChain) {
			t.Fatalf("malformed peer error = %v", err)
		}
	}
}
