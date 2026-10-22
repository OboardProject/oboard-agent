package agentlink

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"math/big"
	"strings"
	"testing"
	"time"
)

func TestDialAuthenticatesCertificateBeforeSendingCredentials(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(der)
	for _, tc := range []struct {
		name, pin string
		accepted  bool
	}{
		{"matching self-signed certificate", hex.EncodeToString(digest[:]), true},
		{"wrong certificate", strings.Repeat("0", 64), false},
		{"malformed pin", "invalid", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			listener, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}, MinVersion: tls.VersionTLS13})
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			authReceived := make(chan bool, 1)
			go func() {
				conn, err := listener.Accept()
				if err != nil {
					authReceived <- false
					return
				}
				defer conn.Close()
				_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
				f, err := readFrame(conn)
				authenticated := err == nil && f.frameType == frameTypeAuth
				if authenticated {
					_ = writeFrame(conn, frame{frameType: frameTypeAuthOK, flags: flagPayloadJSON, payload: []byte("{}")})
				}
				authReceived <- authenticated
			}()
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			session, err := Dial(ctx, ClientConfig{Address: listener.Addr().String(), CertSHA256: tc.pin, AgentID: "test", Token: "test-secret"})
			if session != nil {
				_ = session.conn.Close()
			}
			if (err == nil) != tc.accepted {
				t.Errorf("Dial error = %v, want accepted=%v", err, tc.accepted)
			}
			if got := <-authReceived; got != tc.accepted {
				t.Errorf("credentials sent = %v, want %v", got, tc.accepted)
			}
		})
	}
}

func TestDialRejectsMissingTrustBeforeConnecting(t *testing.T) {
	if _, err := Dial(context.Background(), ClientConfig{Address: "127.0.0.1:1", Token: "test-secret"}); err == nil || !strings.Contains(err.Error(), "requires a certificate pin") {
		t.Fatalf("unexpected error: %v", err)
	}
}
