package tlssession

import (
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"os"

	"github.com/ooni/minivpn/internal/runtimex"
	"github.com/ooni/minivpn/pkg/config"

	"crypto/tls"
)

var (
	// ErrBadTLSInit is returned when TLS configuration cannot be initialized
	ErrBadTLSInit = errors.New("TLS init error")

	// ErrBadTLSHandshake is returned when the OpenVPN handshake failed.
	ErrBadTLSHandshake = errors.New("handshake failure")

	// ErrBadCA is returned when the CA file cannot be found or is not valid.
	ErrBadCA = errors.New("bad ca conf")

	// ErrBadKeypair is returned when the key or cert file cannot be found or is not valid.
	ErrBadKeypair = errors.New("bad keypair conf")

	// ErrCannotVerifyCertChain is returned for certificate chain validation errors.
	ErrCannotVerifyCertChain = errors.New("cannot verify chain")
)

// certVerifyOptionsNoCommonNameCheck returns a x509.VerifyOptions initialized with
// an empty string for the DNSName. This allows to skip CN verification.
func certVerifyOptionsNoCommonNameCheck() x509.VerifyOptions {
	return x509.VerifyOptions{DNSName: ""}
}

// certVerifyOptions is the options factory that the customVerify function will
// use; by default it configures VerifyOptions to skip the DNSName check.
var certVerifyOptions = certVerifyOptionsNoCommonNameCheck

// certPaths holds the paths for the cert, key, and ca used for OpenVPN
// certificate authentication.
type certPaths struct {
	certPath string
	keyPath  string
	caPath   string
}

// loadCertAndCAFromPath parses the PEM certificates contained in the paths pointed by
// the passed certPaths and return a certConfig with the client and CA certificates.
func loadCertAndCAFromPath(pth certPaths) (*certConfig, error) {
	ca := x509.NewCertPool()
	caData, err := os.ReadFile(pth.caPath)
	if err != nil {
		return nil, fmt.Errorf("%w: %s", ErrBadCA, err)
	}
	ok := ca.AppendCertsFromPEM(caData)
	if !ok {
		return nil, fmt.Errorf("%w: %s", ErrBadCA, "cannot parse ca cert")
	}

	cfg := &certConfig{ca: ca}
	if pth.certPath != "" && pth.keyPath != "" {
		cert, err := tls.LoadX509KeyPair(pth.certPath, pth.keyPath)
		if err != nil {
			return nil, fmt.Errorf("%w: %s", ErrBadKeypair, err)
		}
		cfg.cert = cert
	}
	return cfg, nil
}

// certBytes holds the byte arrays for the cert, key, and ca used for OpenVPN
// certificate authentication.
type certBytes struct {
	cert []byte
	key  []byte
	ca   []byte
}

// loadCertAndCAFromBytes parses the PEM certificates from the byte arrays in the
// the passed certBytes, and return a certConfig with the client and CA certificates.
func loadCertAndCAFromBytes(crt certBytes) (*certConfig, error) {
	ca := x509.NewCertPool()
	ok := ca.AppendCertsFromPEM(crt.ca)
	if !ok {
		return nil, fmt.Errorf("%w: %s", ErrBadCA, "cannot parse ca cert")
	}
	cfg := &certConfig{ca: ca}
	if crt.cert != nil && crt.key != nil {
		cert, err := tls.X509KeyPair(crt.cert, crt.key)
		if err != nil {
			return nil, fmt.Errorf("%w: %s", ErrBadKeypair, err)
		}
		cfg.cert = cert
	}
	return cfg, nil
}

// authorityPinner is any object from which we can obtain a certpool containing
// a pinned Certificate Authority for verification.
type authorityPinner interface {
	authority() *x509.CertPool
}

// certConfig holds the parsed certificate and CA used for OpenVPN mutual
// certificate authentication.
type certConfig struct {
	cert tls.Certificate
	ca   *x509.CertPool
}

// newCertConfigFromOptions is a constructor that returns a certConfig object initialized
// from the paths specified in the passed Options object, and an error if it
// could not be properly built.
func newCertConfigFromOptions(o *config.OpenVPNOptions) (*certConfig, error) {
	var cfg *certConfig
	var err error

	if o.ShouldLoadCertsFromPath() {
		cfg, err = loadCertAndCAFromPath(certPaths{
			certPath: o.CertPath,
			keyPath:  o.KeyPath,
			caPath:   o.CAPath,
		})
	} else {
		cfg, err = loadCertAndCAFromBytes(certBytes{
			cert: o.Cert,
			key:  o.Key,
			ca:   o.CA,
		})
	}
	return cfg, err
}

// authority implements authorityPinner interface.
func (c *certConfig) authority() *x509.CertPool {
	return c.ca
}

// ensure certConfig implements authorityPinner.
var _ authorityPinner = &certConfig{}

// verifyFun is the type expected by the VerifyPeerCertificate callback in tls.Config.
type verifyFun func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error

// customVerifyFactory returns a verifyFun callback that will verify any received certificates
// against the ca provided by the pased implementation of authorityPinner
func customVerifyFactory(pinner authorityPinner) verifyFun {
	// customVerify is a version of the verification routines that does not try to verify
	// the Common Name, since we don't know it a priori for a VPN gateway. Returns
	// an error if the verification fails.
	// From tls/common documentation: If normal verification is disabled by
	// setting InsecureSkipVerify, [...] then this callback will be considered but
	// the verifiedChains argument will always be nil.
	customVerify := func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
		// we assume (from docs) that we're always given the
		// leaf certificate as the first cert in the array.
		leaf, _ := x509.ParseCertificate(rawCerts[0])
		if leaf == nil {
			return fmt.Errorf("%w: %s", ErrCannotVerifyCertChain, "nothing to verify")
		}
		// By default has DNSName verification disabled.
		opts := certVerifyOptions()
		// Set the configured CA(s) as the certificate pool to verify against.
		opts.Roots = pinner.authority()
		// Servers commonly send their intermediate CA after the leaf; OpenSSL
		// uses it to build the chain, so the verifier must as well.
		opts.Intermediates = x509.NewCertPool()
		for _, raw := range rawCerts[1:] {
			if cert, err := x509.ParseCertificate(raw); err == nil {
				opts.Intermediates.AddCert(cert)
			}
		}

		if _, err := leaf.Verify(opts); err != nil {
			return fmt.Errorf("%w: %s", ErrCannotVerifyCertChain, err)
		}
		return nil
	}
	return customVerify
}

// initTLS returns a tls.Config matching the VPN options. Internally, it uses
// the verify function returned by the global customVerifyFactory,
// verification function since verifying the ServerName does not make sense in
// the context of establishing a VPN session: we perform mutual TLS
// Authentication with the custom CA.
func initTLS(cfg *certConfig) (*tls.Config, error) {
	runtimex.Assert(cfg != nil, "passed nil configuration")

	customVerify := customVerifyFactory(cfg)

	tlsConf := &tls.Config{
		// the certificate we've loaded from the config file
		Certificates: []tls.Certificate{cfg.cert},
		// crypto/tls wants either ServerName or InsecureSkipVerify set ...
		InsecureSkipVerify: true,
		// ...but we pass our own verification function that verifies against the CA and ignores the ServerName
		VerifyPeerCertificate: customVerify,
		MinVersion:            tls.VersionTLS12,
		MaxVersion:            tls.VersionTLS13,
	} //#nosec G402

	return tlsConf, nil
}

// tlsHandshake performs the TLS handshake over the control channel, and return
// the TLS Client as a net.Conn; returns also any error during the handshake.
func tlsHandshake(tlsConn net.Conn, tlsConf *tls.Config) (net.Conn, error) {
	tlsClient, err := tlsFactoryFn(tlsConn, tlsConf)
	if err != nil {
		return nil, err
	}
	if err := tlsClient.Handshake(); err != nil {
		return nil, fmt.Errorf("%w: %s", ErrBadTLSHandshake, err)
	}
	return tlsClient, nil
}

// handshaker is a custom interface that we define here to be able to mock
// the tls.Conn implementation.
type handshaker interface {
	net.Conn
	Handshake() error
}

// defaultTLSFactory returns an implementer of the handshaker interface; that
// is, the default tls.Client factory; and an error.
// we're not using the default factory right now, but it comes handy to be able
// to compare the fingerprints with a golang TLS handshake.
// TODO(ainghazal): implement some sort of test that extracts/compares the TLS client hello.
func defaultTLSFactory(conn net.Conn, config *tls.Config) (handshaker, error) {
	c := tls.Client(conn, config)
	return c, nil
}

// global variables to allow monkeypatching in tests.
var (
	initTLSFn      = initTLS
	tlsFactoryFn   = defaultTLSFactory
	tlsHandshakeFn = tlsHandshake
)
