package netdiag

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"math"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/url"
	"os"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/OboardProject/oboard-agent/internal/model"
)

const httpProbeBodyLimit = 64 << 10

// Dialer abstracts net.Dialer for tests.
type Dialer interface {
	DialContext(ctx context.Context, network, address string) (net.Conn, error)
}

func errorClass(err error) string {
	var netErr net.Error
	switch {
	case err == nil:
		return ""
	case errors.Is(err, context.DeadlineExceeded) || errors.As(err, &netErr) && netErr.Timeout():
		return "timeout"
	case errors.Is(err, syscall.ECONNREFUSED):
		return "refused"
	case errors.Is(err, syscall.ECONNRESET):
		return "reset"
	case errors.Is(err, syscall.EHOSTUNREACH) || errors.Is(err, syscall.ENETUNREACH):
		return "unreachable"
	case errors.Is(err, os.ErrDeadlineExceeded):
		return "timeout"
	default:
		var dnsErr *net.DNSError
		if errors.As(err, &dnsErr) {
			if dnsErr.IsNotFound {
				return "nxdomain"
			}
			return "dns_failed"
		}
		var certErr *tls.CertificateVerificationError
		if errors.As(err, &certErr) {
			return "tls_failed"
		}
		if strings.Contains(err.Error(), "tls:") {
			return "tls_failed"
		}
		return "network_error"
	}
}

func ValidateTCPProbe(p model.NetworkTCPProbeTaskPayload) error {
	switch {
	case !validFamily(p.IPFamily):
		return invalid("ip_family must be auto, ipv4 or ipv6")
	case p.Port < 1 || p.Port > 65535:
		return invalid("port is out of range")
	case p.TimeoutMS < 100 || p.TimeoutMS > model.TCPProbeMaxTimeoutMS:
		return invalid("timeout_ms is out of range")
	}
	return nil
}

// TCPProbe measures one TCP connect to a public address. A refused or timed
// out connection is a result, not a task failure.
func TCPProbe(ctx context.Context, resolver Resolver, dialer Dialer, p model.NetworkTCPProbeTaskPayload) (model.NetworkTCPProbeResult, error) {
	result := model.NetworkTCPProbeResult{OperationID: p.OperationID, Host: p.Host, Port: p.Port}
	if err := ValidateTCPProbe(p); err != nil {
		return result, err
	}
	ip, err := ResolveTarget(ctx, resolver, p.Host, p.IPFamily)
	if err != nil {
		if CodeOf(err) == model.NetworkDiagnosticCodeResolveFailed {
			result.ErrorClass = "dns_failed"
			return result, nil
		}
		return result, err
	}
	result.ResolvedIP, result.IPFamily = ip.String(), familyName(ip)
	dialCtx, cancel := context.WithTimeout(ctx, time.Duration(p.TimeoutMS)*time.Millisecond)
	defer cancel()
	started := time.Now()
	conn, err := dialer.DialContext(dialCtx, "tcp", net.JoinHostPort(ip.String(), strconv.Itoa(p.Port)))
	if err != nil {
		result.ErrorClass = errorClass(err)
		return result, nil
	}
	_ = conn.Close()
	result.Connected = true
	result.ConnectMS = roundMS(time.Since(started))
	return result, nil
}

func ValidateDNSLookup(p model.NetworkDNSLookupTaskPayload) error {
	if !ValidHostname(p.Name) {
		return invalid("name must be a public DNS name")
	}
	if len(p.RecordTypes) == 0 || len(p.RecordTypes) > 2 {
		return invalid("record_types must contain A and/or AAAA")
	}
	for _, item := range p.RecordTypes {
		if item != "A" && item != "AAAA" {
			return invalid("record_types must contain A and/or AAAA")
		}
	}
	if p.TimeoutMS < 100 || p.TimeoutMS > model.DNSLookupMaxTimeoutMS {
		return invalid("timeout_ms is out of range")
	}
	return nil
}

// DNSLookup resolves A/AAAA records with the host resolver.
func DNSLookup(ctx context.Context, resolver Resolver, p model.NetworkDNSLookupTaskPayload) (model.NetworkDNSLookupResult, error) {
	result := model.NetworkDNSLookupResult{OperationID: p.OperationID, Name: p.Name, Records: []model.NetworkDNSRecord{}}
	if err := ValidateDNSLookup(p); err != nil {
		return result, err
	}
	lookupCtx, cancel := context.WithTimeout(ctx, time.Duration(p.TimeoutMS)*time.Millisecond)
	defer cancel()
	started := time.Now()
	var lastErr error
	for _, recordType := range p.RecordTypes {
		network := "ip4"
		if recordType == "AAAA" {
			network = "ip6"
		}
		addresses, err := resolver.LookupNetIP(lookupCtx, network, p.Name)
		if err != nil {
			lastErr = err
			continue
		}
		for i, address := range addresses {
			if i >= 32 {
				break
			}
			address = address.Unmap()
			if recordType == "A" && !address.Is4() || recordType == "AAAA" && !address.Is6() {
				continue
			}
			result.Records = append(result.Records, model.NetworkDNSRecord{Type: recordType, Address: address.String()})
		}
	}
	result.DurationMS = roundMS(time.Since(started))
	if len(result.Records) == 0 && lastErr != nil {
		result.ErrorClass = errorClass(lastErr)
	}
	return result, nil
}

func ValidateHTTPProbe(p model.NetworkHTTPProbeTaskPayload) (*url.URL, error) {
	if !validFamily(p.IPFamily) {
		return nil, invalid("ip_family must be auto, ipv4 or ipv6")
	}
	if p.Method != http.MethodGet && p.Method != http.MethodHead {
		return nil, invalid("method must be GET or HEAD")
	}
	if p.TimeoutMS < 500 || p.TimeoutMS > model.HTTPProbeMaxTimeoutMS {
		return nil, invalid("timeout_ms is out of range")
	}
	return validateProbeURL(p.URL)
}

func validateProbeURL(raw string) (*url.URL, error) {
	if raw == "" || len(raw) > model.NetworkURLMaxBytes || strings.ContainsAny(raw, "#\r\n\t ") {
		return nil, invalid("url is invalid")
	}
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil || u.Opaque != "" {
		return nil, invalid("url must be an absolute http(s) URL without credentials")
	}
	if _, err := NormalizeTarget(u.Hostname()); err != nil {
		return nil, err
	}
	if port := u.Port(); port != "" {
		if n, err := strconv.Atoi(port); err != nil || n < 1 || n > 65535 {
			return nil, invalid("url port is invalid")
		}
	}
	return u, nil
}

// HTTPProbe performs one GET or HEAD from this server. It returns status,
// timings and TLS facts only; the body is read up to 64 KiB and discarded.
// Every connection (including after a redirect) dials a freshly validated
// public address, so the probe cannot reach the node's private networks.
func HTTPProbe(ctx context.Context, resolver Resolver, dialer Dialer, p model.NetworkHTTPProbeTaskPayload) (model.NetworkHTTPProbeResult, error) {
	result := model.NetworkHTTPProbeResult{OperationID: p.OperationID, URL: p.URL}
	target, err := ValidateHTTPProbe(p)
	if err != nil {
		return result, err
	}
	probeCtx, cancel := context.WithTimeout(ctx, time.Duration(p.TimeoutMS)*time.Millisecond)
	defer cancel()
	var resolvedFirst string
	transport := &http.Transport{
		Proxy:               nil,
		DisableKeepAlives:   true,
		DisableCompression:  true,
		TLSHandshakeTimeout: time.Duration(p.TimeoutMS) * time.Millisecond,
		TLSClientConfig:     &tls.Config{MinVersion: tls.VersionTLS12},
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			host, port, err := net.SplitHostPort(address)
			if err != nil {
				return nil, err
			}
			ip, err := ResolveTarget(ctx, resolver, host, p.IPFamily)
			if err != nil {
				return nil, err
			}
			if resolvedFirst == "" {
				resolvedFirst = ip.String()
			}
			return dialer.DialContext(ctx, "tcp", net.JoinHostPort(ip.String(), port))
		},
	}
	defer transport.CloseIdleConnections()
	redirects := 0
	client := &http.Client{Transport: transport, CheckRedirect: func(next *http.Request, via []*http.Request) error {
		if !p.FollowRedirects {
			return http.ErrUseLastResponse
		}
		if len(via) > model.HTTPProbeMaxRedirects {
			return errors.New("too many redirects")
		}
		if _, err := validateProbeURL(next.URL.String()); err != nil {
			return err
		}
		redirects = len(via)
		return nil
	}}
	request, err := http.NewRequestWithContext(probeCtx, p.Method, target.String(), nil)
	if err != nil {
		return result, invalid("url is invalid")
	}
	request.Header.Set("User-Agent", "OBoard-Probe/1")
	var dnsStart, connectStart, tlsStart, firstByte time.Time
	var dnsMS, connectMS, tlsMS float64
	started := time.Now()
	request = request.WithContext(httptrace.WithClientTrace(probeCtx, &httptrace.ClientTrace{
		DNSStart:             func(httptrace.DNSStartInfo) { dnsStart = time.Now() },
		DNSDone:              func(httptrace.DNSDoneInfo) { dnsMS = sinceMS(dnsStart) },
		ConnectStart:         func(string, string) { connectStart = time.Now() },
		ConnectDone:          func(string, string, error) { connectMS = sinceMS(connectStart) },
		TLSHandshakeStart:    func() { tlsStart = time.Now() },
		TLSHandshakeDone:     func(tls.ConnectionState, error) { tlsMS = sinceMS(tlsStart) },
		GotFirstResponseByte: func() { firstByte = time.Now() },
	}))
	response, err := client.Do(request)
	result.ResolvedIP = resolvedFirst
	result.Redirects = redirects
	if err != nil {
		var diag *Error
		if errors.As(err, &diag) && diag.Code == model.NetworkDiagnosticCodeTargetNotAllowed {
			return result, diag
		}
		result.ErrorClass = errorClass(err)
		result.Timings = model.NetworkHTTPTimings{DNSMS: dnsMS, ConnectMS: connectMS, TLSMS: tlsMS, TotalMS: sinceMS(started)}
		return result, nil
	}
	defer response.Body.Close()
	read, _ := io.Copy(io.Discard, io.LimitReader(response.Body, httpProbeBodyLimit))
	result.StatusCode = response.StatusCode
	result.BodyBytes = read
	result.FinalURL = response.Request.URL.String()
	ttfb := 0.0
	if !firstByte.IsZero() {
		ttfb = roundMS(firstByte.Sub(started))
	}
	result.Timings = model.NetworkHTTPTimings{DNSMS: dnsMS, ConnectMS: connectMS, TLSMS: tlsMS, TTFBMS: ttfb, TotalMS: sinceMS(started)}
	if response.TLS != nil {
		info := &model.NetworkHTTPTLS{Version: tls.VersionName(response.TLS.Version), ServerName: response.TLS.ServerName}
		if len(response.TLS.PeerCertificates) > 0 {
			info.CertExpires = response.TLS.PeerCertificates[0].NotAfter.UTC()
		}
		result.TLS = info
	}
	return result, nil
}

func sinceMS(start time.Time) float64 {
	if start.IsZero() {
		return 0
	}
	return math.Round(float64(time.Since(start))/float64(time.Millisecond)*1000) / 1000
}
