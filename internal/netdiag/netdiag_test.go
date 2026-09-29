package netdiag

import (
	"context"
	"encoding/binary"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"

	"github.com/OboardProject/oboard-agent/internal/model"
)

type fakeResolver map[string][]netip.Addr

func (f fakeResolver) LookupNetIP(_ context.Context, network, host string) ([]netip.Addr, error) {
	addresses, ok := f[host]
	if !ok {
		return nil, &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
	}
	var out []netip.Addr
	for _, address := range addresses {
		if network == "ip4" && !address.Is4() || network == "ip6" && !address.Is6() {
			continue
		}
		out = append(out, address)
	}
	if len(out) == 0 {
		return nil, &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
	}
	return out, nil
}

var (
	publicV4 = netip.MustParseAddr("8.8.8.8")
	publicV6 = netip.MustParseAddr("2606:4700:4700::1111")
)

func TestPublicAddressPolicy(t *testing.T) {
	for _, raw := range []string{"8.8.8.8", "1.1.1.1", "2606:4700:4700::1111"} {
		if !PublicIP(netip.MustParseAddr(raw)) {
			t.Fatalf("%s must be public", raw)
		}
	}
	for _, raw := range []string{"127.0.0.1", "10.1.2.3", "172.16.0.1", "192.168.1.1", "100.64.0.1", "169.254.169.254", "0.0.0.0", "224.0.0.1", "255.255.255.255",
		"192.0.2.1", "198.18.0.1", "::1", "::", "fe80::1", "fc00::1", "fd00::1", "64:ff9b::a00:1", "2001:db8::1", "::ffff:10.0.0.1", "ff02::1"} {
		if PublicIP(netip.MustParseAddr(raw)) {
			t.Fatalf("%s must not be public", raw)
		}
	}
	for _, target := range []string{"localhost", "printer.local", "db.internal", "intranet", "10.0.0.1", "[::1]", "a..b.com", "-x.example.com", "1.2.3.4.5"} {
		if _, err := NormalizeTarget(target); err == nil {
			t.Fatalf("target %q must be refused", target)
		}
	}
	if got, err := NormalizeTarget(" Example.COM "); err != nil || got != "example.com" {
		t.Fatalf("normalize = %q, %v", got, err)
	}
}

func TestResolveRefusesMixedAnswersAndHonoursFamily(t *testing.T) {
	ctx := context.Background()
	resolver := fakeResolver{
		"mixed.example.com": {publicV4, netip.MustParseAddr("10.0.0.5")},
		"dual.example.com":  {publicV4, publicV6},
		"v6.example.com":    {publicV6},
	}
	if _, err := ResolveTarget(ctx, resolver, "mixed.example.com", model.NetworkFamilyAuto); CodeOf(err) != model.NetworkDiagnosticCodeTargetNotAllowed {
		t.Fatalf("a mixed answer must be refused, got %v", err)
	}
	if ip, err := ResolveTarget(ctx, resolver, "dual.example.com", model.NetworkFamilyIPv6); err != nil || ip != publicV6 {
		t.Fatalf("ipv6 family = %v, %v", ip, err)
	}
	if _, err := ResolveTarget(ctx, resolver, "v6.example.com", model.NetworkFamilyIPv4); CodeOf(err) != model.NetworkDiagnosticCodeResolveFailed {
		t.Fatalf("missing family must be a resolve failure, got %v", err)
	}
	if _, err := ResolveTarget(ctx, resolver, "8.8.8.8", model.NetworkFamilyIPv6); CodeOf(err) != model.NetworkDiagnosticCodeInvalidInput {
		t.Fatalf("literal of the wrong family must be invalid, got %v", err)
	}
}

func quotedIPv4(proto byte, dst netip.Addr, upper []byte) []byte {
	header := make([]byte, 20)
	header[0] = 0x45
	header[9] = proto
	copy(header[12:16], []byte{192, 0, 2, 10})
	d := dst.As4()
	copy(header[16:20], d[:])
	return append(header, upper...)
}

func TestParseReplyDecodesQuotedProbe(t *testing.T) {
	router := netip.MustParseAddr("203.0.113.9")
	udp := make([]byte, 8)
	binary.BigEndian.PutUint16(udp[0:], 40001)
	binary.BigEndian.PutUint16(udp[2:], 33434)
	message := icmp.Message{Type: ipv4.ICMPTypeTimeExceeded, Body: &icmp.TimeExceeded{Data: quotedIPv4(protocolUDP, publicV4, udp)}}
	raw, err := message.Marshal(nil)
	if err != nil {
		t.Fatal(err)
	}
	got, ok := parseReply(false, raw, router)
	if !ok || got.kind != replyTimeExceeded || got.proto != protocolUDP || got.srcPort != 40001 || got.dstPort != 33434 || got.innerDst != publicV4 || got.from != router {
		t.Fatalf("unexpected parse %+v ok=%v", got, ok)
	}
	echo := make([]byte, 8)
	echo[0] = 8
	binary.BigEndian.PutUint16(echo[4:], 77)
	binary.BigEndian.PutUint16(echo[6:], 5)
	message = icmp.Message{Type: ipv4.ICMPTypeDestinationUnreachable, Code: 3, Body: &icmp.DstUnreach{Data: quotedIPv4(protocolICMP, publicV4, echo)}}
	raw, _ = message.Marshal(nil)
	got, ok = parseReply(false, raw, publicV4)
	if !ok || got.kind != replyUnreachable || got.id != 77 || got.seq != 5 {
		t.Fatalf("unexpected parse %+v ok=%v", got, ok)
	}
	if _, ok := parseReply(false, []byte{11, 0, 0}, router); ok {
		t.Fatal("a truncated message must be ignored")
	}
	message = icmp.Message{Type: ipv4.ICMPTypeTimeExceeded, Body: &icmp.TimeExceeded{Data: []byte{0x45, 0, 0}}}
	raw, _ = message.Marshal(nil)
	if _, ok := parseReply(false, raw, router); ok {
		t.Fatal("a short quoted packet must be ignored")
	}
}

// fakeTransport simulates a path of routers ending at target.
type fakeTransport struct {
	target  netip.Addr
	path    []netip.Addr
	drop    map[int]bool
	pending []reply
	sent    int
	closed  bool
}

func (f *fakeTransport) SendEcho(dst netip.Addr, id, seq, ttl, size int) error {
	f.sent++
	if f.drop[f.sent] {
		return nil
	}
	if ttl <= len(f.path) {
		f.pending = append(f.pending, reply{kind: replyTimeExceeded, from: f.path[ttl-1], proto: protocolICMP, id: id, seq: seq, innerDst: dst})
		return nil
	}
	// An unrelated reply (another prober's identifier) must be skipped.
	f.pending = append(f.pending, reply{kind: replyEcho, from: dst, proto: protocolICMP, id: id + 1, seq: seq})
	f.pending = append(f.pending, reply{kind: replyEcho, from: dst, proto: protocolICMP, id: id, seq: seq})
	return nil
}

func (f *fakeTransport) SendUDP(dst netip.Addr, port, ttl int) (int, error) {
	f.sent++
	src := 40000 + f.sent
	if ttl <= len(f.path) {
		f.pending = append(f.pending, reply{kind: replyTimeExceeded, from: f.path[ttl-1], proto: protocolUDP, srcPort: src, dstPort: port, innerDst: dst})
	} else {
		f.pending = append(f.pending, reply{kind: replyUnreachable, from: dst, proto: protocolUDP, srcPort: src, dstPort: port, innerDst: dst})
	}
	return src, nil
}

func (f *fakeTransport) Receive(time.Time) (reply, time.Time, error) {
	if len(f.pending) == 0 {
		return reply{}, time.Time{}, errReceiveTimeout
	}
	next := f.pending[0]
	f.pending = f.pending[1:]
	return next, time.Now(), nil
}

func (f *fakeTransport) Close() error { f.closed = true; return nil }

func envelope() model.NetworkDiagnosticEnvelope {
	return model.NetworkDiagnosticEnvelope{ProtocolVersion: 1, OperationID: "op-1", Origin: model.NetworkDiagnosticOriginPlugin}
}

func TestPingMatchesRepliesAndCountsLoss(t *testing.T) {
	transport := &fakeTransport{target: publicV4, drop: map[int]bool{2: true}}
	open := func(bool) (probeTransport, error) { return transport, nil }
	payload := model.NetworkPingTaskPayload{NetworkDiagnosticEnvelope: envelope(), Target: "8.8.8.8", IPFamily: "auto", Count: 3, IntervalMS: 200, TimeoutMS: 100}
	result, err := Ping(context.Background(), fakeResolver{}, open, payload)
	if err != nil {
		t.Fatal(err)
	}
	if result.Sent != 3 || result.Received != 2 || result.LossPercent != 33.3 || len(result.Samples) != 3 || !result.Samples[1].Timeout || !transport.closed {
		t.Fatalf("unexpected ping result %+v", result)
	}
	payload.Count = model.PingMaxCount + 1
	if _, err := Ping(context.Background(), fakeResolver{}, open, payload); CodeOf(err) != model.NetworkDiagnosticCodeInvalidInput {
		t.Fatalf("out-of-range count must be invalid, got %v", err)
	}
	payload.Count, payload.Target = 1, "192.168.1.1"
	if _, err := Ping(context.Background(), fakeResolver{}, open, payload); CodeOf(err) != model.NetworkDiagnosticCodeTargetNotAllowed {
		t.Fatalf("private target must be refused, got %v", err)
	}
}

func TestTraceWalksHopsUntilTheTarget(t *testing.T) {
	path := []netip.Addr{netip.MustParseAddr("203.0.113.1"), netip.MustParseAddr("198.51.100.7")}
	for _, mode := range []string{model.TraceModeICMP, model.TraceModeUDP} {
		transport := &fakeTransport{target: publicV4, path: path}
		payload := model.NetworkTraceTaskPayload{NetworkDiagnosticEnvelope: envelope(), Target: "dns.example.com", IPFamily: "ipv4", Mode: mode, MaxHops: 10, QueriesPerHop: 2, PerHopTimeoutMS: 200}
		if mode == model.TraceModeUDP {
			payload.Port = 33434
		}
		result, err := Trace(context.Background(), fakeResolver{"dns.example.com": {publicV4}}, func(bool) (probeTransport, error) { return transport, nil }, nil, payload)
		if err != nil {
			t.Fatalf("%s: %v", mode, err)
		}
		if !result.Reached || result.Truncated || len(result.Hops) != 3 || result.ResolvedIP != "8.8.8.8" {
			t.Fatalf("%s: unexpected trace %+v", mode, result)
		}
		if result.Hops[0].Addresses[0] != "203.0.113.1" || result.Hops[1].Addresses[0] != "198.51.100.7" || result.Hops[2].Addresses[0] != "8.8.8.8" || len(result.Hops[2].Probes) != 2 {
			t.Fatalf("%s: unexpected hops %+v", mode, result.Hops)
		}
	}
	payload := model.NetworkTraceTaskPayload{NetworkDiagnosticEnvelope: envelope(), Target: "8.8.8.8", IPFamily: "auto", Mode: model.TraceModeTCP, Port: 443, MaxHops: 5, QueriesPerHop: 1, PerHopTimeoutMS: 200}
	if _, err := Trace(context.Background(), fakeResolver{}, func(bool) (probeTransport, error) { return &fakeTransport{}, nil }, nil, payload); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("tcp trace without a tracer must be unsupported, got %v", err)
	}
	for _, bad := range []model.NetworkTraceTaskPayload{
		{Mode: "icmp", Port: 80, MaxHops: 5, QueriesPerHop: 1, PerHopTimeoutMS: 200, IPFamily: "auto"},
		{Mode: "udp", MaxHops: 5, QueriesPerHop: 1, PerHopTimeoutMS: 200, IPFamily: "auto"},
		{Mode: "icmp", MaxHops: model.TraceMaxHops + 1, QueriesPerHop: 1, PerHopTimeoutMS: 200, IPFamily: "auto"},
		{Mode: "icmp", MaxHops: 5, QueriesPerHop: model.TraceMaxQueriesPerHop + 1, PerHopTimeoutMS: 200, IPFamily: "auto"},
		{Mode: "exec", MaxHops: 5, QueriesPerHop: 1, PerHopTimeoutMS: 200, IPFamily: "auto"},
	} {
		if ValidateTrace(bad) == nil {
			t.Fatalf("trace payload %+v must be invalid", bad)
		}
	}
}

type fakeDialer struct {
	err     error
	address string
	target  string
}

func (f *fakeDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	f.address = address
	if f.err != nil {
		return nil, f.err
	}
	var d net.Dialer
	return d.DialContext(ctx, network, f.target)
}

func TestTCPProbeReportsOutcomeAsResult(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			conn.Close()
		}
	}()
	dialer := &fakeDialer{target: listener.Addr().String()}
	payload := model.NetworkTCPProbeTaskPayload{NetworkDiagnosticEnvelope: envelope(), Host: "api.example.com", Port: 443, IPFamily: "auto", TimeoutMS: 1000}
	resolver := fakeResolver{"api.example.com": {publicV4}}
	result, err := TCPProbe(context.Background(), resolver, dialer, payload)
	if err != nil || !result.Connected || dialer.address != "8.8.8.8:443" {
		t.Fatalf("connect: %+v %v dialed %s", result, err, dialer.address)
	}
	result, err = TCPProbe(context.Background(), resolver, &fakeDialer{err: syscall.ECONNREFUSED}, payload)
	if err != nil || result.Connected || result.ErrorClass != "refused" {
		t.Fatalf("refused: %+v %v", result, err)
	}
	payload.Host = "missing.example.com"
	result, err = TCPProbe(context.Background(), resolver, dialer, payload)
	if err != nil || result.ErrorClass != "dns_failed" {
		t.Fatalf("nxdomain: %+v %v", result, err)
	}
	payload.Host = "169.254.169.254"
	if _, err := TCPProbe(context.Background(), resolver, dialer, payload); CodeOf(err) != model.NetworkDiagnosticCodeTargetNotAllowed {
		t.Fatalf("metadata address must be refused, got %v", err)
	}
}

func TestDNSLookupFiltersRecordTypes(t *testing.T) {
	resolver := fakeResolver{"dual.example.com": {publicV4, publicV6}}
	payload := model.NetworkDNSLookupTaskPayload{NetworkDiagnosticEnvelope: envelope(), Name: "dual.example.com", RecordTypes: []string{"A", "AAAA"}, TimeoutMS: 1000}
	result, err := DNSLookup(context.Background(), resolver, payload)
	if err != nil || len(result.Records) != 2 || result.Records[0].Type != "A" || result.Records[1].Type != "AAAA" {
		t.Fatalf("lookup: %+v %v", result, err)
	}
	payload.RecordTypes = []string{"TXT"}
	if _, err := DNSLookup(context.Background(), resolver, payload); CodeOf(err) != model.NetworkDiagnosticCodeInvalidInput {
		t.Fatalf("unsupported record types must be invalid, got %v", err)
	}
	payload.RecordTypes, payload.Name = []string{"A"}, "router.lan"
	if _, err := DNSLookup(context.Background(), resolver, payload); CodeOf(err) != model.NetworkDiagnosticCodeInvalidInput {
		t.Fatalf("internal names must be invalid, got %v", err)
	}
}

func TestHTTPProbeDialsValidatedAddressesAndRevalidatesRedirects(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/private":
			http.Redirect(w, r, "http://10.0.0.1/admin", http.StatusFound)
		case "/hop":
			http.Redirect(w, r, "http://www.example.com/ok", http.StatusFound)
		default:
			_, _ = w.Write([]byte(strings.Repeat("x", 100)))
		}
	}))
	defer server.Close()
	resolver := fakeResolver{"www.example.com": {publicV4}}
	dialer := &fakeDialer{target: strings.TrimPrefix(server.URL, "http://")}
	payload := model.NetworkHTTPProbeTaskPayload{NetworkDiagnosticEnvelope: envelope(), URL: "http://www.example.com/hop", Method: http.MethodGet, IPFamily: "auto", TimeoutMS: 2000, FollowRedirects: true}
	result, err := HTTPProbe(context.Background(), resolver, dialer, payload)
	if err != nil || result.StatusCode != 200 || result.Redirects != 1 || result.BodyBytes != 100 || result.ResolvedIP != "8.8.8.8" || result.FinalURL != "http://www.example.com/ok" {
		t.Fatalf("probe: %+v %v", result, err)
	}
	payload.FollowRedirects = false
	result, err = HTTPProbe(context.Background(), resolver, dialer, payload)
	if err != nil || result.StatusCode != http.StatusFound || result.Redirects != 0 {
		t.Fatalf("no-follow probe: %+v %v", result, err)
	}
	payload.URL, payload.FollowRedirects = "http://www.example.com/private", true
	if _, err := HTTPProbe(context.Background(), resolver, dialer, payload); CodeOf(err) != model.NetworkDiagnosticCodeTargetNotAllowed {
		t.Fatalf("a redirect to a private address must be refused, got %v", err)
	}
	for _, bad := range []string{"ftp://www.example.com/", "http://user:pw@www.example.com/", "http://127.0.0.1/", "http://metadata.internal/", "http://www.example.com:99999/"} {
		payload.URL = bad
		if _, err := HTTPProbe(context.Background(), resolver, dialer, payload); err == nil {
			t.Fatalf("url %q must be refused", bad)
		}
	}
	payload.URL, payload.Method = "http://www.example.com/", http.MethodPost
	if _, err := HTTPProbe(context.Background(), resolver, dialer, payload); CodeOf(err) != model.NetworkDiagnosticCodeInvalidInput {
		t.Fatalf("POST must be refused, got %v", err)
	}
}
