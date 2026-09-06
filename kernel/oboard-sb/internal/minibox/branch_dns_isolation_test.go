package minibox

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	mDNS "github.com/miekg/dns"
	box "github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing/service"
)

// branchDNS is a controllable UDP resolver. It records every question so the
// test can prove which resolver a branch actually used, and it can be switched
// to SERVFAIL to exercise the fail-closed path.
type branchDNS struct {
	server  *mDNS.Server
	port    int
	family  uint16
	answerA net.IP
	failing atomic.Bool
	mu      sync.Mutex
	queries map[string]int
}

func startBranchDNS(t *testing.T, family uint16) *branchDNS {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	d := &branchDNS{port: pc.LocalAddr().(*net.UDPAddr).Port, family: family, answerA: net.IPv4(127, 0, 0, 1), queries: map[string]int{}}
	d.server = &mDNS.Server{PacketConn: pc, Handler: d}
	go func() { _ = d.server.ActivateAndServe() }()
	t.Cleanup(func() { _ = d.server.Shutdown() })
	return d
}

func (d *branchDNS) ServeDNS(w mDNS.ResponseWriter, r *mDNS.Msg) {
	reply := new(mDNS.Msg).SetReply(r)
	if len(r.Question) == 1 {
		q := r.Question[0]
		d.mu.Lock()
		d.queries[strings.ToLower(q.Name)]++
		d.mu.Unlock()
		// Negative answers carry an SOA so RFC 2308 negative caching applies
		// and the cache-isolation assertions observe real cache behaviour.
		soa := &mDNS.SOA{Hdr: mDNS.RR_Header{Name: "test.", Rrtype: mDNS.TypeSOA, Class: mDNS.ClassINET, Ttl: 300}, Ns: "ns.test.", Mbox: "hostmaster.test.", Serial: 1, Refresh: 300, Retry: 300, Expire: 300, Minttl: 300}
		switch {
		case d.failing.Load():
			reply.Rcode = mDNS.RcodeServerFailure
		case d.family == 0 || !strings.HasSuffix(strings.ToLower(q.Name), "service.test.") || strings.HasPrefix(strings.ToLower(q.Name), "nxdomain."):
			reply.Rcode = mDNS.RcodeNameError
			reply.Ns = []mDNS.RR{soa}
		case q.Qtype == mDNS.TypeA && d.family == mDNS.TypeA:
			d.mu.Lock()
			answer := d.answerA
			d.mu.Unlock()
			reply.Answer = []mDNS.RR{&mDNS.A{Hdr: mDNS.RR_Header{Name: q.Name, Rrtype: mDNS.TypeA, Class: mDNS.ClassINET, Ttl: 300}, A: answer}}
		case q.Qtype == mDNS.TypeAAAA && d.family == mDNS.TypeAAAA:
			reply.Answer = []mDNS.RR{&mDNS.AAAA{Hdr: mDNS.RR_Header{Name: q.Name, Rrtype: mDNS.TypeAAAA, Class: mDNS.ClassINET, Ttl: 300}, AAAA: net.IPv6loopback}}
		default:
			reply.Ns = []mDNS.RR{soa}
		}
	}
	_ = w.WriteMsg(reply)
}

func (d *branchDNS) count(name string) int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.queries[strings.ToLower(mDNS.Fqdn(name))]
}

func (d *branchDNS) total() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	sum := 0
	for _, n := range d.queries {
		sum += n
	}
	return sum
}

// bannerService answers every accepted connection with one line so the test
// can tell which endpoint a branch finally connected to.
func bannerService(t *testing.T, listener net.Listener, banner string) {
	t.Helper()
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				defer conn.Close()
				_ = conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
				_, _ = io.WriteString(conn, banner+"\n")
			}(conn)
		}
	}()
	t.Cleanup(func() { _ = listener.Close() })
}

// listenSamePortDualFamily binds the same TCP port on 127.0.0.1 and [::1], so a
// single hostname:port resolves to different services purely by DNS answer.
func listenSamePortDualFamily(t *testing.T) (net.Listener, net.Listener, int) {
	t.Helper()
	for attempt := 0; attempt < 20; attempt++ {
		v4, err := net.Listen("tcp4", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		port := v4.Addr().(*net.TCPAddr).Port
		v6, err := net.Listen("tcp6", fmt.Sprintf("[::1]:%d", port))
		if err == nil {
			return v4, v6, port
		}
		_ = v4.Close()
		if strings.Contains(err.Error(), "cannot assign requested address") || strings.Contains(err.Error(), "address family not supported") {
			t.Skip("IPv6 loopback is unavailable: " + err.Error())
		}
	}
	t.Fatal("could not bind the same port on both loopback families")
	return nil, nil, 0
}

func freeTCPPort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

// socksBanner opens an authenticated SOCKS5 CONNECT through the kernel and
// returns the banner of the service that finally answered.
func socksBanner(proxyPort int, user, password, host string, port int) (string, error) {
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", proxyPort), 5*time.Second)
	if err != nil {
		return "", err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(8 * time.Second))
	reader := bufio.NewReader(conn)
	if _, err := conn.Write([]byte{0x05, 0x01, 0x02}); err != nil {
		return "", err
	}
	head := make([]byte, 2)
	if _, err := io.ReadFull(reader, head); err != nil || head[1] != 0x02 {
		return "", fmt.Errorf("socks method negotiation failed: %v %v", head, err)
	}
	auth := append([]byte{0x01, byte(len(user))}, user...)
	auth = append(append(auth, byte(len(password))), password...)
	if _, err := conn.Write(auth); err != nil {
		return "", err
	}
	if _, err := io.ReadFull(reader, head); err != nil || head[1] != 0x00 {
		return "", fmt.Errorf("socks authentication rejected: %v %v", head, err)
	}
	request := append([]byte{0x05, 0x01, 0x00, 0x03, byte(len(host))}, host...)
	request = append(request, byte(port>>8), byte(port))
	if _, err := conn.Write(request); err != nil {
		return "", err
	}
	replyHead := make([]byte, 4)
	if _, err := io.ReadFull(reader, replyHead); err != nil {
		return "", fmt.Errorf("socks connect reply: %w", err)
	}
	if replyHead[1] != 0x00 {
		return "", fmt.Errorf("socks connect refused: rep=%d", replyHead[1])
	}
	var bound int
	switch replyHead[3] {
	case 0x01:
		bound = 4
	case 0x04:
		bound = 16
	case 0x03:
		l, err := reader.ReadByte()
		if err != nil {
			return "", err
		}
		bound = int(l)
	default:
		return "", fmt.Errorf("socks bound address type %d", replyHead[3])
	}
	if _, err := io.ReadFull(reader, make([]byte, bound+2)); err != nil {
		return "", err
	}
	line, err := reader.ReadString('\n')
	if err != nil {
		return "", fmt.Errorf("read banner: %w", err)
	}
	return strings.TrimSpace(line), nil
}

type branchDNSFixture struct {
	dnsA, dnsB, dnsDefault *branchDNS
	servicePort            int
	proxyPort              int
	configPath             string
	kernelCtx              context.Context
}

func newBranchDNSFixture(t *testing.T) *branchDNSFixture {
	t.Helper()
	v4, v6, servicePort := listenSamePortDualFamily(t)
	bannerService(t, v4, "service-a")
	bannerService(t, v6, "service-b")
	f := &branchDNSFixture{dnsA: startBranchDNS(t, mDNS.TypeA), dnsB: startBranchDNS(t, mDNS.TypeAAAA), dnsDefault: startBranchDNS(t, 0), servicePort: servicePort, proxyPort: freeTCPPort(t)}
	scope := func(user string) map[string]any {
		return map[string]any{"inbound": []string{"in-1"}, "auth_user": []string{user}, "domain_suffix": []string{"service.test"}, "port": []int{servicePort}}
	}
	unit := func(user, resolver string) []map[string]any {
		resolve := scope(user)
		resolve["action"], resolve["server"] = "resolve", resolver
		route := scope(user)
		route["action"], route["outbound"] = "route", "direct"
		return []map[string]any{resolve, route}
	}
	rules := append(unit("alice__oboard_path_101", "branch-a"), unit("bob__oboard_path_102", "branch-b")...)
	raw, err := json.Marshal(map[string]any{
		"log": map[string]any{"level": "warn"},
		"dns": map[string]any{
			"servers": []map[string]any{
				{"type": "udp", "tag": "branch-a", "server": "127.0.0.1", "server_port": f.dnsA.port},
				{"type": "udp", "tag": "branch-b", "server": "127.0.0.1", "server_port": f.dnsB.port},
				{"type": "udp", "tag": "server-default", "server": "127.0.0.1", "server_port": f.dnsDefault.port},
			},
			"final": "server-default",
		},
		"inbounds": []map[string]any{{
			"type": "socks", "tag": "in-1", "listen": "127.0.0.1", "listen_port": f.proxyPort,
			"users": []map[string]any{
				{"username": "alice__oboard_path_101", "password": "alice-secret"},
				{"username": "bob__oboard_path_102", "password": "bob-secret"},
				{"username": "carol", "password": "carol-secret"},
			},
		}},
		"outbounds": []map[string]any{{"type": "direct", "tag": "direct"}},
		"route":     map[string]any{"rules": rules, "final": "direct", "default_domain_resolver": map[string]any{"server": "server-default"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	f.configPath = filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(f.configPath, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	return f
}

func (f *branchDNSFixture) start(t *testing.T) *box.Box {
	t.Helper()
	opts, _, err := LoadConfig(f.configPath, HY2Tuning{})
	if err != nil {
		t.Fatal(err)
	}
	f.kernelCtx = Context(context.Background())
	instance, err := box.New(box.Options{Context: f.kernelCtx, Options: opts})
	if err != nil {
		t.Fatal(err)
	}
	if err := instance.Start(); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", f.proxyPort), 200*time.Millisecond)
		if err == nil {
			_ = conn.Close()
			return instance
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("kernel socks listener did not come up")
	return nil
}

func (f *branchDNSFixture) alice(host string) (string, error) {
	return socksBanner(f.proxyPort, "alice__oboard_path_101", "alice-secret", host, f.servicePort)
}

func (f *branchDNSFixture) bob(host string) (string, error) {
	return socksBanner(f.proxyPort, "bob__oboard_path_102", "bob-secret", host, f.servicePort)
}

func (f *branchDNSFixture) expect(t *testing.T, label string, got string, err error, want string) {
	t.Helper()
	if err != nil {
		t.Fatalf("%s: %v", label, err)
	}
	if got != want {
		t.Fatalf("%s: connected to %q, want %q", label, got, want)
	}
}

// Two branches share one listener and one kernel. The same hostname must be
// resolved by each branch's own resolver and land on that answer's service:
// alternating, concurrently, after the other branch warmed its cache, after
// one resolver fails, and after a full configuration reload.
func TestBranchDNSIsolationOnOneKernel(t *testing.T) {
	f := newBranchDNSFixture(t)
	instance := f.start(t)
	defer instance.Close()

	// Prewarm A only: B and the default resolver must not have been consulted.
	got, err := f.alice("service.test")
	f.expect(t, "alice first", got, err, "service-a")
	if f.dnsB.total() != 0 || f.dnsDefault.total() != 0 {
		t.Fatalf("branch A resolution leaked: dns-b=%d default=%d", f.dnsB.total(), f.dnsDefault.total())
	}
	got, err = f.bob("service.test")
	f.expect(t, "bob after A warmed", got, err, "service-b")
	if f.dnsB.count("service.test") == 0 {
		t.Fatal("branch B answered from another resolver's cache")
	}

	// Alternating access with a warm cache stays isolated and does not hit
	// the resolvers again for the cached name.
	queriesA, queriesB := f.dnsA.count("service.test"), f.dnsB.count("service.test")
	for i := 0; i < 3; i++ {
		got, err = f.alice("service.test")
		f.expect(t, fmt.Sprintf("alice alternating %d", i), got, err, "service-a")
		got, err = f.bob("service.test")
		f.expect(t, fmt.Sprintf("bob alternating %d", i), got, err, "service-b")
	}
	if f.dnsA.count("service.test") != queriesA || f.dnsB.count("service.test") != queriesB {
		t.Fatalf("cached name was re-queried: a=%d->%d b=%d->%d", queriesA, f.dnsA.count("service.test"), queriesB, f.dnsB.count("service.test"))
	}

	// Concurrent mixed access.
	var wg sync.WaitGroup
	failures := make(chan error, 32)
	for i := 0; i < 16; i++ {
		wg.Add(2)
		go func() {
			defer wg.Done()
			if got, err := f.alice("concurrent.service.test"); err != nil || got != "service-a" {
				failures <- fmt.Errorf("alice concurrent: %q %v", got, err)
			}
		}()
		go func() {
			defer wg.Done()
			if got, err := f.bob("concurrent.service.test"); err != nil || got != "service-b" {
				failures <- fmt.Errorf("bob concurrent: %q %v", got, err)
			}
		}()
	}
	wg.Wait()
	close(failures)
	for err := range failures {
		t.Error(err)
	}
	if t.Failed() {
		t.FailNow()
	}

	// Branch B's resolver fails: B fails closed, A is untouched, and neither
	// falls back to the default resolver.
	defaultBefore := f.dnsDefault.total()
	f.dnsB.failing.Store(true)
	if got, err := f.bob("failing-b.service.test"); err == nil {
		t.Fatalf("bob connected to %q while its resolver was failing", got)
	}
	got, err = f.alice("failing-b.service.test")
	f.expect(t, "alice while B fails", got, err, "service-a")
	f.dnsB.failing.Store(false)
	f.dnsA.failing.Store(true)
	if got, err := f.alice("failing-a.service.test"); err == nil {
		t.Fatalf("alice connected to %q while its resolver was failing", got)
	}
	got, err = f.bob("failing-a.service.test")
	f.expect(t, "bob while A fails", got, err, "service-b")
	f.dnsA.failing.Store(false)
	if f.dnsDefault.total() != defaultBefore {
		t.Fatalf("branch failures fell back to the default resolver (%d -> %d)", defaultBefore, f.dnsDefault.total())
	}

	// A user without a branch policy goes to the server default resolver and
	// never borrows a branch resolver.
	if got, err := socksBanner(f.proxyPort, "carol", "carol-secret", "service.test", f.servicePort); err == nil {
		t.Fatalf("carol connected to %q without a policy", got)
	}
	if f.dnsDefault.count("service.test") == 0 {
		t.Fatal("unscoped user did not use the default resolver")
	}
	if f.dnsA.count("service.test") != queriesA || f.dnsB.count("service.test") != queriesB {
		t.Fatal("unscoped user consulted a branch resolver")
	}

	// Reload: a fresh kernel with the same configuration keeps the isolation
	// with a cold cache.
	if err := instance.Close(); err != nil {
		t.Fatal(err)
	}
	instance = f.start(t)
	got, err = f.bob("reload.service.test")
	f.expect(t, "bob after reload", got, err, "service-b")
	got, err = f.alice("reload.service.test")
	f.expect(t, "alice after reload", got, err, "service-a")
	if f.dnsA.count("reload.service.test") == 0 || f.dnsB.count("reload.service.test") == 0 {
		t.Fatal("reloaded kernel served a name it never resolved")
	}
}

// The sequential failover group is real runtime behaviour on a live kernel:
// the primary's NODATA and NXDOMAIN are final answers, only a failing primary
// moves the query to the secondary, a group with every member failing fails
// the connection without touching any other resolver, and the
// public-answers-only view refuses a private answer for restricted SSH.
func TestDNSGroupFailoverOnOneKernel(t *testing.T) {
	v4, v6, servicePort := listenSamePortDualFamily(t)
	bannerService(t, v4, "service-a")
	bannerService(t, v6, "service-b")
	primary, secondary, fallback := startBranchDNS(t, mDNS.TypeA), startBranchDNS(t, mDNS.TypeAAAA), startBranchDNS(t, 0)
	proxyPort := freeTCPPort(t)
	scope := func(user, resolver string) []map[string]any {
		match := map[string]any{"inbound": []string{"in-1"}, "auth_user": []string{user}, "domain_suffix": []string{"service.test"}}
		resolve := map[string]any{"action": "resolve", "server": resolver}
		route := map[string]any{"action": "route", "outbound": "direct"}
		for key, value := range match {
			resolve[key], route[key] = value, value
		}
		return []map[string]any{resolve, route}
	}
	raw, err := json.Marshal(map[string]any{
		"log": map[string]any{"level": "warn"},
		"dns": map[string]any{
			"servers": []map[string]any{
				{"type": "udp", "tag": "remote-primary", "server": "127.0.0.1", "server_port": primary.port},
				{"type": "udp", "tag": "remote-secondary", "server": "127.0.0.1", "server_port": secondary.port},
				{"type": "udp", "tag": "server-default", "server": "127.0.0.1", "server_port": fallback.port},
				{"type": "oboard-dns-group", "tag": "remote", "members": []string{"remote-primary", "remote-secondary"}, "timeout_ms": 2000},
				{"type": "oboard-dns-group", "tag": "ssh-public-remote", "members": []string{"remote-primary", "remote-secondary"}, "timeout_ms": 2000, "public_answers_only": true},
			},
			"final": "server-default",
		},
		"inbounds": []map[string]any{{
			"type": "socks", "tag": "in-1", "listen": "127.0.0.1", "listen_port": proxyPort,
			"users": []map[string]any{{"username": "alice", "password": "alice-secret"}, {"username": "ssh-user", "password": "ssh-secret"}},
		}},
		"outbounds": []map[string]any{{"type": "direct", "tag": "direct"}},
		"route":     map[string]any{"rules": append(scope("alice", "remote"), scope("ssh-user", "ssh-public-remote")...), "final": "direct", "default_domain_resolver": map[string]any{"server": "server-default"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	f := &branchDNSFixture{dnsA: primary, dnsB: secondary, dnsDefault: fallback, servicePort: servicePort, proxyPort: proxyPort, configPath: filepath.Join(t.TempDir(), "config.json")}
	if err := os.WriteFile(f.configPath, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	instance := f.start(t)
	defer instance.Close()
	alice := func(host string) (string, error) {
		return socksBanner(proxyPort, "alice", "alice-secret", host, servicePort)
	}

	// Healthy primary: its A answer wins and its NODATA for AAAA is final, so
	// the secondary (which would answer ::1) is never consulted.
	got, err := alice("service.test")
	f.expect(t, "healthy primary", got, err, "service-a")
	if secondary.total() != 0 {
		t.Fatalf("NODATA from the primary triggered failover: secondary queries=%d", secondary.total())
	}

	// NXDOMAIN is a legitimate answer and does not move to the secondary.
	if got, err := alice("nxdomain.service.test"); err == nil {
		t.Fatalf("connected to %q on an NXDOMAIN name", got)
	}
	if primary.count("nxdomain.service.test") == 0 {
		t.Fatal("primary was not asked for the NXDOMAIN name")
	}
	if secondary.count("nxdomain.service.test") != 0 {
		t.Fatal("NXDOMAIN moved the query to the secondary")
	}

	// A failing primary moves the query to the secondary; the connection
	// lands on the secondary's answer, not on a public fallback.
	primary.failing.Store(true)
	got, err = alice("failover.service.test")
	f.expect(t, "failover to secondary", got, err, "service-b")
	if secondary.count("failover.service.test") == 0 {
		t.Fatal("secondary did not answer the failover name")
	}

	// Every member failing fails the request closed.
	secondary.failing.Store(true)
	if got, err := alice("dead.service.test"); err == nil {
		t.Fatalf("connected to %q while the whole group was failing", got)
	}
	if fallback.total() != 0 {
		t.Fatalf("group exhaustion fell back to the default resolver %d time(s)", fallback.total())
	}
	primary.failing.Store(false)
	secondary.failing.Store(false)

	// The public-answers-only view of the same members rejects the loopback
	// answer restricted SSH traffic must never reach, then accepts a public one.
	if got, err := socksBanner(proxyPort, "ssh-user", "ssh-secret", "private.service.test", servicePort); err == nil {
		t.Fatalf("restricted view connected to private answer %q", got)
	}
	primary.mu.Lock()
	primary.answerA = net.IPv4(203, 0, 113, 10)
	primary.mu.Unlock()
	// A public answer cannot be observed through SOCKS without reaching
	// 203.0.113.10, so prove acceptance through the running kernel's DNS
	// router using the same guarded transport the route rule references.
	guarded, ok := service.FromContext[adapter.DNSTransportManager](f.kernelCtx).Transport("ssh-public-remote")
	if !ok {
		t.Fatal("guarded DNS group is not loaded")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	answer, err := service.FromContext[adapter.DNSRouter](f.kernelCtx).Exchange(ctx, new(mDNS.Msg).SetQuestion("public.service.test.", mDNS.TypeA), adapter.DNSQueryOptions{Transport: guarded})
	if err != nil {
		t.Fatalf("public answer rejected by the guarded group: %v", err)
	}
	if len(answer.Answer) != 1 || answer.Answer[0].(*mDNS.A).A.String() != "203.0.113.10" {
		t.Fatalf("unexpected guarded answer: %v", answer)
	}
}

// A resolve action whose resolver is missing must be rejected when the
// configuration is created, not discovered at first connection.
func TestBranchResolveRejectsUnknownResolver(t *testing.T) {
	raw, err := json.Marshal(map[string]any{
		"dns":       map[string]any{"servers": []map[string]any{{"type": "udp", "tag": "only", "server": "127.0.0.1", "server_port": 5353}}, "final": "only"},
		"outbounds": []map[string]any{{"type": "direct", "tag": "direct"}},
		"route":     map[string]any{"rules": []map[string]any{{"domain_suffix": []string{"service.test"}, "action": "resolve", "server": "missing"}}, "final": "direct"},
	})
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := LoadConfig(path, HY2Tuning{}); err == nil || !strings.Contains(err.Error(), `unknown DNS server "missing"`) {
		t.Fatalf("unknown resolver accepted by LoadConfig: %v", err)
	}
	logical, err := json.Marshal(map[string]any{
		"dns":       map[string]any{"servers": []map[string]any{{"type": "udp", "tag": "only", "server": "127.0.0.1", "server_port": 5353}}, "final": "only"},
		"outbounds": []map[string]any{{"type": "direct", "tag": "direct"}},
		"route":     map[string]any{"rules": []map[string]any{{"type": "logical", "mode": "and", "rules": []map[string]any{{"inbound": []string{"in-1"}}, {"domain_suffix": []string{"service.test"}}}, "action": "resolve", "server": "only"}}, "final": "direct"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, logical, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := LoadConfig(path, HY2Tuning{}); err != nil {
		t.Fatalf("valid logical resolve rejected: %v", err)
	}
}
