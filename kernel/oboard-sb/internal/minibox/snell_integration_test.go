package minibox

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/OboardProject/oboard-agent/kernel/oboard-sb/internal/authorization"
	box "github.com/sagernet/sing-box"
	snell "github.com/sagernet/sing-snell"
	"github.com/sagernet/sing-snell/snellv4"
	"github.com/sagernet/sing-snell/snellv6"
	M "github.com/sagernet/sing/common/metadata"
)

func snellTestMethod(t *testing.T, version int, mode, psk string) snell.Method {
	t.Helper()
	if version == 5 {
		c, e := snellv4.NewClient(snellv4.ClientOptions{PSK: []byte(psk)})
		if e != nil {
			t.Fatal(e)
		}
		return c
	}
	m, e := snellv6.ParseMode(mode)
	if e != nil {
		t.Fatal(e)
	}
	c, e := snellv6.NewClient(snellv6.ClientOptions{PSK: []byte(psk), Mode: m})
	if e != nil {
		t.Fatal(e)
	}
	return c
}
func snellTestEntry(name, key, psk string, id int64) UserInstallEntry {
	return UserInstallEntry{InboundTag: "in-1", AuthUser: name, Credential: UserCredential{PSK: psk}, AuthorizationKey: key, Identity: UserIdentity{UserID: id, InboundID: 1, CredentialStatus: "active"}, RouteOutbound: "direct", Policy: RuntimeUserLimit{Billable: true, UserID: id, InboundID: 1}}
}
func installSnellTest(t *testing.T, r *RuntimeUsers, revision int64, entries []UserInstallEntry) {
	t.Helper()
	digest, e := UsersDigest(revision, []string{"in-1"}, entries)
	if e != nil {
		t.Fatal(e)
	}
	status, e := r.Install(UserInstallRequest{Scope: []string{"in-1"}, UsersRevision: revision, UsersDigest: digest, Mode: "full", Entries: entries})
	if e != nil {
		t.Fatal(e)
	}
	if status.UsersRevision != revision || status.UsersDigest != digest {
		t.Fatal("ack differs from installed snapshot")
	}
}
func TestSnellSharedBranchDNSAndRuntimeLifecycle(t *testing.T) {
	for _, tc := range []struct {
		version int
		mode    string
	}{{5, ""}, {6, "default"}, {6, "unshaped"}} {
		t.Run(fmt.Sprint(tc), func(t *testing.T) {
			f := newBranchDNSFixture(t)
			raw, e := os.ReadFile(f.configPath)
			if e != nil {
				t.Fatal(e)
			}
			var config map[string]any
			if e = json.Unmarshal(raw, &config); e != nil {
				t.Fatal(e)
			}
			config["inbounds"] = []map[string]any{{"type": "snell", "tag": "in-1", "version": tc.version, "mode": tc.mode, "auth_mode": "multi_psk", "listen": "127.0.0.1", "listen_port": f.proxyPort, "users": []any{}}}
			raw, e = json.Marshal(config)
			if e != nil {
				t.Fatal(e)
			}
			if e = os.WriteFile(f.configPath, raw, 0600); e != nil {
				t.Fatal(e)
			}
			opts, _, e := LoadConfig(f.configPath, HY2Tuning{})
			if e != nil {
				t.Fatal(e)
			}
			ctx := Context(context.Background())
			b, e := box.New(box.Options{Context: ctx, Options: opts})
			if e != nil {
				t.Fatal(e)
			}
			t.Cleanup(func() { b.Close() })
			tracker := AttachRuntimeTrackers(ctx, RuntimeMetadata{RuntimeUsers: &RuntimeUsersMeta{Inbounds: []string{"in-1"}}})
			users := NewRuntimeUsers(filepath.Join(t.TempDir(), "kernel-users.json"), b, tracker, []string{"in-1"})
			if e = b.Start(); e != nil {
				t.Fatal(e)
			}
			a := snellTestEntry("alice__oboard_path_101", "key-a", "alice-independent-psk-1234567890", 1)
			bob := snellTestEntry("bob__oboard_path_102", "key-b", "bob-independent-psk-123456789012", 2)
			banner := func(psk string) (string, error) {
				c, e := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", f.proxyPort), time.Second)
				if e != nil {
					return "", e
				}
				defer c.Close()
				c.SetDeadline(time.Now().Add(2 * time.Second))
				proxy := snellTestMethod(t, tc.version, tc.mode, psk).DialEarlyConn(c, M.ParseSocksaddr(fmt.Sprintf("service.test:%d", f.servicePort)))
				if _, e = proxy.Write(nil); e != nil {
					return "", e
				}
				v := make([]byte, 9)
				_, e = io.ReadFull(proxy, v)
				return string(v), e
			}
			installSnellTest(t, users, 1, []UserInstallEntry{a, bob})
			if _, e = banner(a.Credential.PSK); e == nil {
				t.Fatal("credential without grant admitted")
			}
			if f.dnsA.count("service.test") != 0 || f.dnsB.count("service.test") != 0 {
				t.Fatal("unauthorized handshake queried target DNS")
			}
			now := time.Now().UTC()
			if e = tracker.UpdateAuthorization(&authorization.Lease{Revision: 1, IssuedAt: now.Format(time.RFC3339Nano), Grants: map[string]string{"key-a": now.Add(time.Minute).Format(time.RFC3339Nano), "key-b": now.Add(time.Minute).Format(time.RFC3339Nano)}}); e != nil {
				t.Fatal(e)
			}
			if tc.version == 5 && os.Getenv("OBOARD_MIHOMO_BINARY") != "" {
				runMihomoSnellClients(t, f, []UserInstallEntry{a, bob})
			}
			for _, check := range []struct {
				entry UserInstallEntry
				want  string
			}{{a, "service-a"}, {bob, "service-b"}, {a, "service-a"}} {
				got, e := banner(check.entry.Credential.PSK)
				if e != nil || got != check.want {
					t.Fatalf("branch %s got %q err=%v", check.entry.AuthUser, got, e)
				}
			}
			for _, name := range []string{a.AuthUser, bob.AuthUser} {
				state := tracker.stateForKey("user:" + name)
				counter, ok := state.snapshot()
				if !ok || counter.Download < 9 {
					t.Fatalf("runtime-installed user not billed: %+v", counter)
				}
			}
			testSnellUDPAccounting(t, f, tracker, a, tc.version, tc.mode)
			reuseClient := testSnellNativeReuse(t, f, tracker, a, tc.version, tc.mode)
			defer reuseClient.Close()
			oldPSK := a.Credential.PSK
			a.Credential.PSK = "rotated-independent-psk-1234567890"
			before := tracker.stateForKey("user:" + a.AuthUser).currentConfig().counters
			installSnellTest(t, users, 2, []UserInstallEntry{a, bob})
			tracker.mu.RLock()
			parents := len(tracker.snellParents)
			tracker.mu.RUnlock()
			if parents != 0 {
				t.Fatalf("rotation retained idle protocol parent: %d", parents)
			}

			if tracker.stateForKey("user:"+a.AuthUser).currentConfig().counters != before {
				t.Fatal("rotation reset traffic counters")
			}
			if _, e = banner(oldPSK); e == nil {
				t.Fatal("rotated credential still accepted")
			}
			if got, e := banner(a.Credential.PSK); e != nil || got != "service-a" {
				t.Fatalf("rotated credential %q %v", got, e)
			}
			installSnellTest(t, users, 3, nil)
			if _, e = banner(a.Credential.PSK); e == nil {
				t.Fatal("last deleted credential still accepted")
			}
			installSnellTest(t, users, 4, []UserInstallEntry{bob})
			if got, e := banner(bob.Credential.PSK); e != nil || got != "service-b" {
				t.Fatalf("zero to one %q %v", got, e)
			}
			if tracker.ConnectionAuditEnabled() || tracker.presenceStates != nil || tracker.auditBuckets != nil {
				t.Fatal("authentication enabled optional audit")
			}
		})
	}
}

func runMihomoSnellClients(t *testing.T, f *branchDNSFixture, entries []UserInstallEntry) {
	t.Helper()
	binary := os.Getenv("OBOARD_MIHOMO_BINARY")
	version, err := exec.Command(binary, "-v").Output()
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("independent client: %s", version)
	ports := make([]int, len(entries))
	for i, entry := range entries {
		ports[i] = freeTCPPort(t)
		dir := t.TempDir()
		config := map[string]any{
			"mixed-port": ports[i], "bind-address": "127.0.0.1", "allow-lan": false, "mode": "rule", "log-level": "error",
			"authentication": []string{"local:test-only"}, "dns": map[string]any{"enable": false}, "tun": map[string]any{"enable": false},
			"proxies": []map[string]any{{"name": "snell", "type": "snell", "server": "127.0.0.1", "port": f.proxyPort, "psk": entry.Credential.PSK, "version": 4, "reuse": true}}, "rules": []string{"MATCH,snell"},
		}
		raw, e := json.Marshal(config)
		if e != nil {
			t.Fatal(e)
		}
		path := filepath.Join(dir, "config.yaml")
		if e = os.WriteFile(path, raw, 0600); e != nil {
			t.Fatal(e)
		}
		log, e := os.Create(filepath.Join(dir, "mihomo.log"))
		if e != nil {
			t.Fatal(e)
		}
		cmd := exec.Command(binary, "-d", dir, "-f", path)
		cmd.Stdout, cmd.Stderr = log, log
		if e = cmd.Start(); e != nil {
			log.Close()
			t.Fatal(e)
		}
		t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait(); log.Close() })
		ready := false
		deadline := time.Now().Add(5 * time.Second)
		for time.Now().Before(deadline) {
			c, e := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", ports[i]), 50*time.Millisecond)
			if e == nil {
				c.Close()
				ready = true
				break
			}
			time.Sleep(20 * time.Millisecond)
		}
		if !ready {
			t.Fatal("isolated mihomo listener failed to start")
		}
	}
	var wg sync.WaitGroup
	for i, port := range ports {
		wg.Add(1)
		go func() {
			defer wg.Done()
			want := []string{"service-a", "service-b"}[i]
			for j := 0; j < 3; j++ {
				got, e := socksBanner(port, "local", "test-only", "service.test", f.servicePort)
				if e != nil || got != want {
					t.Errorf("mihomo user %d branch %q expected %s err=%v", i, got, want, e)
					return
				}
			}
		}()
	}
	wg.Wait()
}

type snellLoopbackDialer struct{ count atomic.Int64 }

func (d *snellLoopbackDialer) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	d.count.Add(1)
	return (&net.Dialer{Timeout: time.Second}).DialContext(ctx, network, destination.String())
}
func (d *snellLoopbackDialer) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	return (&net.ListenConfig{}).ListenPacket(ctx, "udp", "127.0.0.1:0")
}

type nativeSnellClient interface {
	DialContext(context.Context, M.Socksaddr) (net.Conn, error)
	Close() error
}

func testSnellNativeReuse(t *testing.T, f *branchDNSFixture, tr *RateLimitTracker, entry UserInstallEntry, version int, mode string) nativeSnellClient {
	t.Helper()
	dialer := &snellLoopbackDialer{}
	server := M.ParseSocksaddr(fmt.Sprintf("127.0.0.1:%d", f.proxyPort))
	var client nativeSnellClient
	var err error
	if version == 5 {
		client, err = snellv4.NewClient(snellv4.ClientOptions{PSK: []byte(entry.Credential.PSK), UserKey: []byte("forged-bob"), Reuse: true, Dialer: dialer, Server: server})
	} else {
		m, _ := snellv6.ParseMode(mode)
		client, err = snellv6.NewClient(snellv6.ClientOptions{PSK: []byte(entry.Credential.PSK), UserKey: []byte("forged-bob"), Mode: m, Reuse: true, Dialer: dialer, Server: server})
	}
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { client.Close() })
	for i := 0; i < 3; i++ {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		c, e := client.DialContext(ctx, M.ParseSocksaddr(fmt.Sprintf("service.test:%d", f.servicePort)))
		if e != nil {
			cancel()
			t.Fatal(e)
		}
		c.SetDeadline(time.Now().Add(time.Second))
		if _, e = c.Write(nil); e != nil {
			c.Close()
			cancel()
			t.Fatal(e)
		}
		value, e := io.ReadAll(c)
		c.Close()
		cancel()
		if e != nil || string(value) != "service-a\n" {
			t.Fatalf("native reuse %q %v", value, e)
		}
	}
	if dialer.count.Load() != 1 {
		t.Fatalf("test did not reuse a parent: %d", dialer.count.Load())
	}
	tr.mu.RLock()
	parents := len(tr.snellParents)
	tr.mu.RUnlock()
	if parents < 1 {
		t.Fatal("idle reusable parent was not indexed")
	}
	return client
}
func testSnellUDPAccounting(t *testing.T, f *branchDNSFixture, tr *RateLimitTracker, entry UserInstallEntry, version int, mode string) {
	t.Helper()
	var echoes []net.PacketConn
	var wg sync.WaitGroup
	for i := 0; i < 2; i++ {
		pc, err := net.ListenPacket("udp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		echoes = append(echoes, pc)
		wg.Add(1)
		go func() {
			defer wg.Done()
			b := make([]byte, 2048)
			for {
				n, peer, err := pc.ReadFrom(b)
				if err != nil {
					return
				}
				_, _ = pc.WriteTo(b[:n], peer)
			}
		}()
	}
	defer func() {
		for _, pc := range echoes {
			pc.Close()
		}
		wg.Wait()
	}()
	raw, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", f.proxyPort), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	raw.SetDeadline(time.Now().Add(2 * time.Second))
	c, err := snellTestMethod(t, version, mode, entry.Credential.PSK).DialPacketConn(raw)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	counters := tr.stateForKey("user:" + entry.AuthUser).currentConfig().counters
	up, down := counters.upload.Load(), counters.download.Load()
	for _, pc := range echoes {
		payload := []byte("snell-udp-payload")
		if _, err = c.WriteTo(payload, pc.LocalAddr()); err != nil {
			t.Fatal(err)
		}
		reply := make([]byte, 100)
		n, _, err := c.ReadFrom(reply)
		if err != nil || string(reply[:n]) != string(payload) {
			t.Fatalf("udp echo %q %v", reply[:n], err)
		}
	}
	if counters.upload.Load()-up != 34 || counters.download.Load()-down != 34 {
		t.Fatalf("UDP payload billing differs: up=%d down=%d", counters.upload.Load()-up, counters.download.Load()-down)
	}
}
