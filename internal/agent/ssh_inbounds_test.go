package agent

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/OboardProject/oboard-agent/internal/model"
)

func testSSHInboundUser(id int64, username, password string) model.SSHInboundUser {
	return model.SSHInboundUser{UserID: id, Username: username, Password: password, PathID: 1, RouteKind: "direct", Enabled: true}
}

func TestSSHInboundRejectsUnsafeDestinationAddresses(t *testing.T) {
	for _, destination := range []string{"127.0.0.1", "10.0.0.1", "169.254.1.1", "224.0.0.1", "::1", "fc00::1", "fe80::1"} {
		if _, err := resolvePermittedSSHDestination(t.Context(), destination, 443); err == nil {
			t.Fatalf("destination %q was allowed", destination)
		}
	}
	addresses, err := resolvePermittedSSHDestination(t.Context(), "1.1.1.1", 443)
	if err != nil || len(addresses) != 1 || addresses[0].String() != "1.1.1.1" {
		t.Fatalf("public destination addresses=%v error=%v", addresses, err)
	}
}

func TestSSHInboundAllowsOnlyPasswordAndDirectTCPIP(t *testing.T) {
	user := testSSHInboundUser(19, "alice", "correct horse battery staple")
	reserve, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := reserve.Addr().(*net.TCPAddr).Port
	_ = reserve.Close()
	runner := New(Config{StateDir: t.TempDir()})
	plan := model.SSHInboundPlan{Version: 1, Inbounds: []model.SSHInbound{{InboundID: 71, ServerID: 1, Name: "restricted", ListenIP: "127.0.0.1", Port: port, Enabled: true, Users: []model.SSHInboundUser{user}}}}
	if _, err := runner.applySSHInbounds(plan); err != nil {
		t.Fatal(err)
	}
	defer func() { _, _ = runner.applySSHInbounds(model.SSHInboundPlan{Version: 2}) }()

	client, err := ssh.Dial("tcp", net.JoinHostPort("127.0.0.1", fmt.Sprint(port)), &ssh.ClientConfig{User: "alice", Auth: []ssh.AuthMethod{ssh.Password(user.Password)}, HostKeyCallback: ssh.InsecureIgnoreHostKey()})
	if err != nil {
		t.Fatalf("password authentication failed: %v", err)
	}
	defer client.Close()
	if session, err := client.NewSession(); err == nil {
		_ = session.Close()
		t.Fatal("session channel was accepted")
	}
	if _, err := client.Dial("tcp", "127.0.0.1:22"); err == nil {
		t.Fatal("loopback direct-tcpip destination was accepted")
	}
	udpGateway, err := client.Dial("tcp", "127.0.0.1:7300")
	if err != nil {
		t.Fatalf("BadVPN UDP gateway was rejected: %v", err)
	}
	if _, err := udpGateway.Write([]byte{3, 0, badVPNFlagKeepalive, 0, 0}); err != nil {
		t.Fatalf("write BadVPN keepalive: %v", err)
	}
	_ = udpGateway.Close()

	if _, err := ssh.Dial("tcp", net.JoinHostPort("127.0.0.1", fmt.Sprint(port)), &ssh.ClientConfig{User: "alice", Auth: []ssh.AuthMethod{ssh.Password("wrong")}, HostKeyCallback: ssh.InsecureIgnoreHostKey()}); err == nil {
		t.Fatal("incorrect SSH password was accepted")
	}
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	userSigner, err := ssh.NewSignerFromKey(privateKey)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ssh.Dial("tcp", net.JoinHostPort("127.0.0.1", fmt.Sprint(port)), &ssh.ClientConfig{User: "alice", Auth: []ssh.AuthMethod{ssh.PublicKeys(userSigner)}, HostKeyCallback: ssh.InsecureIgnoreHostKey()}); err == nil {
		t.Fatal("public-key authentication was accepted")
	}
}

func TestSSHInboundApplyReportsPersistentHostIdentity(t *testing.T) {
	stateDir := filepath.Join(t.TempDir(), "state")
	runner := New(Config{StateDir: stateDir})
	first, err := runner.applySSHInbounds(model.SSHInboundPlan{Version: 1})
	if err != nil {
		t.Fatal(err)
	}
	hostKey, rest, _, _, err := ssh.ParseAuthorizedKey([]byte(first.HostPublicKey))
	if err != nil || len(rest) != 0 {
		t.Fatalf("host public key = %q, err=%v", first.HostPublicKey, err)
	}
	canonical := string(ssh.MarshalAuthorizedKey(hostKey))
	if first.HostPublicKey != canonical[:len(canonical)-1] || first.HostKeyFingerprint != ssh.FingerprintSHA256(hostKey) {
		t.Fatalf("host identity = %#v", first)
	}
	info, err := os.Stat(filepath.Join(stateDir, sshInboundHostKey))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("host private key mode = %o, want 600", info.Mode().Perm())
	}

	unchanged, err := runner.applySSHInbounds(model.SSHInboundPlan{Version: 2})
	if err != nil {
		t.Fatal(err)
	}
	if !unchanged.Unchanged || unchanged.HostPublicKey != first.HostPublicKey || unchanged.HostKeyFingerprint != first.HostKeyFingerprint {
		t.Fatalf("unchanged apply changed host identity: first=%#v unchanged=%#v", first, unchanged)
	}

	restarted := New(Config{StateDir: stateDir})
	if err := restarted.restoreManagedSSHInboundsOnStartup(); err != nil {
		t.Fatal(err)
	}
	afterRestart, err := restarted.applySSHInbounds(model.SSHInboundPlan{Version: 3})
	if err != nil {
		t.Fatal(err)
	}
	if !afterRestart.Unchanged || afterRestart.HostPublicKey != first.HostPublicKey || afterRestart.HostKeyFingerprint != first.HostKeyFingerprint {
		t.Fatalf("restart changed host identity: first=%#v restarted=%#v", first, afterRestart)
	}
}

func TestDeploymentReplayIncludesSSHHostIdentity(t *testing.T) {
	runner := New(Config{StateDir: t.TempDir()})
	status, resultJSON := runner.deploymentReplayResponse(model.DeploymentTaskPayload{Version: 9, SSHInbounds: model.SSHInboundPlan{Version: 9}})
	if status != "succeeded" {
		t.Fatalf("replay status = %q, result=%s", status, resultJSON)
	}
	var result struct {
		Steps []struct {
			Key    string                `json:"key"`
			Status string                `json:"status"`
			Result sshInboundApplyResult `json:"result"`
		} `json:"steps"`
	}
	if err := json.Unmarshal([]byte(resultJSON), &result); err != nil {
		t.Fatal(err)
	}
	for _, step := range result.Steps {
		if step.Key != "ssh_inbounds" {
			continue
		}
		if step.Status != "skipped" || step.Result.HostPublicKey == "" || step.Result.HostKeyFingerprint == "" {
			t.Fatalf("SSH replay step = %#v", step)
		}
		return
	}
	t.Fatalf("SSH replay step missing: %#v", result.Steps)
}

func TestSSHInboundTrafficUsesInboundAndUserPolicy(t *testing.T) {
	counter := &sshInboundCounter{}
	counter.setPolicy(model.TrafficRuntimePolicy{UserID: 7, InboundID: 17, Billable: true, PeriodKey: "2026-07", TrafficLimitBytes: 10, UsedBaselineBytes: 4})
	counter.addTraffic(true, 6)
	if counter.allowNewConnection() {
		t.Fatal("quota-exhausted user was accepted")
	}
	counter.setPolicy(model.TrafficRuntimePolicy{UserID: 7, InboundID: 17, Billable: true, PeriodKey: "2026-08", TrafficLimitBytes: 100})
	if counter.upload.Load() != 0 || counter.download.Load() != 0 {
		t.Fatal("new traffic period did not reset SSH inbound counters")
	}
	counter.addTraffic(true, 3)
	counter.addTraffic(false, 5)
	manager := &sshInboundManager{listeners: map[int64]*managedSSHInbound{17: {plan: model.SSHInbound{InboundID: 17}, counters: map[int64]*sshInboundCounter{7: counter}}}}
	items := manager.snapshot()
	if len(items) != 1 || items[0].InboundID != 17 || items[0].UserID != 7 || items[0].Upload != 3 || items[0].Download != 5 || items[0].PeriodKey != "2026-08" {
		t.Fatalf("unexpected SSH traffic snapshot: %#v", items)
	}
	manager.updatePolicies(map[string]interface{}{"user:7": model.TrafficRuntimePolicy{UserID: 7, InboundID: 17, QuotaState: "quota_exceeded"}}, nil)
	if counter.allowNewConnection() {
		t.Fatal("dynamic quota policy was not applied to SSH inbound")
	}
}

func TestSSHInboundAcknowledgementPreventsBaselineDoubleCount(t *testing.T) {
	counter := &sshInboundCounter{}
	counter.setPolicy(model.TrafficRuntimePolicy{UserID: 7, Billable: true, PeriodKey: "2026-07", TrafficLimitBytes: 12, UsedBaselineBytes: 4})
	counter.addTraffic(true, 6)
	counter.acknowledge(trafficCounterCheckpoint{PeriodKey: "2026-07", Upload: 6})
	counter.setPolicy(model.TrafficRuntimePolicy{UserID: 7, Billable: true, PeriodKey: "2026-07", TrafficLimitBytes: 12, UsedBaselineBytes: 10})
	if counter.quotaExceeded() {
		t.Fatal("accepted local bytes were counted again on top of the Controller baseline")
	}
	counter.addTraffic(false, 2)
	if !counter.quotaExceeded() {
		t.Fatal("new unacknowledged bytes did not consume the remaining quota")
	}
}

func TestSSHInboundQuotaAggregatesSameUserAcrossInbounds(t *testing.T) {
	usage := &sshInboundUserUsage{periods: map[string]*sshInboundUsagePeriod{}}
	first := &sshInboundCounter{usage: usage}
	second := &sshInboundCounter{usage: usage}
	policy := model.TrafficRuntimePolicy{UserID: 7, Billable: true, PeriodKey: "2026-07", TrafficLimitBytes: 10}
	first.setPolicy(policy)
	second.setPolicy(policy)
	first.addTraffic(true, 6)
	second.addTraffic(false, 4)
	if !first.quotaExceeded() || !second.quotaExceeded() {
		t.Fatal("same user's traffic was not aggregated across SSH inbounds")
	}
}

func TestSSHInboundPolicyCollectionRetainsSameUserAcrossInbounds(t *testing.T) {
	plan := model.SSHInboundPlan{Inbounds: []model.SSHInbound{
		{InboundID: 17, Policies: map[string]model.TrafficRuntimePolicy{"user:7": {UserID: 7, InboundID: 17, LeaseBytes: 11}}},
		{InboundID: 18, Policies: map[string]model.TrafficRuntimePolicy{"user:7": {UserID: 7, InboundID: 18, LeaseBytes: 22}}},
	}}
	policies := collectSSHInboundTrafficPolicies(plan)
	if len(policies) != 2 {
		t.Fatalf("collected policies = %#v", policies)
	}
	first, firstOK := policies["ssh-inbound:17:user:7"].(model.TrafficRuntimePolicy)
	second, secondOK := policies["ssh-inbound:18:user:7"].(model.TrafficRuntimePolicy)
	if !firstOK || !secondOK || first.InboundID != 17 || first.LeaseBytes != 11 || second.InboundID != 18 || second.LeaseBytes != 22 {
		t.Fatalf("same-user SSH policies were not retained per inbound: %#v", policies)
	}
}

func TestSSHInboundPolicyPartitionUsesFloorHalfOfCoreLease(t *testing.T) {
	dir := t.TempDir()
	config := `{"_oboard":{"rate_limits":{"users":{"alice":{"user_id":7,"billable":true,"lease_enforced":true,"lease_bytes":101,"reset_lease_bytes":51}}}}}`
	if err := os.WriteFile(filepath.Join(dir, "sing-box.json"), []byte(config), 0o600); err != nil {
		t.Fatal(err)
	}
	runner := New(Config{StateDir: dir})
	plan := model.SSHInboundPlan{Inbounds: []model.SSHInbound{{InboundID: 17, Policies: map[string]model.TrafficRuntimePolicy{
		"user:7": {UserID: 7, LeaseEnforced: true, LeaseBytes: 101, ResetLeaseBytes: 51},
	}}}}
	partitioned, err := runner.partitionSSHInboundPlanPolicies(plan)
	if err != nil {
		t.Fatal(err)
	}
	policy := partitioned.Inbounds[0].Policies["user:7"]
	if policy.LeaseBytes != 50 || policy.ResetLeaseBytes != 25 {
		t.Fatalf("SSH lease partition = %#v, want floor halves 50/25", policy)
	}
	if original := plan.Inbounds[0].Policies["user:7"]; original.LeaseBytes != 101 || original.ResetLeaseBytes != 51 {
		t.Fatalf("partition mutated source plan: %#v", original)
	}
}

func TestEmptySSHInboundPlanRestoresFullCoreLease(t *testing.T) {
	dir := t.TempDir()
	config := `{"_oboard":{"rate_limits":{"users":{"alice":{"user_id":7,"billable":true,"lease_enforced":true,"lease_bytes":101,"reset_lease_bytes":51}}}}}`
	if err := os.WriteFile(filepath.Join(dir, "sing-box.json"), []byte(config), 0o600); err != nil {
		t.Fatal(err)
	}
	var received model.TrafficRuntimePolicy
	runner := New(Config{StateDir: dir})
	runner.coreClient = &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		if request.Method != http.MethodPost || request.URL.Path != "/traffic/policy" {
			t.Fatalf("unexpected core policy request: %s %s", request.Method, request.URL.Path)
		}
		var body struct {
			Policies map[string]model.TrafficRuntimePolicy `json:"policies"`
		}
		if err := json.NewDecoder(request.Body).Decode(&body); err != nil {
			t.Fatal(err)
		}
		received = body.Policies["user:7"]
		return &http.Response{StatusCode: http.StatusOK, Body: http.NoBody, Header: make(http.Header)}, nil
	})}
	counter := &sshInboundCounter{}
	counter.setPolicy(model.TrafficRuntimePolicy{UserID: 7, InboundID: 17, Billable: true, LeaseEnforced: true, LeaseBytes: 50, ResetLeaseBytes: 25})
	runner.sshInboundManager = &sshInboundManager{listeners: map[int64]*managedSSHInbound{
		17: {plan: model.SSHInbound{InboundID: 17}, counters: map[int64]*sshInboundCounter{7: counter}, conns: map[net.Conn]int64{}},
	}}
	if _, err := runner.applySSHInbounds(model.SSHInboundPlan{Version: 2}); err != nil {
		t.Fatal(err)
	}
	if received.LeaseBytes != 101 || received.ResetLeaseBytes != 51 {
		t.Fatalf("empty SSH plan left core with a partitioned lease: %#v", received)
	}
	if users := runner.sshInboundManager.trafficPolicyUsers(); len(users) != 0 {
		t.Fatalf("empty SSH plan retained runtime users: %#v", users)
	}
	if err := runner.reconcileSSHAndCoreTrafficPolicies(context.Background(), model.SSHInboundPlan{}); err != nil {
		t.Fatalf("repeated empty-plan reconciliation was not idempotent: %v", err)
	}
}

func TestSSHInboundRejectNewPreservesExistingTransfers(t *testing.T) {
	counter := &sshInboundCounter{}
	counter.setPolicy(model.TrafficRuntimePolicy{UserID: 7, Billable: true, QuotaState: "quota_exceeded", EnforcementMode: "reject_new"})
	if counter.allowNewConnection() {
		t.Fatal("reject_new accepted a new SSH connection after quota exhaustion")
	}
	if !counter.allowTransfer() {
		t.Fatal("reject_new interrupted an already admitted SSH transfer")
	}
}

func TestSSHInboundDisconnectPolicyClosesExistingUserConnection(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	counter := &sshInboundCounter{}
	counter.setPolicy(model.TrafficRuntimePolicy{UserID: 7, InboundID: 17, Billable: true})
	inbound := &managedSSHInbound{plan: model.SSHInbound{InboundID: 17}, counters: map[int64]*sshInboundCounter{7: counter}, conns: map[net.Conn]int64{server: 7}}
	manager := &sshInboundManager{listeners: map[int64]*managedSSHInbound{17: inbound}}
	manager.updatePolicies(map[string]interface{}{"user:7": model.TrafficRuntimePolicy{UserID: 7, InboundID: 17, Billable: true, QuotaState: "quota_exceeded", EnforcementMode: "disconnect_and_reject"}}, nil)
	_ = client.SetWriteDeadline(time.Now().Add(time.Second))
	if _, err := client.Write([]byte("closed")); err == nil {
		t.Fatal("disconnect_and_reject left the existing SSH connection open")
	}
}

func TestSSHInboundExpiredPolicyStartsNewPeriod(t *testing.T) {
	counter := &sshInboundCounter{}
	counter.setPolicy(model.TrafficRuntimePolicy{UserID: 7, Billable: true, PeriodKey: "old", PeriodEnd: time.Now().Add(-time.Minute).UTC().Format(time.RFC3339Nano), ResetMode: "monthly", ResetLeaseBytes: 25, LeaseEnforced: true, QuotaState: "quota_exceeded"})
	counter.upload.Store(9)
	policy := counter.currentPolicy()
	if policy.PeriodKey == "old" || policy.QuotaState != "active" || policy.LeaseBytes != 25 {
		t.Fatalf("expired SSH policy did not reset: %#v", policy)
	}
	if counter.upload.Load() != 0 || counter.download.Load() != 0 {
		t.Fatal("expired SSH traffic counters were not reset")
	}
}

func TestSSHInboundPlanRejectsDuplicateUsersAndEmptyPasswords(t *testing.T) {
	user := testSSHInboundUser(1, "alice", "password")
	duplicate := user
	duplicate.UserID = 2
	if err := validateSSHInboundPlan(model.SSHInboundPlan{Inbounds: []model.SSHInbound{{InboundID: 1, ServerID: 1, ListenIP: "127.0.0.1", Port: 2222, Enabled: true, Users: []model.SSHInboundUser{user, duplicate}}}}); err == nil {
		t.Fatal("duplicate SSH username was accepted")
	}
	user.Password = ""
	if err := validateSSHInboundPlan(model.SSHInboundPlan{Inbounds: []model.SSHInbound{{InboundID: 1, ServerID: 1, ListenIP: "127.0.0.1", Port: 2222, Enabled: true, Users: []model.SSHInboundUser{user}}}}); err == nil {
		t.Fatal("empty SSH password was accepted")
	}
}

func TestSSHInboundPlanValidatesBoundRoute(t *testing.T) {
	user := testSSHInboundUser(1, "alice", "password")
	plan := func(candidate model.SSHInboundUser) model.SSHInboundPlan {
		return model.SSHInboundPlan{Inbounds: []model.SSHInbound{{InboundID: 1, ServerID: 1, ListenIP: "127.0.0.1", Port: 2222, Enabled: true, Users: []model.SSHInboundUser{candidate}}}}
	}
	for name, mutate := range map[string]func(*model.SSHInboundUser){
		"missing path":         func(user *model.SSHInboundUser) { user.PathID = 0 },
		"missing route":        func(user *model.SSHInboundUser) { user.RouteKind = "" },
		"direct with tag":      func(user *model.SSHInboundUser) { user.OutboundTag = "path-1-step-1" },
		"outbound without tag": func(user *model.SSHInboundUser) { user.RouteKind = "outbound" },
		"unmanaged tag":        func(user *model.SSHInboundUser) { user.RouteKind = "outbound"; user.OutboundTag = "direct" },
	} {
		t.Run(name, func(t *testing.T) {
			candidate := user
			mutate(&candidate)
			if err := validateSSHInboundPlan(plan(candidate)); err == nil {
				t.Fatalf("invalid route was accepted: %#v", candidate)
			}
		})
	}
	user.RouteKind = "outbound"
	user.OutboundTag = "path-9-step-2"
	if err := validateSSHInboundPlan(plan(user)); err != nil {
		t.Fatalf("valid outbound route was rejected: %v", err)
	}
}

func TestSSHOutboundRouteRequiresKernelCapability(t *testing.T) {
	runner := New(Config{StateDir: t.TempDir()})
	runner.coreClient = &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(`{"capabilities":["runtime_clock_v1"]}`)), Header: make(http.Header)}, nil
	})}
	user := testSSHInboundUser(1, "alice", "password")
	user.RouteKind = "outbound"
	user.OutboundTag = "path-9-step-1"
	plan := model.SSHInboundPlan{Inbounds: []model.SSHInbound{{InboundID: 1, ServerID: 1, ListenIP: "127.0.0.1", Port: 2222, Enabled: true, Users: []model.SSHInboundUser{user}}}}
	if _, err := runner.newSSHInboundManager(plan); err == nil || !strings.Contains(err.Error(), outboundRelayCapability) {
		t.Fatalf("missing relay capability error = %v", err)
	}
}

func TestDialSSHRelayAddressesUsesSelectedOutbound(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()
	var network, tag, destination string
	conn, err := dialSSHRelayAddresses(t.Context(), func(_ context.Context, gotNetwork, gotTag, gotDestination string) (net.Conn, error) {
		network, tag, destination = gotNetwork, gotTag, gotDestination
		return client, nil
	}, "path-9-step-1", []netip.Addr{netip.MustParseAddr("1.1.1.1")}, 443)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if network != "tcp" || tag != "path-9-step-1" || destination != "1.1.1.1:443" {
		t.Fatalf("relay dial = %q %q %q", network, tag, destination)
	}
}
