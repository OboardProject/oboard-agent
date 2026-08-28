package agent

import (
	"context"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/OboardProject/oboard-agent/internal/model"
)

func TestRunLatencyProbeRejectsInvalidTargetsAndKeepsOtherResults(t *testing.T) {
	probe := func(_ context.Context, host string, _ int, count int, _, _ time.Duration) ([]int64, []string) {
		if host != "192.0.2.1" || count != 1 {
			t.Fatalf("probe host=%q count=%d", host, count)
		}
		return []int64{12}, nil
	}
	report, runErr := (&Runner{}).runLatencyProbeTaskWithProbe(context.Background(), model.LatencyProbeTargetsPlan{
		ResourceVersion: "v1", Mode: model.LatencyProbeModeICMP, SampleCount: 1, IntervalMS: 25, TimeoutMS: 500,
		Targets: []model.LatencyProbeTarget{
			{ProbeID: "ok", Kind: "regional", Province: "测试", Carrier: "测试", Host: "192.0.2.1", IP: "192.0.2.1"},
			{ProbeID: "bad", Kind: "regional", Province: "测试", Carrier: "测试", Host: "2001:db8::1", IP: "2001:db8::1"},
		},
	}, probe)
	if runErr == nil || len(report.Items) != 2 || !report.Items[0].Available || report.Items[1].Error == "" {
		t.Fatalf("report=%#v err=%v", report, runErr)
	}
}

func TestRunLatencyProbeTargetLimit(t *testing.T) {
	targets := make([]model.LatencyProbeTarget, latencyProbeMaxTargets+1)
	if _, err := (&Runner{}).runLatencyProbeTask(context.Background(), model.LatencyProbeTargetsPlan{ResourceVersion: "v1", Targets: targets}); err == nil {
		t.Fatal("oversized target list was accepted")
	}
}

func TestApplyLatencyStats(t *testing.T) {
	result := model.LatencyProbeResult{}
	applyLatencyStats(&result, []int64{20, 10, 30, 15, 25}, 5)
	if result.SuccessCount != 5 || result.LatencyMS != 20 || result.MinLatencyMS != 10 || result.P95LatencyMS != 30 || result.JitterMS != 13 {
		t.Fatalf("unexpected latency stats: %#v", result)
	}
}

func TestValidLatencyProbeIPv4(t *testing.T) {
	for _, value := range []string{"127.0.0.1", "10.0.0.1", "169.254.1.1", "224.0.0.1", "2001:db8::1"} {
		if validLatencyProbeIPv4(mustParseAddr(t, value)) {
			t.Fatalf("non-public target %s was accepted", value)
		}
	}
	if !validLatencyProbeIPv4(mustParseAddr(t, "192.0.2.1")) {
		t.Fatal("public IPv4 target was rejected")
	}
}

func TestValidateLatencyProbeTargetAcceptsRegionalHostname(t *testing.T) {
	hostname := model.LatencyProbeTarget{ProbeID: "广东-中国电信-0", Kind: "regional", Province: "广东", Carrier: "中国电信", Host: "gd-ct-v4.ip.zstaticcdn.com", Port: 80}
	if err := validateLatencyProbeTarget(hostname, model.LatencyProbeModeTCP); err != nil {
		t.Fatal(err)
	}
	if err := validateLatencyProbeTarget(model.LatencyProbeTarget{ProbeID: "ok", Kind: "regional", Province: "广东", Carrier: "中国电信", Host: "gd-ct-v4.ip.zstaticcdn.com", IP: "192.0.2.1", Port: 80}, model.LatencyProbeModeTCP); err == nil {
		t.Fatal("hostname target with a prefilled IP was accepted")
	}
	if err := validateLatencyProbeTarget(model.LatencyProbeTarget{ProbeID: "ok", Kind: "regional", Province: "广东", Carrier: "中国电信", Host: "localhost", Port: 80}, model.LatencyProbeModeTCP); err == nil {
		t.Fatal("localhost regional host was accepted")
	}
	literal := model.LatencyProbeTarget{ProbeID: "广东-教育网-0", Kind: "regional", Province: "广东", Carrier: "教育网", Host: "192.0.2.1", IP: "192.0.2.1", Port: 80}
	if err := validateLatencyProbeTarget(literal, model.LatencyProbeModeTCP); err != nil {
		t.Fatal(err)
	}
}

func mustParseAddr(t *testing.T, value string) netip.Addr {
	t.Helper()
	addr, err := netip.ParseAddr(value)
	if err != nil {
		t.Fatal(err)
	}
	return addr
}

func TestApplyLatencyStatsEmpty(t *testing.T) {
	result := model.LatencyProbeResult{}
	applyLatencyStats(&result, nil, 3)
	if result.SuccessCount != 0 || result.LatencyMS != 0 || result.P95LatencyMS != 0 {
		t.Fatalf("empty latency stats should remain zero: %#v", result)
	}
}

func TestLatencyProbePlanVersionAndPendingStateSurviveRestart(t *testing.T) {
	stateDir := t.TempDir()
	plan := model.LatencyProbeTargetsPlan{Version: 10, ResourceVersion: "resource-v1", Mode: model.LatencyProbeModeTCP, Enabled: true, IntervalSeconds: 60, SampleCount: 1, IntervalMS: 150, TimeoutMS: 1000, Targets: []model.LatencyProbeTarget{{ProbeID: "public-cloudflare", Kind: "public", Host: "cp.cloudflare.com", Port: 443}}}
	runner := New(Config{AgentID: "agent-latency", StateDir: stateDir, ResourceProfile: "large", CommandTimeoutSeconds: 20})
	if err := runner.setLatencyProbePlan(plan); err != nil {
		t.Fatal(err)
	}
	if err := runner.setLatencyProbePlan(plan); err != nil {
		t.Fatalf("identical plan was not idempotent: %v", err)
	}
	conflict := plan
	conflict.IntervalSeconds = 120
	if err := runner.setLatencyProbePlan(conflict); err == nil {
		t.Fatal("different content at the same version was accepted")
	}
	stale := plan
	stale.Version = 9
	if err := runner.setLatencyProbePlan(stale); err == nil {
		t.Fatal("older plan version was accepted")
	}
	report := model.LatencyProbeResultReport{ReportID: "offline-report", ResourceVersion: plan.ResourceVersion, CheckedAt: time.Now().UTC(), Items: []model.LatencyProbeResult{{ProbeID: "public-cloudflare", Kind: "public", Mode: "tcp", Host: "cp.cloudflare.com", Port: 443, Available: true, LatencyMS: 20, MinLatencyMS: 20, P95LatencyMS: 20, SampleCount: 1, SuccessCount: 1}}}
	runner.latencyProbeMu.Lock()
	runner.latencyProbeState.Pending = append(runner.latencyProbeState.Pending, report)
	if err := runner.persistLatencyProbeStateLocked(); err != nil {
		runner.latencyProbeMu.Unlock()
		t.Fatal(err)
	}
	runner.latencyProbeMu.Unlock()
	if info, err := os.Stat(runner.latencyProbeStatePath()); err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("state file mode=%v err=%v", info.Mode().Perm(), err)
	}
	restarted := New(Config{AgentID: "agent-latency", StateDir: stateDir, ResourceProfile: "large", CommandTimeoutSeconds: 20})
	pending, ok := restarted.nextPendingLatencyProbeReport()
	if !ok || pending.ReportID != report.ReportID || restarted.latencyProbeState.Plan.Version != plan.Version {
		t.Fatalf("restored state = %#v pending=%#v", restarted.latencyProbeState, pending)
	}
	if err := restarted.ackLatencyProbeReport(report.ReportID); err != nil {
		t.Fatal(err)
	}
	afterAck := New(Config{AgentID: "agent-latency", StateDir: stateDir, ResourceProfile: "large", CommandTimeoutSeconds: 20})
	if _, ok := afterAck.nextPendingLatencyProbeReport(); ok {
		t.Fatal("acknowledged report survived restart")
	}
}

func TestQueueLatencyProbeReportRollsBackWhenPersistenceFails(t *testing.T) {
	statePath := filepath.Join(t.TempDir(), "not-a-directory")
	if err := os.WriteFile(statePath, []byte("blocked"), 0o600); err != nil {
		t.Fatal(err)
	}
	runner := New(Config{AgentID: "agent-latency", StateDir: statePath, ResourceProfile: "large", CommandTimeoutSeconds: 20})
	runner.latencyProbeStateLoaded = true
	runner.latencyProbeState.Pending = []model.LatencyProbeResultReport{{ReportID: "already-durable", CheckedAt: time.Now().UTC()}}
	report := model.LatencyProbeResultReport{ReportID: "not-durable", CheckedAt: time.Now().UTC()}
	if err := runner.queueLatencyProbeReport(report, time.Now().UTC()); err == nil {
		t.Fatal("queue succeeded despite an unwritable state path")
	}
	if len(runner.latencyProbeState.Pending) != 1 || runner.latencyProbeState.Pending[0].ReportID != "already-durable" {
		t.Fatalf("failed persistence changed pending state: %#v", runner.latencyProbeState.Pending)
	}
}
