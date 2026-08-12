package agent

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"github.com/OboardProject/oboard-agent/internal/model"
)

func TestRunLatencyProbeRejectsInvalidTargetsAndKeepsOtherResults(t *testing.T) {
	probe := func(_ context.Context, host string, count int, _, _ time.Duration) ([]int64, []string) {
		if host != "192.0.2.1" || count != 1 {
			t.Fatalf("probe host=%q count=%d", host, count)
		}
		return []int64{12}, nil
	}
	report, runErr := (&Runner{}).runLatencyProbeTaskWithProbe(context.Background(), model.LatencyProbeTargetsPlan{
		ResourceVersion: "v1", SampleCount: 1, IntervalMS: 25, TimeoutMS: 500,
		Targets: []model.LatencyProbeTarget{
			{ProbeID: "ok", Province: "测试", Carrier: "测试", IP: "192.0.2.1"},
			{ProbeID: "bad", Province: "测试", Carrier: "测试", IP: "2001:db8::1"},
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
