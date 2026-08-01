package agent

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/OboardProject/oboard-agent/internal/model"
)

func withNTPQueryStub(t *testing.T, query func(context.Context, string) (time.Duration, error)) {
	t.Helper()
	previous := queryNTPSource
	queryNTPSource = query
	t.Cleanup(func() { queryNTPSource = previous })
}

func TestQueryNTPMedianRequiresTwoSourcesAndUsesMedian(t *testing.T) {
	withNTPQueryStub(t, func(_ context.Context, server string) (time.Duration, error) {
		switch server {
		case "one.example":
			return -12 * time.Second, nil
		case "two.example":
			return 3 * time.Second, nil
		case "three.example":
			return 40 * time.Second, nil
		default:
			return 0, errors.New("unexpected source")
		}
	})
	reference, err := queryNTPMedian(context.Background(), []string{"one.example", "two.example", "three.example"})
	if err != nil {
		t.Fatal(err)
	}
	if reference.Offset != 3*time.Second || !strings.Contains(reference.Source, "one.example") || !strings.Contains(reference.Source, "three.example") {
		t.Fatalf("median reference = %#v", reference)
	}

	withNTPQueryStub(t, func(_ context.Context, server string) (time.Duration, error) {
		if server == "one.example" {
			return time.Second, nil
		}
		return 0, errors.New("unavailable")
	})
	if _, err := queryNTPMedian(context.Background(), []string{"one.example", "two.example", "three.example"}); err == nil || !strings.Contains(err.Error(), "至少需要两个") {
		t.Fatalf("single-source result error = %v", err)
	}
}

func TestNormalizeNTPServersCanonicalizesIPv6AndRejectsPorts(t *testing.T) {
	servers, err := normalizeNTPServers([]string{"[2001:db8::1]", "time.example.com", "192.0.2.1"})
	if err != nil {
		t.Fatal(err)
	}
	if servers[0] != "2001:db8::1" {
		t.Fatalf("normalized IPv6 NTP server = %q", servers[0])
	}
	if _, err := normalizeNTPServers([]string{"[2001:db8::1]:123", "time.example.com", "192.0.2.1"}); err == nil {
		t.Fatal("NTP server with an explicit port was accepted")
	}
}

func TestResolveTimeReferenceRejectsControllerNTPConflict(t *testing.T) {
	withNTPQueryStub(t, func(context.Context, string) (time.Duration, error) { return 0, nil })
	runner := New(Config{StateDir: t.TempDir(), TimeSyncCommand: "none", ResourceProfile: "large"})
	runner.setControllerReference(time.Now().Add(10 * time.Second))
	_, err := runner.resolveTimeReference(context.Background(), []string{"one.example", "two.example", "three.example"})
	if err == nil || !strings.Contains(err.Error(), "拒绝应用") {
		t.Fatalf("controller/NTP conflict error = %v", err)
	}
}

func TestTimeCorrectionModesUseExpectedClockStrategy(t *testing.T) {
	withNTPQueryStub(t, func(context.Context, string) (time.Duration, error) { return 45 * time.Second, nil })
	tests := []struct {
		name            string
		mode            model.TimeCorrectionMode
		wantStatus      string
		wantLogical     bool
		wantSystemTry   bool
		wantSystemError bool
		wantEffectiveMS int64
	}{
		{name: "off only reports skew", mode: model.TimeCorrectionOff, wantStatus: "skewed", wantEffectiveMS: 45_000},
		{name: "auto falls back to logical clock", mode: model.TimeCorrectionAuto, wantStatus: "corrected", wantLogical: true, wantSystemTry: true, wantSystemError: true},
		{name: "ntp directly enables logical clock", mode: model.TimeCorrectionNTP, wantStatus: "corrected", wantLogical: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			runner := New(Config{StateDir: t.TempDir(), TimeSyncCommand: "none", ResourceProfile: "large"})
			result, err := runner.runTimeCheckTask(context.Background(), model.TimeCheckPlan{CorrectionMode: test.mode, ThresholdSeconds: 30, NTPServers: []string{"one.example", "two.example", "three.example"}})
			if err != nil {
				t.Fatal(err)
			}
			if result.Status != test.wantStatus || result.LogicalTimeActive != test.wantLogical || result.SystemSyncAttempted != test.wantSystemTry {
				t.Fatalf("time result = %#v", result)
			}
			if result.EffectiveOffsetMS != test.wantEffectiveMS {
				t.Fatalf("effective offset = %d, want %d", result.EffectiveOffsetMS, test.wantEffectiveMS)
			}
			if (result.SystemSyncError != "") != test.wantSystemError {
				t.Fatalf("system sync error = %q", result.SystemSyncError)
			}
			if test.wantLogical && absDuration(runner.clock.Now().Sub(time.Now().Add(45*time.Second))) > time.Second {
				t.Fatalf("logical clock did not apply expected offset: now=%s", runner.clock.Now())
			}
		})
	}
}

func TestTimeCheckKeepsEffectiveOffsetWhenCorrectionIsNotNeeded(t *testing.T) {
	withNTPQueryStub(t, func(context.Context, string) (time.Duration, error) { return 12 * time.Second, nil })
	for _, mode := range []model.TimeCorrectionMode{model.TimeCorrectionOff, model.TimeCorrectionAuto, model.TimeCorrectionNTP} {
		runner := New(Config{StateDir: t.TempDir(), TimeSyncCommand: "none", ResourceProfile: "large"})
		result, err := runner.runTimeCheckTask(context.Background(), model.TimeCheckPlan{CorrectionMode: mode, ThresholdSeconds: 30, NTPServers: []string{"one.example", "two.example", "three.example"}})
		if err != nil {
			t.Fatalf("mode %s: %v", mode, err)
		}
		if result.Status != "ok" || result.RawOffsetMS != 12_000 || result.EffectiveOffsetMS != 12_000 || result.LogicalTimeActive {
			t.Fatalf("mode %s result = %#v", mode, result)
		}
	}
}

func TestRuntimeClockPersistsAndRestoresMonotonicReference(t *testing.T) {
	dir := t.TempDir()
	clock := newRuntimeClock(dir)
	reference := time.Now().UTC().Add(2 * time.Minute)
	if err := clock.Apply(true, reference, "ntp:test", reference); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(filepath.Join(dir, runtimeClockStateFile))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("runtime clock state mode = %o", info.Mode().Perm())
	}
	restored := newRuntimeClock(dir)
	if !restored.Snapshot().Enabled || restored.Snapshot().Source != "ntp:test" {
		t.Fatalf("restored clock state = %#v", restored.Snapshot())
	}
	if absDuration(restored.Now().Sub(clock.Now())) > time.Second {
		t.Fatalf("restored clock differs: restored=%s original=%s", restored.Now(), clock.Now())
	}
}

func TestTurningTimeCorrectionOffClearsLogicalClockWhenSourcesFail(t *testing.T) {
	withNTPQueryStub(t, func(context.Context, string) (time.Duration, error) { return 0, errors.New("offline") })
	runner := New(Config{StateDir: t.TempDir(), TimeSyncCommand: "none", TimeCorrectionMode: model.TimeCorrectionNTP, ResourceProfile: "large"})
	if err := runner.clock.Apply(true, time.Now().Add(time.Minute), "previous", time.Now()); err != nil {
		t.Fatal(err)
	}
	result, err := runner.runTimeCheckTask(context.Background(), model.TimeCheckPlan{CorrectionMode: model.TimeCorrectionOff, NTPServers: []string{"one.example", "two.example", "three.example"}})
	if err == nil || result.Status != "unavailable" {
		t.Fatalf("off mode failure result = %#v, err=%v", result, err)
	}
	if runner.clock.Snapshot().Enabled || result.LogicalTimeActive {
		t.Fatalf("logical clock remained active: state=%#v result=%#v", runner.clock.Snapshot(), result)
	}
}
