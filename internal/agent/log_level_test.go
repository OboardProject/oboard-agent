package agent

import (
	"testing"
	"time"

	"github.com/OboardProject/oboard-agent/internal/logging"
)

func TestNormalizeLogLevelPolicyGivesVerboseADeadline(t *testing.T) {
	now := time.Date(2026, 9, 3, 10, 0, 0, 0, time.UTC)
	cfg := normalizeLogLevelPolicy(Config{LogLevel: "debug"}, now)
	if cfg.LogLevel != "debug" {
		t.Fatalf("level = %q, want debug", cfg.LogLevel)
	}
	deadline, err := time.Parse(logLevelExpiryLayout, cfg.LogLevelExpiresAt)
	if err != nil {
		t.Fatalf("expiry %q is not RFC 3339: %v", cfg.LogLevelExpiresAt, err)
	}
	if want := now.Add(defaultVerboseLogTTL); !deadline.Equal(want) {
		t.Fatalf("expiry = %s, want %s", deadline, want)
	}
}

func TestNormalizeLogLevelPolicyClampsAnOverlongDeadline(t *testing.T) {
	now := time.Date(2026, 9, 3, 10, 0, 0, 0, time.UTC)
	cfg := normalizeLogLevelPolicy(Config{
		LogLevel:          "trace",
		LogLevelExpiresAt: now.Add(30 * 24 * time.Hour).Format(logLevelExpiryLayout),
	}, now)
	deadline, err := time.Parse(logLevelExpiryLayout, cfg.LogLevelExpiresAt)
	if err != nil {
		t.Fatal(err)
	}
	if want := now.Add(maxVerboseLogTTL); !deadline.Equal(want) {
		t.Fatalf("expiry = %s, want it clamped to %s", deadline, want)
	}
}

func TestNormalizeLogLevelPolicyDropsDeadlineForQuietLevels(t *testing.T) {
	now := time.Now()
	cfg := normalizeLogLevelPolicy(Config{LogLevel: "warn", LogLevelExpiresAt: now.Format(logLevelExpiryLayout)}, now)
	if cfg.LogLevelExpiresAt != "" {
		t.Fatalf("quiet level kept an expiry: %q", cfg.LogLevelExpiresAt)
	}
}

func TestNormalizeLogLevelPolicyFallsBackOnAnUnknownName(t *testing.T) {
	cfg := normalizeLogLevelPolicy(Config{LogLevel: "chatty"}, time.Now())
	if cfg.LogLevel != logging.DefaultLevel.String() {
		t.Fatalf("level = %q, want %s", cfg.LogLevel, logging.DefaultLevel)
	}
}

func TestResolveLogLevelRetiresAnExpiredVerboseLevel(t *testing.T) {
	now := time.Date(2026, 9, 3, 10, 0, 0, 0, time.UTC)
	cfg := Config{LogLevel: "debug", LogLevelExpiresAt: now.Add(-time.Minute).Format(logLevelExpiryLayout)}
	level, expired := resolveLogLevel(cfg, now)
	if !expired || level != logging.DefaultLevel {
		t.Fatalf("resolveLogLevel = %v expired=%t, want %v expired=true", level, expired, logging.DefaultLevel)
	}
}

func TestResolveLogLevelKeepsALiveVerboseLevel(t *testing.T) {
	now := time.Date(2026, 9, 3, 10, 0, 0, 0, time.UTC)
	cfg := Config{LogLevel: "debug", LogLevelExpiresAt: now.Add(time.Hour).Format(logLevelExpiryLayout)}
	level, expired := resolveLogLevel(cfg, now)
	if expired || level != logging.LevelDebug {
		t.Fatalf("resolveLogLevel = %v expired=%t, want debug expired=false", level, expired)
	}
}

func TestRefreshLogLevelPersistsTheRetirement(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/agent.json"
	runner := &Runner{}
	runner.storeConfig(Config{
		ConfigPath:        path,
		LogLevel:          "debug",
		LogLevelExpiresAt: time.Now().Add(-time.Minute).Format(logLevelExpiryLayout),
	})
	if level := runner.refreshLogLevel(); level != logging.DefaultLevel {
		t.Fatalf("level = %v, want %v", level, logging.DefaultLevel)
	}
	if got := runner.Config().LogLevel; got != logging.DefaultLevel.String() {
		t.Fatalf("in-memory level = %q, want %s", got, logging.DefaultLevel)
	}
	stored, err := LoadConfig(path)
	if err != nil {
		t.Fatalf("expired level was not written back: %v", err)
	}
	if stored.LogLevel != logging.DefaultLevel.String() || stored.LogLevelExpiresAt != "" {
		t.Fatalf("stored level = %q expiry = %q, want %s with no expiry", stored.LogLevel, stored.LogLevelExpiresAt, logging.DefaultLevel)
	}
}

func TestApplyLogTotalBudgetGivesUpBackupsBeforeSize(t *testing.T) {
	const budget = 100
	maxBytes, backups := applyLogTotalBudget(40, 5, budget)
	if maxBytes != 40 {
		t.Fatalf("max bytes = %d, want the configured 40 kept", maxBytes)
	}
	if backups != 1 {
		t.Fatalf("backups = %d, want 1 so the set fits %d", backups, budget)
	}
	if total := maxBytes * int64(backups+1); total > budget {
		t.Fatalf("total %d exceeds budget %d", total, budget)
	}
}

func TestApplyLogTotalBudgetCapsAnOversizedSingleFile(t *testing.T) {
	maxBytes, backups := applyLogTotalBudget(500, 3, 100)
	if maxBytes != 100 || backups != 0 {
		t.Fatalf("got max=%d backups=%d, want max=100 backups=0", maxBytes, backups)
	}
}

func TestVerboseAwareIntervalTightensOnlyWhileVerbose(t *testing.T) {
	previous := logging.CurrentLevel()
	t.Cleanup(func() { logging.SetLevel(previous) })

	logging.SetLevel(logging.LevelInfo)
	if got := verboseAwareInterval(30 * time.Second); got != 30*time.Second {
		t.Fatalf("quiet interval = %s, want 30s untouched", got)
	}
	logging.SetLevel(logging.LevelDebug)
	if got := verboseAwareInterval(30 * time.Second); got != verboseLogMaintenanceInterval {
		t.Fatalf("verbose interval = %s, want %s", got, verboseLogMaintenanceInterval)
	}
	if got := verboseAwareInterval(time.Second); got != time.Second {
		t.Fatalf("verbose must not slow an already tighter sweep: got %s", got)
	}
}
