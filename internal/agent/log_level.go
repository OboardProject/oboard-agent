package agent

import (
	"time"

	"github.com/OboardProject/oboard-agent/internal/logging"
)

const (
	// defaultVerboseLogTTL is how long a verbose level survives when the
	// operator did not pick a deadline. Verbose logging is a diagnostic tool,
	// not a running mode, and a node left at debug will fill its disk long
	// after whoever raised it stopped watching.
	defaultVerboseLogTTL = 6 * time.Hour
	// maxVerboseLogTTL bounds an operator-supplied deadline for the same reason.
	maxVerboseLogTTL = 72 * time.Hour
	// verboseLogMaintenanceInterval keeps rotation checks close together while a
	// verbose level is active, so a burst cannot overshoot the size ceiling by
	// much before the next sweep truncates it.
	verboseLogMaintenanceInterval = 5 * time.Second
	// agentLogTotalBudgetBytes and coreLogTotalBudgetBytes cap the whole
	// on-disk footprint of one service's log set (current file plus retained
	// backups). Per-file size and backup count stay operator-controlled; these
	// ceilings only stop a combination that would outgrow a small node's disk.
	agentLogTotalBudgetBytes = 256 << 20
	coreLogTotalBudgetBytes  = 512 << 20
)

const logLevelExpiryLayout = time.RFC3339

// normalizeLogLevelPolicy settles the stored level and its deadline. A verbose
// level always carries an expiry after this runs, and a quiet level never does.
func normalizeLogLevelPolicy(cfg Config, now time.Time) Config {
	level, ok := logging.ParseLevel(cfg.LogLevel)
	if !ok {
		level = logging.DefaultLevel
	}
	cfg.LogLevel = level.String()
	if !level.Verbose() {
		cfg.LogLevelExpiresAt = ""
		return cfg
	}
	deadline, err := time.Parse(logLevelExpiryLayout, cfg.LogLevelExpiresAt)
	if cfg.LogLevelExpiresAt == "" || err != nil {
		deadline = now.Add(defaultVerboseLogTTL)
	}
	if limit := now.Add(maxVerboseLogTTL); deadline.After(limit) {
		deadline = limit
	}
	cfg.LogLevelExpiresAt = deadline.UTC().Format(logLevelExpiryLayout)
	return cfg
}

// resolveLogLevel reports the level to run at right now. The second result is
// true when a verbose level has outlived its deadline and must be written back
// as the default.
func resolveLogLevel(cfg Config, now time.Time) (logging.Level, bool) {
	level, ok := logging.ParseLevel(cfg.LogLevel)
	if !ok {
		return logging.DefaultLevel, false
	}
	if !level.Verbose() || cfg.LogLevelExpiresAt == "" {
		return level, false
	}
	deadline, err := time.Parse(logLevelExpiryLayout, cfg.LogLevelExpiresAt)
	if err != nil {
		return logging.DefaultLevel, true
	}
	if now.Before(deadline) {
		return level, false
	}
	return logging.DefaultLevel, true
}

// refreshLogLevel applies the configured level to the process and retires an
// expired verbose level, persisting the change so a restart does not resurrect
// it. It returns the level now in effect.
func (r *Runner) refreshLogLevel() logging.Level {
	cfg := r.Config()
	level, expired := resolveLogLevel(cfg, time.Now())
	if expired {
		next := cfg
		next.LogLevel = logging.DefaultLevel.String()
		next.LogLevelExpiresAt = ""
		if path := agentConfigPath(next); path != "" {
			if err := SaveConfig(path, next); err != nil {
				logging.Errorf("log level expiry could not be persisted path=%s: %v", path, err)
			}
		}
		r.storeConfig(next)
		logging.Warnf("verbose log level expired; returning to %s", logging.DefaultLevel)
	}
	logging.SetLevel(level)
	return level
}

func agentConfigPath(cfg Config) string {
	if cfg.ConfigPath != "" {
		return cfg.ConfigPath
	}
	return "/etc/oboard-agent/config.json"
}

// logMaintenanceInterval is the rotation sweep cadence for the current storage
// profile, tightened while a verbose level is active.
func (r *Runner) logMaintenanceInterval() time.Duration {
	return verboseAwareInterval(r.logMaintenanceEvery)
}

func verboseAwareInterval(base time.Duration) time.Duration {
	if base <= 0 {
		base = logMaintenanceInterval
	}
	if logging.CurrentLevel().Verbose() && base > verboseLogMaintenanceInterval {
		return verboseLogMaintenanceInterval
	}
	return base
}

// applyLogTotalBudget lowers a retention plan until the whole log set fits the
// service ceiling. Backups are given up before per-file size, because losing
// history is less damaging than losing the record of what just happened.
func applyLogTotalBudget(maxBytes int64, backups int, budget int64) (int64, int) {
	if maxBytes <= 0 || budget <= 0 {
		return maxBytes, backups
	}
	if backups < 0 {
		backups = 0
	}
	for backups > 0 && maxBytes*int64(backups+1) > budget {
		backups--
	}
	if maxBytes > budget {
		maxBytes = budget
	}
	return maxBytes, backups
}
