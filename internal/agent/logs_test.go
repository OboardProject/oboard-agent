package agent

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/OboardProject/oboard-agent/internal/model"
)

func TestRotateLogFileCopyTruncatesAndRetainsTail(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "agent.log")
	content := strings.Repeat("old\n", 100) + "last-lines\n"
	if err := os.WriteFile(path, []byte(content), 0o640); err != nil {
		t.Fatal(err)
	}
	if err := rotateLogFile(managedLog{Path: path, MaxBytes: 64, Backups: 2}); err != nil {
		t.Fatal(err)
	}
	current, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(current) != 0 {
		t.Fatalf("current log size = %d, want 0", len(current))
	}
	backup, err := os.ReadFile(path + ".1")
	if err != nil {
		t.Fatal(err)
	}
	if len(backup) > 64 || !strings.HasSuffix(string(backup), "last-lines\n") {
		t.Fatalf("backup was not bounded tail: %q", backup)
	}
}

func TestRotateLogFileShiftsBackups(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "core.log")
	if err := os.WriteFile(path, []byte("current"), 0o640); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path+".1", []byte("previous"), 0o640); err != nil {
		t.Fatal(err)
	}
	if err := rotateLogFile(managedLog{Path: path, MaxBytes: 1024, Backups: 2}); err != nil {
		t.Fatal(err)
	}
	second, err := os.ReadFile(path + ".2")
	if err != nil {
		t.Fatal(err)
	}
	if string(second) != "previous" {
		t.Fatalf("second backup = %q, want previous", second)
	}
}

func TestClearLogFileRemovesBackups(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "agent.log")
	for _, name := range []string{path, path + ".1", path + ".2", path + ".9"} {
		if err := os.WriteFile(name, []byte("log data"), 0o640); err != nil {
			t.Fatal(err)
		}
	}
	if err := clearLogFile(path, 2); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Size() != 0 {
		t.Fatalf("current log size = %d, want 0", info.Size())
	}
	for _, name := range []string{path + ".1", path + ".2", path + ".9"} {
		if _, err := os.Stat(name); !os.IsNotExist(err) {
			t.Fatalf("backup still exists: %s", name)
		}
	}
}

func TestPruneLogBackupsAppliesReducedRetention(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "agent.log")
	for _, name := range []string{path + ".1", path + ".2", path + ".5", path + ".1.tmp-123"} {
		if err := os.WriteFile(name, []byte("old"), 0o640); err != nil {
			t.Fatal(err)
		}
	}
	if err := pruneLogBackups(path, 1); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path + ".1"); err != nil {
		t.Fatalf("retained backup was removed: %v", err)
	}
	for _, name := range []string{path + ".2", path + ".5", path + ".1.tmp-123"} {
		if _, err := os.Stat(name); !os.IsNotExist(err) {
			t.Fatalf("excess backup still exists: %s", name)
		}
	}
}

func TestReadManagedLogTailIncludesRotatedFiles(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "core.log")
	if err := os.WriteFile(path+".1", []byte("older-one\nolder-two\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("current-one\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	result := readManagedLogTail(path, 2, 3)
	if ok, _ := result["ok"].(bool); !ok {
		t.Fatalf("managed tail failed: %#v", result)
	}
	content, _ := result["content"].(string)
	if content != "older-one\nolder-two\ncurrent-one" {
		t.Fatalf("managed tail order = %q", content)
	}
	files, _ := result["files"].([]map[string]any)
	if len(files) != 2 {
		t.Fatalf("managed tail files = %#v", result["files"])
	}
}

func TestLogMaintenanceRotatesWhileControllerIsOffline(t *testing.T) {
	dir := t.TempDir()
	runner := New(Config{CoreService: "oboard-sb", LogMaxMB: 1, LogBackups: 1, CoreLogMaxMB: 1, CoreLogBackups: 1})
	runner.logDir = dir
	runner.logMaintenanceEvery = 10 * time.Millisecond
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	runner.startLogMaintenance(ctx)
	path := filepath.Join(dir, "oboard-agent.log")
	if err := os.WriteFile(path, []byte(strings.Repeat("x", (1<<20)+1024)), 0o640); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if backup, err := os.Stat(path + ".1"); err == nil && backup.Size() > 0 {
			current, err := os.Stat(path)
			if err != nil {
				t.Fatal(err)
			}
			if current.Size() != 0 {
				t.Fatalf("current log size = %d after offline maintenance", current.Size())
			}
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("offline log maintenance did not rotate oversized log")
}

func TestExecuteManageLogsTaskClearsSelectedServices(t *testing.T) {
	dir := t.TempDir()
	runner := New(Config{CoreService: "oboard-sb", LogMaxMB: 1, LogBackups: 2, CoreLogMaxMB: 1, CoreLogBackups: 2})
	runner.logDir = dir
	for _, name := range []string{"oboard-agent.log", "oboard-agent.log.1", "oboard-sb.log", "oboard-sb.log.1"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("task log"), 0o640); err != nil {
			t.Fatal(err)
		}
	}
	payload, err := json.Marshal(model.ManageLogsTaskPayload{Action: "clear", Services: "all"})
	if err != nil {
		t.Fatal(err)
	}
	status, result := runner.ExecuteAgentTask(model.AgentTask{Type: "manage_logs", PayloadJSON: string(payload)})
	if status != "succeeded" {
		t.Fatalf("manage_logs status=%s result=%s", status, result)
	}
	for _, name := range []string{"oboard-agent.log", "oboard-sb.log"} {
		info, err := os.Stat(filepath.Join(dir, name))
		if err != nil {
			t.Fatal(err)
		}
		if info.Size() != 0 {
			t.Fatalf("%s was not cleared", name)
		}
	}
	for _, name := range []string{"oboard-agent.log.1", "oboard-sb.log.1"} {
		if _, err := os.Stat(filepath.Join(dir, name)); !os.IsNotExist(err) {
			t.Fatalf("backup was not removed: %s", name)
		}
	}
}

func TestLoadConfigPreservesZeroBackups(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, []byte(`{"log_backups":0,"core_log_backups":0}`), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	cfg = normalizeConfig(cfg)
	if cfg.LogBackups != 0 || cfg.CoreLogBackups != 0 {
		t.Fatalf("zero backups were replaced: %#v", cfg)
	}
}
