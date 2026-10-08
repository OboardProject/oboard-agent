package agent

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func hiddenSwitchFixture(t *testing.T, manager string) (*Runner, *[]string) {
	t.Helper()
	commands := fakeSwitchEnvironment(t, manager)
	install, configParent, _, config, state := standardLayoutFixture(t)
	original := unitDirForManager
	unitDirForManager = func(string) string { return filepath.Join(configParent, "units") }
	t.Cleanup(func() { unitDirForManager = original })
	r := runnerForSwitch(t, install, config, state)
	if _, err := r.applyStealthTask("{\"enable\":true}"); err != nil {
		t.Fatal(err)
	}
	cfg := r.Config()
	binary := filepath.Join(filepath.Dir(cfg.CoreBinary), cfg.Stealth.Identity.AgentName)
	osExecutable = func() (string, error) { return binary, nil }
	r.reconcileStealthSwitchCleanup()
	r.stealthSwitchPending = nil
	*commands = nil
	return r, commands
}

func TestStealthDisableStopFailurePreservesLayout(t *testing.T) {
	for _, manager := range []string{"systemd", "openrc"} {
		t.Run(manager, func(t *testing.T) {
			r, commands := hiddenSwitchFixture(t, manager)
			cfg := r.Config()
			runner := stealthCommandRunner
			stealthCommandRunner = func(timeout time.Duration, name string, args ...string) error {
				_ = runner(timeout, name, args...)
				return errors.New("injected stop failure")
			}
			if _, err := r.applyStealthTask("{\"enable\":false}"); err == nil {
				t.Fatal("stop failure accepted")
			}
			if !r.stealthOn() || r.coreService() != cfg.CoreService {
				t.Fatal("failed stop changed active layout")
			}
			if r.stealthSwitchPending != nil {
				t.Fatal("failed stop armed handoff")
			}
			if _, err := os.Stat(cfg.CoreBinary); err != nil {
				t.Fatal(err)
			}
			if _, err := os.Stat(cfg.Stealth.Origin.AgentBinary); !os.IsNotExist(err) {
				t.Fatalf("replacement copied after stop failure: %v", err)
			}
			if len(*commands) != 1 {
				t.Fatalf("commands after stop failure: %v", *commands)
			}
			stealthCommandRunner = runner
			if _, err := r.applyStealthTask("{\"enable\":false}"); err != nil {
				t.Fatalf("retry: %v", err)
			}
		})
	}
}

func TestStealthDisableStartFailureRollsBackAndRetries(t *testing.T) {
	for _, manager := range []string{"systemd", "openrc"} {
		t.Run(manager, func(t *testing.T) {
			r, commands := hiddenSwitchFixture(t, manager)
			cfg := r.Config()
			desired := []byte("{\"inbounds\":[],\"outbounds\":[]}")
			if err := r.stateWrite(singBoxConfigFile, desired, 0600); err != nil {
				t.Fatal(err)
			}
			// The kernel serves the restored plaintext config once the replacement starts.
			kernel := newFakeCoreKernel(t, filepath.Join(cfg.Stealth.Origin.StateDir, singBoxConfigFile), true)
			r.coreClient = kernel.client
			r.coreServiceActiveCheck = func() error { return nil }
			base := stealthCommandRunner
			fail := true
			stealthCommandRunner = func(timeout time.Duration, name string, args ...string) error {
				_ = base(timeout, name, args...)
				joined := strings.Join(args, " ")
				if joined == "start oboard-sb" || joined == "oboard-sb start" {
					if fail {
						return errors.New("injected replacement start failure")
					}
					kernel.boot()
				}
				return nil
			}
			if _, err := r.applyStealthTask("{\"enable\":false}"); err == nil || !strings.Contains(err.Error(), "injected replacement") {
				t.Fatalf("error = %v", err)
			}
			if !r.stealthOn() || r.coreService() != cfg.CoreService {
				t.Fatal("rollback did not restore old config")
			}
			if r.stealthSwitchPending != nil {
				t.Fatal("failed start armed handoff")
			}
			startNew, stopNew, startOld := -1, -1, -1
			for i, command := range *commands {
				if strings.Contains(command, "start oboard-sb") || strings.Contains(command, "oboard-sb start") {
					startNew = i
				}
				if strings.Contains(command, "stop oboard-sb") || strings.Contains(command, "oboard-sb stop") {
					stopNew = i
				}
				if strings.Contains(command, "start "+cfg.CoreService) || strings.Contains(command, cfg.CoreService+" start") {
					startOld = i
				}
			}
			if startNew < 0 || stopNew <= startNew || startOld <= stopNew {
				t.Fatalf("unsafe rollback order: %v", *commands)
			}
			fail = false
			if _, err := r.applyStealthTask("{\"enable\":false}"); err != nil {
				t.Fatalf("retry after copied files and failed startup: %v", err)
			}
			if r.stealthOn() || r.coreService() != "oboard-sb" || r.stealthSwitchPending == nil {
				t.Fatal("retry did not complete switch")
			}
		})
	}
}

func TestStealthCleanupStopFailureKeepsRecoveryRecord(t *testing.T) {
	for _, manager := range []string{"systemd", "openrc"} {
		t.Run(manager, func(t *testing.T) {
			r, _ := hiddenSwitchFixture(t, manager)
			if _, err := r.applyStealthTask("{\"enable\":false}"); err != nil {
				t.Fatal(err)
			}
			cfg := r.Config()
			previous := *cfg.Stealth.Previous
			osExecutable = func() (string, error) { return cfg.Stealth.Origin.AgentBinary, nil }
			base := stealthCommandRunner
			stealthCommandRunner = func(time.Duration, string, ...string) error { return errors.New("injected stop failure") }
			r.reconcileStealthSwitchCleanup()
			if r.Config().Stealth.Previous == nil {
				t.Fatal("cleanup dropped retry record")
			}
			if _, err := os.Stat(previous.CoreBinary); err != nil {
				t.Fatalf("cleanup removed old files: %v", err)
			}
			saved, err := LoadConfig(cfg.ConfigPath)
			if err != nil || saved.Stealth.Previous == nil {
				t.Fatalf("persisted retry record missing: %v", err)
			}
			stealthCommandRunner = base
			r.reconcileStealthSwitchCleanup()
			if r.Config().Stealth.Previous != nil {
				t.Fatal("cleanup retry did not finish")
			}
		})
	}
}

func TestStealthRestoreBinaryRetryAndConflicts(t *testing.T) {
	dir := t.TempDir()
	source, target := filepath.Join(dir, "source"), filepath.Join(dir, "target")
	if err := os.WriteFile(source, []byte("binary"), 0755); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		if err := copyStealthRestoreBinary(source, target); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(target, []byte("unrelated"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := copyStealthRestoreBinary(source, target); err == nil {
		t.Fatal("overwrote unrelated binary")
	}
	if err := os.Remove(target); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(source, target); err != nil {
		t.Fatal(err)
	}
	if err := copyStealthRestoreBinary(source, target); err == nil {
		t.Fatal("accepted symlink")
	}
}

func TestStealthHandoffStopsBeforeStartingAndRollsBack(t *testing.T) {
	for _, manager := range []string{"systemd", "openrc"} {
		for _, failure := range []string{"old_stop", "new_start", "new_stop", "none"} {
			t.Run(manager+"/"+failure, func(t *testing.T) {
				dir := t.TempDir()
				log := filepath.Join(dir, "commands")
				script := "#!/bin/sh\necho \"$*\" >> \"$TEST_HANDOFF_LOG\"\ncase \"$*\" in\n'stop old-agent'|'old-agent stop') [ \"$TEST_HANDOFF_FAIL\" != old_stop ] || exit 1;;\n'restart new-agent'|'new-agent restart') [ \"$TEST_HANDOFF_FAIL\" = none ] || exit 1;;\n'stop new-agent'|'new-agent stop') [ \"$TEST_HANDOFF_FAIL\" != new_stop ] || exit 1;;\nesac\nexit 0\n"
				tool := "systemctl"
				if manager == "openrc" {
					tool = "rc-service"
				}
				if err := os.WriteFile(filepath.Join(dir, tool), []byte(script), 0755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(dir, "rc-update"), []byte(script), 0755); err != nil {
					t.Fatal(err)
				}
				p := stealthSwitchFinalizer{Manager: manager, OldService: "old-agent", NewService: "new-agent", OldCore: "old-core", NewCore: "new-core", RestoreCore: true}
				cmd := exec.Command("/bin/sh", "-c", p.handoffCommand())
				cmd.Env = append(os.Environ(), "PATH="+dir+":"+os.Getenv("PATH"), "TEST_HANDOFF_LOG="+log, "TEST_HANDOFF_FAIL="+failure)
				err := cmd.Run()
				if (err == nil) != (failure == "none") {
					t.Fatalf("handoff error: %v", err)
				}
				data, err := os.ReadFile(log)
				if err != nil {
					t.Fatal(err)
				}
				lines := strings.Split(strings.TrimSpace(string(data)), "\n")
				wantCount := map[string]int{"old_stop": 1, "new_start": 10, "new_stop": 3, "none": 2}[failure]
				if len(lines) != wantCount {
					t.Fatalf("unsafe handoff: %s", data)
				}
				if failure == "new_start" {
					if !strings.Contains(lines[3], "new-core") || !strings.Contains(lines[8], "old-core") || !strings.Contains(lines[9], "old-agent") {
						t.Fatalf("unsafe rollback: %s", data)
					}
				}
			})
		}
	}
}

func TestStealthHandoffScheduleFailureCanRetry(t *testing.T) {
	r, _ := hiddenSwitchFixture(t, "systemd")
	r.armStealthSwitchFinalizer("old-agent", "new-agent", "systemd")
	base := stealthCommandRunner
	stealthCommandRunner = func(time.Duration, string, ...string) error { return errors.New("schedule failure") }
	if err := r.runStealthSwitchFinalizer(); err == nil {
		t.Fatal("schedule failure ignored")
	}
	if r.stealthSwitchPending == nil {
		t.Fatal("lost pending handoff")
	}
	stealthCommandRunner = base
	if err := r.runStealthSwitchFinalizer(); err != nil {
		t.Fatal(err)
	}
}

func TestStealthDisablePartialCopyCanRetry(t *testing.T) {
	r, _ := hiddenSwitchFixture(t, "systemd")
	realm := r.realmBinary()
	data, err := os.ReadFile(realm)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(realm); err != nil {
		t.Fatal(err)
	}
	if _, err := r.applyStealthTask("{\"enable\":false}"); err == nil {
		t.Fatal("missing realm accepted")
	}
	if !r.stealthOn() {
		t.Fatal("partial copy changed active config")
	}
	if err := os.WriteFile(realm, data, 0755); err != nil {
		t.Fatal(err)
	}
	if _, err := r.applyStealthTask("{\"enable\":false}"); err != nil {
		t.Fatalf("retry after partial copy: %v", err)
	}
}

func TestStealthDisableRollbackStopFailureNeverRestartsOldCore(t *testing.T) {
	r, commands := hiddenSwitchFixture(t, "systemd")
	old := r.coreService()
	if err := r.stateWrite(singBoxConfigFile, []byte("{}"), 0600); err != nil {
		t.Fatal(err)
	}
	base := stealthCommandRunner
	stealthCommandRunner = func(timeout time.Duration, name string, args ...string) error {
		_ = base(timeout, name, args...)
		switch strings.Join(args, " ") {
		case "start oboard-sb", "stop oboard-sb":
			return errors.New("injected replacement failure")
		}
		return nil
	}
	if _, err := r.applyStealthTask("{\"enable\":false}"); err == nil || !strings.Contains(err.Error(), "rollback refused") {
		t.Fatalf("error = %v", err)
	}
	for _, command := range *commands {
		if command == "systemctl start "+old {
			t.Fatalf("old core restarted while replacement may run: %v", *commands)
		}
	}
	if !r.stealthOn() {
		t.Fatal("retry must retain previous configuration")
	}
}
