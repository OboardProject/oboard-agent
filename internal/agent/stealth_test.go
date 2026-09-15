package agent

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/OboardProject/oboard-agent/internal/stealth"
)

// fakeSwitchEnvironment neutralizes the service-manager invocations and pins
// the detected manager so the layout switch can run on any host.
func fakeSwitchEnvironment(t *testing.T, manager string) *[]string {
	t.Helper()
	commands := &[]string{}
	originalRunner := stealthCommandRunner
	originalManager := serviceManagerOverride
	originalEuid := stealthSwitchEuid
	stealthCommandRunner = func(timeout time.Duration, name string, args ...string) error {
		*commands = append(*commands, name+" "+strings.Join(args, " "))
		return nil
	}
	serviceManagerOverride = func() string { return manager }
	stealthSwitchEuid = func() int { return 0 }
	t.Cleanup(func() {
		stealthCommandRunner = originalRunner
		serviceManagerOverride = originalManager
		stealthSwitchEuid = originalEuid
	})
	return commands
}

// standardLayoutFixture creates a plausible standard installation inside temp
// directories: the three binaries, a config, and a state tree with the files
// the switch migrates.
func standardLayoutFixture(t *testing.T) (installDir, configParent, stateParent, configPath, stateDir string) {
	t.Helper()
	root := t.TempDir()
	installDir = filepath.Join(root, "bin")
	configParent = filepath.Join(root, "etc")
	stateParent = filepath.Join(root, "var")
	stateDir = filepath.Join(stateParent, "oboard-agent")
	if err := os.MkdirAll(installDir, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"oboard-agent", "oboard-sb", "oboard-realm"} {
		if err := os.WriteFile(filepath.Join(installDir, name), []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	configPath = filepath.Join(configParent, "oboard-agent", "config.json")
	if err := os.MkdirAll(filepath.Dir(configPath), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := SaveConfig(configPath, normalizeConfig(Config{ControllerURL: "https://controller.example.com", StateDir: stateDir, CoreBinary: filepath.Join(installDir, "oboard-sb"), CoreService: "oboard-sb"})); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(stateDir, "traffic-state.json"), []byte(`{"schema_version":2}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(stateDir, "last-applied-version.json"), []byte(`{"version":7}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(stateDir, "core-lifecycle.lock"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	tunnels := filepath.Join(stateDir, "tunnels", "42")
	if err := os.MkdirAll(tunnels, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(tunnels, "sshd-2200.conf"), []byte("Port 2200\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return installDir, configParent, stateParent, configPath, stateDir
}

func runnerForSwitch(t *testing.T, installDir, configPath, stateDir string) *Runner {
	t.Helper()
	cfg := Config{
		ConfigPath:    configPath,
		ControllerURL: "https://controller.example.com",
		StateDir:      stateDir,
		CoreBinary:    filepath.Join(installDir, "oboard-sb"),
		CoreService:   "oboard-sb",
	}
	cfg = normalizeConfig(cfg)
	runner := New(cfg)
	// Pin the executable resolution to the fixture's agent binary so the
	// switch copies from and reports the fixture layout.
	original := osExecutable
	osExecutable = func() (string, error) { return filepath.Join(installDir, "oboard-agent"), nil }
	t.Cleanup(func() { osExecutable = original })
	return runner
}

func TestStealthBootstrapCreatesHiddenLayout(t *testing.T) {
	commands := fakeSwitchEnvironment(t, "systemd")
	installDir, configParent, stateParent, configPath, _ := standardLayoutFixture(t)
	_ = configPath
	// The bootstrap runs as the downloaded agent binary inside the install
	// directory; pin the executable resolution the same way.
	original := osExecutable
	osExecutable = func() (string, error) { return filepath.Join(installDir, "oboard-agent"), nil }
	t.Cleanup(func() { osExecutable = original })
	unitDir := filepath.Join(configParent, "units")
	logDir := filepath.Join(configParent, "log")
	runDir := filepath.Join(configParent, "run")

	layout, err := RunStealthBootstrap(stealthBootstrapOptions{
		InstallDir:    installDir,
		Manager:       "systemd",
		ControllerURL: "https://controller.example.com",
		ConfigParent:  configParent,
		StateParent:   stateParent,
		UnitDir:       unitDir,
		LogDir:        logDir,
		RunDir:        runDir,
	})
	if err != nil {
		t.Fatal(err)
	}
	// The oboard-named binaries must be gone; the identity-named ones present.
	for _, name := range []string{"oboard-agent", "oboard-sb", "oboard-realm"} {
		if _, err := os.Stat(filepath.Join(installDir, name)); !os.IsNotExist(err) {
			t.Fatalf("%s should have been renamed away", name)
		}
	}
	for _, path := range []string{layout.AgentBinary, layout.CoreBinary, layout.RealmBinary, layout.KeyPath, layout.ConfigPath} {
		if _, err := os.Stat(path); err != nil {
			t.Fatalf("layout path %s missing: %v", path, err)
		}
	}
	// The config must be an envelope that only loads with the key.
	if _, err := LoadConfig(layout.ConfigPath); err == nil {
		t.Fatal("plaintext load of an encrypted config must fail")
	}
	key, err := stealth.LoadKey(layout.KeyPath)
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := LoadConfigWithKey(layout.ConfigPath, key)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.ControllerURL != "https://controller.example.com" || cfg.AgentService != layout.AgentService || cfg.Stealth == nil {
		t.Fatalf("decrypted config = %+v", cfg)
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("stealth config invalid: %v", err)
	}
	// Units reference the hidden paths and carry no OBoard markers.
	agentUnit, err := os.ReadFile(filepath.Join(unitDir, layout.AgentService+".service"))
	if err != nil {
		t.Fatal(err)
	}
	// The workspace path itself contains "oboard"; strip the temp root
	// before asserting that the unit carries no OBoard markers.
	unitContent := strings.ReplaceAll(string(agentUnit), filepath.Dir(filepath.Dir(configParent)), "")
	if strings.Contains(unitContent, "oboard") || strings.Contains(unitContent, "OBoard") {
		t.Fatalf("agent unit leaks the OBoard name:\n%s", agentUnit)
	}
	if !strings.Contains(string(agentUnit), "-key "+layout.KeyPath) {
		t.Fatalf("agent unit must pass the key file:\n%s", agentUnit)
	}
	if len(*commands) == 0 {
		t.Fatal("bootstrap must enable the new units")
	}
}

func TestApplyStealthEnableDisableRoundTrip(t *testing.T) {
	fakeSwitchEnvironment(t, "systemd")
	installDir, configParent, _, configPath, stateDir := standardLayoutFixture(t)
	// The unit directory is redirected through a writable location so the
	// switch never touches the real /etc.
	unitRedirect := map[string]string{"/etc/systemd/system": filepath.Join(configParent, "units")}
	originalUnitDir := unitDirForManager
	unitDirForManager = func(manager string) string {
		if dir, ok := unitRedirect["/etc/systemd/system"]; ok && manager == "systemd" {
			return dir
		}
		return originalUnitDir(manager)
	}
	t.Cleanup(func() { unitDirForManager = originalUnitDir })

	runner := runnerForSwitch(t, installDir, configPath, stateDir)
	result, err := runner.applyStealthTask(`{"enable":true}`)
	if err != nil {
		t.Fatalf("enable: %v (%v)", err, result)
	}
	if result["stealth_enabled"] != true {
		t.Fatalf("enable result = %#v", result)
	}
	newService, _ := result["agent_service"].(string)
	if newService == "" || newService == "oboard-agent" {
		t.Fatalf("agent service = %q", newService)
	}
	// The runner now speaks the hidden layout.
	if !runner.stealthOn() {
		t.Fatal("runner must be in stealth mode after enable")
	}
	hiddenStateDir := runner.stateDir()
	if hiddenStateDir == stateDir {
		t.Fatal("state dir must have moved to the hidden layout")
	}
	// The migrated traffic state must exist encrypted under its derived name.
	key := runner.Config().StealthKey
	trafficPhysical := stealth.PhysicalName(key, "traffic-state.json")
	raw, err := os.ReadFile(filepath.Join(hiddenStateDir, trafficPhysical))
	if err != nil {
		t.Fatalf("migrated traffic state missing: %v", err)
	}
	if !stealth.IsEncrypted(raw) {
		t.Fatal("migrated traffic state must be an envelope")
	}
	decrypted, err := runner.stateRead("traffic-state.json")
	if err != nil || !strings.Contains(string(decrypted), `"schema_version"`) {
		t.Fatalf("state read through the runner = %q, %v", decrypted, err)
	}
	// The lock file stays plaintext.
	if _, err := os.Stat(filepath.Join(hiddenStateDir, stealth.PhysicalName(key, "core-lifecycle.lock"))); err != nil {
		t.Fatalf("lock file must migrate: %v", err)
	}
	// The old layout still exists until the post-restart cleanup.
	if _, err := os.Stat(stateDir); err != nil {
		t.Fatalf("old state dir must survive until cleanup: %v", err)
	}
	if _, err := os.Stat(configPath); err != nil {
		t.Fatalf("old config must survive until cleanup: %v", err)
	}
	// The switch finalizer must be armed.
	runner.stealthSwitchMu.Lock()
	pending := runner.stealthSwitchPending
	runner.stealthSwitchMu.Unlock()
	if pending == nil || pending.NewService != newService || pending.OldService != "oboard-agent" {
		t.Fatalf("switch finalizer = %+v", pending)
	}

	// Simulate the restarted process: the executable now resolves to the
	// hidden binary, so the cleanup may remove the old layout.
	osExecutable = func() (string, error) { return filepath.Join(installDir, newService), nil }
	runner.reconcileStealthSwitchCleanup()
	if _, err := os.Stat(stateDir); !os.IsNotExist(err) {
		t.Fatalf("old state dir must be removed by cleanup: %v", err)
	}
	if _, err := os.Stat(configPath); !os.IsNotExist(err) {
		t.Fatalf("old config dir must be removed by cleanup: %v", err)
	}
	if _, err := os.Stat(filepath.Join(installDir, "oboard-agent")); !os.IsNotExist(err) {
		t.Fatal("old agent binary must be removed by cleanup")
	}
	if _, err := os.Stat(filepath.Join(installDir, newService)); err != nil {
		t.Fatalf("hidden agent binary must survive cleanup: %v", err)
	}
	if runner.Config().Stealth != nil && runner.Config().Stealth.Previous != nil {
		t.Fatal("cleanup must drop the previous-layout record")
	}

	// Disable back to the standard layout.
	disableResult, err := runner.applyStealthTask(`{"enable":false}`)
	if err != nil {
		t.Fatalf("disable: %v (%v)", err, disableResult)
	}
	if disableResult["stealth_enabled"] != false {
		t.Fatalf("disable result = %#v", disableResult)
	}
	if runner.stealthOn() {
		t.Fatal("runner must be back in standard mode")
	}
	// The restored state must be plaintext at the logical names in the
	// origin layout.
	if runner.stateDir() != stateDir {
		t.Fatalf("state dir after disable = %q, want the origin %q", runner.stateDir(), stateDir)
	}
	restored, err := runner.stateRead("traffic-state.json")
	if err != nil || !strings.Contains(string(restored), `"schema_version"`) {
		t.Fatalf("restored traffic state = %q, %v", restored, err)
	}
	// The restored config must keep the previous-layout record for cleanup.
	restoredCfg := runner.Config()
	if restoredCfg.Stealth == nil || restoredCfg.Stealth.Previous == nil || !restoredCfg.Stealth.Previous.Stealth {
		t.Fatalf("restored config must record the previous hidden layout: %+v", restoredCfg.Stealth)
	}
	// Simulate the restarted standard process before the second cleanup.
	osExecutable = func() (string, error) { return filepath.Join(installDir, "oboard-agent"), nil }
	runner.reconcileStealthSwitchCleanup()
	if runner.Config().Stealth != nil && runner.Config().Stealth.Previous != nil {
		t.Fatal("cleanup after disable must drop the previous-layout record")
	}
	if _, err := os.Stat(filepath.Join(installDir, newService)); !os.IsNotExist(err) {
		t.Fatal("cleanup after disable must remove the hidden agent binary")
	}
}

func TestApplyStealthIdempotentReplay(t *testing.T) {
	fakeSwitchEnvironment(t, "systemd")
	installDir, _, _, configPath, stateDir := standardLayoutFixture(t)
	runner := runnerForSwitch(t, installDir, configPath, stateDir)

	// Disable on a standard runner is an idempotent no-op.
	result, err := runner.applyStealthTask(`{"enable":false}`)
	if err != nil {
		t.Fatalf("disable on standard layout: %v", err)
	}
	if result["idempotent_replay"] != true {
		t.Fatalf("result = %#v", result)
	}
}

func TestMigrateStateTreeRoundTrip(t *testing.T) {
	src := t.TempDir()
	dst := t.TempDir()
	key, _ := stealth.GenerateKey()
	files := map[string]string{
		"sing-box.json":              `{"inbounds":[]}`,
		"traffic-state.json":         `{"schema_version":2}`,
		"traffic-state.json.bak":     `{"schema_version":1}`,
		"authorization.json":         `{"revision":3}`,
		"realm.pid":                  `{"pid":123}`,
		hostCoreLockName:             "",
		"last-applied-version.json":  `{"version":9}`,
	}
	for name, content := range files {
		if err := os.WriteFile(filepath.Join(src, name), []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	nested := filepath.Join(src, "tunnels", "7")
	if err := os.MkdirAll(nested, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(nested, "sshd-2200.conf"), []byte("Port 2200\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	if err := migrateStateTreeEncrypt(src, dst, key); err != nil {
		t.Fatal(err)
	}
	// No logical name may survive in the hidden tree.
	entries, err := os.ReadDir(dst)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		for name := range files {
			if entry.Name() == name && name != "realm.pid" && name != hostCoreLockName {
				t.Fatalf("logical name %s survived the encryption migration", name)
			}
		}
		if strings.Contains(entry.Name(), "oboard") {
			t.Fatalf("physical name %s leaks the OBoard marker", entry.Name())
		}
	}
	// The encrypted tree must contain no plaintext JSON.
	filepath.WalkDir(dst, func(path string, entry os.DirEntry, err error) error {
		if err != nil || entry.IsDir() {
			return err
		}
		data, _ := os.ReadFile(path)
		if strings.Contains(string(data), "schema_version") && entry.Name() != "realm.pid" {
			t.Fatalf("plaintext content leaked into %s", path)
		}
		return nil
	})

	// Round-trip back to plaintext.
	back := t.TempDir()
	if err := migrateStateTreeDecrypt(dst, back, key); err != nil {
		t.Fatal(err)
	}
	for name, content := range files {
		data, err := os.ReadFile(filepath.Join(back, name))
		if err != nil {
			t.Fatalf("restored %s: %v", name, err)
		}
		if string(data) != content {
			t.Fatalf("restored %s = %q, want %q", name, data, content)
		}
	}
	restoredNested, err := os.ReadFile(filepath.Join(back, "tunnels", "7", "sshd-2200.conf"))
	if err != nil || string(restoredNested) != "Port 2200\n" {
		t.Fatalf("nested restore = %q, %v", restoredNested, err)
	}
}

func TestStealthConfigRoundTripThroughSaveLoad(t *testing.T) {
	dir := t.TempDir()
	key, _ := stealth.GenerateKey()
	cfg := Config{ControllerURL: "https://controller.example.com", AgentToken: "secret-token", AgentService: "abcdefghij", CoreService: "abcdefghik", Stealth: &stealth.Settings{Identity: stealth.Identity{AgentName: "abcdefghij"}, KeyPath: filepath.Join(dir, "k")}}
	path := filepath.Join(dir, "config.bin")
	if err := SaveConfigWithKey(path, cfg, key); err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(path)
	if !stealth.IsEncrypted(raw) || strings.Contains(string(raw), "secret-token") {
		t.Fatal("saved config must be an encrypted envelope without plaintext")
	}
	loaded, err := LoadConfigWithKey(path, key)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.AgentToken != "secret-token" || loaded.AgentService != "abcdefghij" {
		t.Fatalf("loaded = %+v", loaded)
	}
	// A plaintext file with a key must be rejected, not silently accepted.
	plain := filepath.Join(dir, "plain.json")
	if err := SaveConfig(plain, cfg); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadConfigWithKey(plain, key); err == nil {
		t.Fatal("plaintext config with a key must be rejected")
	}
}

func TestStatePathMapping(t *testing.T) {
	dir := t.TempDir()
	key, _ := stealth.GenerateKey()
	cfg := Config{StateDir: dir, StealthKey: key}
	runner := New(cfg)
	if runner.statePath("sing-box.json") == filepath.Join(dir, "sing-box.json") {
		t.Fatal("stealth runner must derive physical names")
	}
	if runner.statePath("sing-box.json") != filepath.Join(dir, stealth.PhysicalName(key, "sing-box.json")) {
		t.Fatalf("state path = %s", runner.statePath("sing-box.json"))
	}
	// Write through the runner and read back.
	if err := runner.stateWrite("probe.json", []byte(`{"ok":true}`), 0o600); err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(filepath.Join(dir, stealth.PhysicalName(key, "probe.json")))
	if !stealth.IsEncrypted(raw) {
		t.Fatal("stateWrite must encrypt in stealth mode")
	}
	data, err := runner.stateRead("probe.json")
	if err != nil || string(data) != `{"ok":true}` {
		t.Fatalf("stateRead = %q, %v", data, err)
	}
	// A standard runner keeps the logical name and plaintext content.
	standard := New(Config{StateDir: dir})
	if err := standard.stateWrite("probe2.json", []byte(`{"ok":1}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, "probe2.json")); err != nil {
		t.Fatalf("standard write must use the logical name: %v", err)
	}
}

func TestUpdateAgentConfigRejectsStealthIdentityFields(t *testing.T) {
	dir := t.TempDir()
	key, _ := stealth.GenerateKey()
	cfg := normalizeConfig(Config{ConfigPath: filepath.Join(dir, "config.bin"), StateDir: dir, ControllerURL: "https://controller.example.com", Stealth: &stealth.Settings{Identity: stealth.Identity{AgentName: "abcdefghij", CoreName: "abcdefghik"}, KeyPath: filepath.Join(dir, "key")}, AgentService: "abcdefghij", CoreService: "abcdefghik"})
	cfg.StealthKey = key
	runner := New(cfg)
	if _, err := runner.updateAgentConfig(Config{}, map[string]json.RawMessage{"agent_service": json.RawMessage(`"zzzzzzzzzz"`)}) ; err == nil {
		t.Fatal("agent_service patch must be rejected")
	}
	if _, err := runner.updateAgentConfig(Config{}, map[string]json.RawMessage{"stealth": json.RawMessage(`{}`)}); err == nil {
		t.Fatal("stealth patch must be rejected")
	}
	if _, err := runner.updateAgentConfig(Config{StateDir: "/var/lib/other"}, map[string]json.RawMessage{"state_dir": json.RawMessage(`"/var/lib/other"`)}); err == nil {
		t.Fatal("state_dir change must be rejected in stealth mode")
	}
}
