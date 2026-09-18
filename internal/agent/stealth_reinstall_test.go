package agent

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/OboardProject/oboard-agent/internal/stealth"
)

func TestStealthReinstallCleansPreviousLayouts(t *testing.T) {
	for _, manager := range []string{"systemd", "openrc"} {
		t.Run(manager, func(t *testing.T) {
			commands := fakeSwitchEnvironment(t, manager)
			installDir, configParent, stateParent, _, stateDir := standardLayoutFixture(t)
			opts := stealthBootstrapOptions{InstallDir: installDir, Manager: manager, ControllerURL: "https://controller.example.com", ConfigParent: configParent, StateParent: stateParent, UnitDir: filepath.Join(configParent, "units"), LogDir: filepath.Join(configParent, "log"), RunDir: filepath.Join(configParent, "run")}
			original := osExecutable
			osExecutable = func() (string, error) { return filepath.Join(opts.InstallDir, "oboard-agent"), nil }
			t.Cleanup(func() { osExecutable = original })
			makeLayout := func(name string) stealth.Layout {
				opts.InstallDir = filepath.Join(filepath.Dir(installDir), name)
				if err := os.MkdirAll(opts.InstallDir, 0700); err != nil {
					t.Fatal(err)
				}
				for _, file := range []string{"oboard-agent", "oboard-sb", "oboard-realm"} {
					if err := os.WriteFile(filepath.Join(opts.InstallDir, file), []byte("binary"), 0755); err != nil {
						t.Fatal(err)
					}
				}
				layout, err := RunStealthBootstrap(opts)
				if err != nil {
					t.Fatal(err)
				}
				return layout
			}
			randomOld := makeLayout("stage-random-old")
			old := makeLayout("stage-old")
			// Recreate the pre-random-directory layout: random binary names in
			// a fixed directory, with no install_dir_name in its encrypted config.
			legacyKey, err := stealth.LoadKey(old.KeyPath)
			if err != nil {
				t.Fatal(err)
			}
			legacyConfig, err := LoadConfigWithKey(old.ConfigPath, legacyKey)
			if err != nil {
				t.Fatal(err)
			}
			legacyDir := filepath.Join(filepath.Dir(installDir), "fixed-legacy")
			if err := os.Rename(filepath.Dir(old.AgentBinary), legacyDir); err != nil {
				t.Fatal(err)
			}
			legacyConfig.Stealth.Identity.InstallDirName = ""
			old.AgentBinary = filepath.Join(legacyDir, filepath.Base(old.AgentBinary))
			old.CoreBinary = filepath.Join(legacyDir, filepath.Base(old.CoreBinary))
			old.RealmBinary = filepath.Join(legacyDir, filepath.Base(old.RealmBinary))
			legacyConfig.CoreBinary = old.CoreBinary
			if err := SaveConfigWithKey(old.ConfigPath, legacyConfig, legacyKey); err != nil {
				t.Fatal(err)
			}
			legacyUnits := stealthUnits{Layout: old, Identity: legacyConfig.Stealth.Identity, Manager: manager, UnitDir: opts.UnitDir, KeyPath: old.KeyPath, key: legacyKey}
			if err := legacyUnits.write(); err != nil {
				t.Fatal(err)
			}
			replacement := makeLayout("stage-new")
			suffix := ""
			if manager == "systemd" {
				suffix = ".service"
			}
			unit := "ExecStart=" + filepath.Join(installDir, "oboard-agent") + " -config " + filepath.Join(configParent, "oboard-agent", "config.json") + "\n"
			if manager == "openrc" {
				unit = "command=" + filepath.Join(installDir, "oboard-agent") + "\n"
			}
			for _, service := range []string{"oboard-agent", "oboard-sb"} {
				if err := os.WriteFile(filepath.Join(opts.UnitDir, service+suffix), []byte(unit), 0600); err != nil {
					t.Fatal(err)
				}
			}
			unrelated := filepath.Join(installDir, "operator-data")
			if err := os.WriteFile(unrelated, []byte("keep"), 0600); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(opts.UnitDir, "unrelated"+suffix), []byte("unrelated service"), 0600); err != nil {
				t.Fatal(err)
			}
			if err := cleanupPreviousAgentInstalls(opts, replacement.ConfigPath); err != nil {
				t.Fatal(err)
			}
			for _, path := range []string{randomOld.AgentBinary, randomOld.ConfigPath, randomOld.StateDir, old.AgentBinary, old.ConfigPath, old.StateDir, filepath.Join(opts.UnitDir, old.AgentService+suffix), filepath.Join(installDir, "oboard-agent"), stateDir, filepath.Join(opts.UnitDir, "oboard-agent"+suffix)} {
				if _, err := os.Stat(path); !os.IsNotExist(err) {
					t.Fatalf("old path retained: %s (%v)", path, err)
				}
			}
			for _, path := range []string{replacement.AgentBinary, replacement.ConfigPath, replacement.KeyPath, unrelated, filepath.Join(opts.UnitDir, "unrelated"+suffix)} {
				if _, err := os.Stat(path); err != nil {
					t.Fatalf("preserved path missing: %s (%v)", path, err)
				}
			}
			for _, cmd := range *commands {
				if strings.Contains(cmd, " stop "+replacement.AgentService) {
					t.Fatal("replacement stopped")
				}
			}
			if err := cleanupPreviousAgentInstalls(opts, replacement.ConfigPath); err != nil {
				t.Fatalf("cleanup not idempotent: %v", err)
			}
		})
	}
}

func TestStealthReinstallRequiresVerifiedReplacement(t *testing.T) {
	root := t.TempDir()
	err := cleanupPreviousAgentInstalls(stealthBootstrapOptions{Manager: "systemd", UnitDir: root}, "/missing/config")
	if err == nil {
		t.Fatal("cleanup accepted unknown replacement")
	}
}

// A previous installation whose encrypted config was downgraded to plaintext
// by a runtime writer cannot be decrypted, but it is still a managed layout:
// the reinstall cleanup must recognize and remove it instead of leaving the
// broken install behind forever.
func TestStealthReinstallCleansPlaintextBrokenLayout(t *testing.T) {
	for _, manager := range []string{"systemd", "openrc"} {
		t.Run(manager, func(t *testing.T) {
			fakeSwitchEnvironment(t, manager)
			installDir, configParent, stateParent, _, _ := standardLayoutFixture(t)
			opts := stealthBootstrapOptions{InstallDir: installDir, Manager: manager, ControllerURL: "https://controller.example.com", ConfigParent: configParent, StateParent: stateParent, UnitDir: filepath.Join(configParent, "units"), LogDir: filepath.Join(configParent, "log"), RunDir: filepath.Join(configParent, "run")}
			original := osExecutable
			osExecutable = func() (string, error) { return filepath.Join(opts.InstallDir, "oboard-agent"), nil }
			t.Cleanup(func() { osExecutable = original })
			makeLayout := func(name string) stealth.Layout {
				opts.InstallDir = filepath.Join(filepath.Dir(installDir), name)
				if err := os.MkdirAll(opts.InstallDir, 0o700); err != nil {
					t.Fatal(err)
				}
				for _, file := range []string{"oboard-agent", "oboard-sb", "oboard-realm"} {
					if err := os.WriteFile(filepath.Join(opts.InstallDir, file), []byte("binary"), 0o755); err != nil {
						t.Fatal(err)
					}
				}
				layout, err := RunStealthBootstrap(opts)
				if err != nil {
					t.Fatal(err)
				}
				return layout
			}
			broken := makeLayout("stage-broken")
			// Simulate the historical bug: a runtime writer replaced the
			// encrypted envelope with a plaintext config.
			brokenKey, err := stealth.LoadKey(broken.KeyPath)
			if err != nil {
				t.Fatal(err)
			}
			brokenCfg, err := LoadConfigWithKey(broken.ConfigPath, brokenKey)
			if err != nil {
				t.Fatal(err)
			}
			if err := SaveConfig(broken.ConfigPath, brokenCfg); err != nil {
				t.Fatal(err)
			}
			replacement := makeLayout("stage-new")
			if err := cleanupPreviousAgentInstalls(opts, replacement.ConfigPath); err != nil {
				t.Fatal(err)
			}
			for _, path := range []string{broken.AgentBinary, broken.ConfigPath, broken.KeyPath, broken.StateDir} {
				if _, err := os.Stat(path); !os.IsNotExist(err) {
					t.Fatalf("broken layout retained: %s (%v)", path, err)
				}
			}
			for _, path := range []string{replacement.AgentBinary, replacement.ConfigPath, replacement.KeyPath} {
				if _, err := os.Stat(path); err != nil {
					t.Fatalf("replacement missing: %s (%v)", path, err)
				}
			}
		})
	}
}

func TestStealthReinstallStopFailurePreservesFiles(t *testing.T) {
	fakeSwitchEnvironment(t, "systemd")
	root := t.TempDir()
	binary := filepath.Join(root, "old-agent")
	if err := os.WriteFile(binary, []byte("old"), 0700); err != nil {
		t.Fatal(err)
	}
	stealthCommandRunner = func(time.Duration, string, ...string) error { return fmt.Errorf("stop failed") }
	if err := removePreviousInstall(stealthBootstrapOptions{Manager: "systemd"}, stealth.Layout{AgentService: "old-agent", AgentBinary: binary}); err == nil {
		t.Fatal("stop failure ignored")
	}
	if _, err := os.Stat(binary); err != nil {
		t.Fatal("old binary removed after stop failure")
	}
}
