package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/OboardProject/oboard-agent/internal/agent"
	"github.com/OboardProject/oboard-agent/internal/logging"
	"github.com/OboardProject/oboard-agent/internal/model"
	"github.com/OboardProject/oboard-agent/internal/version"
)

func main() {
	args := os.Args[1:]
	if len(args) >= 1 && strings.EqualFold(args[0], "maintenance") {
		// Lightweight offline maintenance: no controller connection, no state sync.
		configPath := defaultConfig()
		if len(args) >= 3 && args[1] == "-config" {
			configPath = args[2]
		} else {
			for i, a := range args {
				if a == "-config" && i+1 < len(args) {
					configPath = args[i+1]
					break
				}
				if strings.HasPrefix(a, "-config=") {
					configPath = strings.TrimPrefix(a, "-config=")
					break
				}
			}
		}
		// Also respect flag parsing for --config style
		for _, a := range args {
			if strings.HasPrefix(a, "--config=") {
				configPath = strings.TrimPrefix(a, "--config=")
			}
		}
		if len(args) >= 2 && args[1] == "storage" {
			cfg, err := agent.LoadConfig(configPath)
			if err != nil && !os.IsNotExist(err) {
				fmt.Fprintf(os.Stderr, "load config %s: %v\n", configPath, err)
				os.Exit(1)
			}
			// Normalize to apply profile defaults
			// Use a minimal runner just for storage maintenance.
			runner := agent.New(cfg)
			states := runner.MaintainStorage()
			for _, s := range states {
				fmt.Fprintf(os.Stdout, "%s: %s max=%d backups=%d rotated=%v err=%s\n", s.Service, s.Path, s.MaxBytes, s.Backups, s.Rotated, s.Error)
			}
			os.Exit(0)
		}
		fmt.Fprintf(os.Stderr, "usage: %s maintenance storage [-config path]\n", os.Args[0])
		os.Exit(2)
	}
	if filepath.Base(os.Args[0]) == "obag" || isManagementCommand(args) {
		os.Exit(agent.RunManagementConsole(defaultConfig(), args, os.Stdin, os.Stdout, os.Stderr))
	}
	showVersion := flag.Bool("version", false, "print version and exit")
	configPath := flag.String("config", defaultConfig(), "agent config path")
	controllerURL := flag.String("controller", "", "controller URL")
	enrollOnly := flag.Bool("enroll-only", false, "enroll, save config, and exit")
	stateDir := flag.String("state-dir", "/var/lib/oboard-agent", "agent state directory")
	coreBinary := flag.String("core-binary", "", "proxy core binary; defaults to the oboard-sb binary installed beside the Agent")
	coreService := flag.String("core-service", "", "system service to restart; defaults to oboard-sb")
	resourceProfile := flag.String("resource-profile", "", "resource profile: auto, small, or large; default auto-detects memory and containers")
	commandTimeout := flag.Int("command-timeout", 20, "external command timeout in seconds")
	reloadCommand := flag.String("reload-command", "auto", "core hot reload preset: auto, none, systemd-reload, or openrc-reload")
	restartCommand := flag.String("restart-command", "auto", "core restart preset: auto, none, systemd-restart, or openrc-restart")
	timeSyncCommand := flag.String("time-sync-command", "auto", "time sync preset: auto, none, chrony, or systemd-timesyncd")
	timeCorrectionMode := flag.String("time-correction-mode", "off", "time correction mode: off, auto, or ntp")
	updateSource := flag.String("update-source", "", "agent update source: panel or github")
	allowPanelUpdate := flag.Bool("allow-panel-update", false, "allow future Agent updates from the controller panel")
	updateRepo := flag.String("update-repo", "", "GitHub repository used for release updates, for example OboardProject/oboard-agent")
	verifyRelease := flag.Bool("verify-release", false, "verify a downloaded Agent release manifest and files")
	verifyManifest := flag.String("verify-manifest", "", "release manifest path")
	verifySignature := flag.String("verify-signature", "", "release manifest signature path")
	verifyBaseDir := flag.String("verify-base-dir", "", "directory containing release files")
	verifyOS := flag.String("verify-os", "", "release OS")
	verifyArch := flag.String("verify-arch", "", "release architecture")
	install := flag.Bool("install", false, "print a systemd unit template")
	flag.Parse()
	enrollToken := consumeEnrollToken()
	provided := providedFlags()
	if *showVersion {
		fmt.Println("OBoard Agent", version.String())
		return
	}
	if *install {
		printSystemd(*configPath)
		return
	}
	if *verifyRelease {
		if err := agent.VerifyReleaseFiles(*verifyManifest, *verifySignature, *verifyBaseDir, *verifyOS, *verifyArch, flag.Args()); err != nil {
			log.Fatal(err)
		}
		fmt.Println("release verification ok")
		return
	}
	cfg, _ := agent.LoadConfig(*configPath)
	cfg.ConfigPath = *configPath
	if *controllerURL != "" {
		cfg.ControllerURL = *controllerURL
	}
	if provided["state-dir"] && *stateDir != "" {
		cfg.StateDir = *stateDir
	}
	if *coreBinary != "" {
		cfg.CoreBinary = *coreBinary
	}
	if *coreService != "" {
		cfg.CoreService = *coreService
	}
	if provided["resource-profile"] {
		cfg.ResourceProfile = *resourceProfile
	}
	if provided["command-timeout"] {
		cfg.CommandTimeoutSeconds = *commandTimeout
	}
	if provided["reload-command"] {
		cfg.ReloadCommand = *reloadCommand
	}
	if provided["restart-command"] {
		cfg.RestartCommand = *restartCommand
	}
	if provided["time-sync-command"] {
		cfg.TimeSyncCommand = *timeSyncCommand
	}
	if provided["time-correction-mode"] {
		cfg.TimeCorrectionMode = model.TimeCorrectionMode(*timeCorrectionMode)
	}
	if provided["update-source"] {
		cfg.UpdateSource = *updateSource
	}
	if provided["allow-panel-update"] {
		cfg.AllowPanelUpdate = *allowPanelUpdate
	}
	if provided["update-repo"] {
		cfg.UpdateRepo = *updateRepo
	}
	executablePath, _ := os.Executable()
	cfg = fillLocalCoreDefaults(cfg, executablePath)
	runner := agent.New(cfg)
	if err := runner.Config().Validate(); err != nil {
		log.Fatal(err)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if enrollToken != "" {
		if cfg.ControllerURL == "" {
			log.Fatal("-controller is required when OBOARD_ENROLL_TOKEN is set")
		}
		if err := runner.Enroll(ctx, enrollToken); err != nil {
			log.Fatal(err)
		}
		logging.Infof("agent enrolled and config saved to %s", *configPath)
		if *enrollOnly {
			return
		}
	}
	if err := runner.Run(ctx); err != nil {
		log.Fatal(err)
	}
}

func fillLocalCoreDefaults(cfg agent.Config, executablePath string) agent.Config {
	if strings.TrimSpace(cfg.CoreBinary) == "" && strings.TrimSpace(executablePath) != "" {
		cfg.CoreBinary = agent.InstalledCoreBinary(executablePath)
	}
	if strings.TrimSpace(cfg.CoreService) == "" {
		cfg.CoreService = "oboard-sb"
	}
	return cfg
}

// isManagementCommand reports whether the first argument selects the local
// management console so the binary works even without the obag symlink.
func isManagementCommand(args []string) bool {
	if len(args) == 0 {
		return false
	}
	switch strings.ToLower(strings.TrimSpace(args[0])) {
	case "status", "start", "stop", "restart", "logs", "log", "check", "connection", "controller", "help", "remote-access":
		return true
	default:
		return false
	}
}

func defaultConfig() string {
	home, _ := os.UserHomeDir()
	if home == "" {
		return "/etc/oboard-agent/config.json"
	}
	return filepath.Join(home, ".oboard-agent", "config.json")
}

func providedFlags() map[string]bool {
	provided := map[string]bool{}
	flag.Visit(func(f *flag.Flag) { provided[f.Name] = true })
	return provided
}

func consumeEnrollToken() string {
	value := os.Getenv("OBOARD_ENROLL_TOKEN")
	_ = os.Unsetenv("OBOARD_ENROLL_TOKEN")
	return value
}

func printSystemd(configPath string) {
	fmt.Printf(`[Unit]
Description=OBoard Agent
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
# Intentionally privileged host-management service; see README privilege boundary.
User=root
ExecStart=/usr/local/bin/oboard-agent -config %s
StandardOutput=append:/var/log/oboard-agent.log
StandardError=append:/var/log/oboard-agent.log
Restart=always
RestartSec=5
UMask=0077
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=false
ProtectHome=true
ReadWritePaths=/usr/local/bin /etc/oboard-agent /var/lib/oboard-agent /var/log /run
LockPersonality=true
MemoryDenyWriteExecute=true
ProtectClock=true
ProtectHostname=true
ProtectKernelLogs=true
RestrictRealtime=true
RestrictSUIDSGID=true
SystemCallArchitectures=native
ProtectKernelTunables=false
ProtectControlGroups=false
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
`, configPath)
}
