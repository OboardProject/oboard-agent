package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"github.com/OboardProject/oboard-agent/internal/agent"
	"github.com/OboardProject/oboard-agent/internal/model"
	"github.com/OboardProject/oboard-agent/internal/version"
)

func main() {
	if filepath.Base(os.Args[0]) == "obag" {
		os.Exit(agent.RunManagementConsole(defaultConfig(), os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
	}
	showVersion := flag.Bool("version", false, "print version and exit")
	configPath := flag.String("config", defaultConfig(), "agent config path")
	controllerURL := flag.String("controller", "", "controller URL")
	enrollOnly := flag.Bool("enroll-only", false, "enroll, save config, and exit")
	stateDir := flag.String("state-dir", "/var/lib/oboard-agent", "agent state directory")
	coreBinary := flag.String("core-binary", "", "proxy core binary; defaults to oboard-sb then sing-box")
	coreService := flag.String("core-service", "", "systemd service to restart; defaults to oboard-sb then sing-box")
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
		if err := agent.SaveConfig(*configPath, runner.Config()); err != nil {
			log.Fatal(err)
		}
		log.Printf("agent enrolled and config saved to %s", *configPath)
		if *enrollOnly {
			return
		}
	}
	if err := runner.Run(ctx); err != nil {
		log.Fatal(err)
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
