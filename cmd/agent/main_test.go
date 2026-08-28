package main

import (
	"testing"

	"github.com/OboardProject/oboard-agent/internal/agent"
)

func TestIsManagementCommand(t *testing.T) {
	commands := []string{"status", "start", "stop", "restart", "logs", "log", "check", "connection", "controller", "help", " STATUS ", "Logs"}
	for _, command := range commands {
		if !isManagementCommand([]string{command}) {
			t.Fatalf("isManagementCommand(%q) = false, want true", command)
		}
	}
	for _, args := range [][]string{
		nil,
		{},
		{"-config", "/etc/oboard-agent/config.json"},
		{"-version"},
		{"--help"},
		{"-h"},
		{"bogus"},
	} {
		if isManagementCommand(args) {
			t.Fatalf("isManagementCommand(%v) = true, want false", args)
		}
	}
}

func TestFillLocalCoreDefaultsUsesInstalledSibling(t *testing.T) {
	cfg := fillLocalCoreDefaults(agent.Config{}, "/opt/oboard/oboard-agent")
	if cfg.CoreBinary != "/opt/oboard/oboard-sb" || cfg.CoreService != "oboard-sb" {
		t.Fatalf("core defaults = %q/%q", cfg.CoreBinary, cfg.CoreService)
	}
	explicit := fillLocalCoreDefaults(agent.Config{CoreBinary: "/usr/bin/sing-box", CoreService: "sing-box"}, "/opt/oboard/oboard-agent")
	if explicit.CoreBinary != "/usr/bin/sing-box" || explicit.CoreService != "sing-box" {
		t.Fatalf("explicit core identity was overwritten: %#v", explicit)
	}
	temporary := fillLocalCoreDefaults(agent.Config{}, "/tmp/process-test/oboard-agent")
	if temporary.CoreBinary != "" || temporary.CoreService != "oboard-sb" {
		t.Fatalf("unsafe executable sibling was persisted: %#v", temporary)
	}
}
