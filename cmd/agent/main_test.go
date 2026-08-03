package main

import "testing"

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
