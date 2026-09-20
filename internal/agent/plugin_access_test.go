package agent

import (
	"strings"
	"testing"

	"github.com/OboardProject/oboard-agent/internal/agentsecurity"
	"github.com/OboardProject/oboard-agent/internal/model"
)

func TestPluginRemoteOperationLocalGate(t *testing.T) {
	for _, mode := range []string{model.RemoteAccessModeStandard, model.RemoteAccessModeHardened} {
		t.Run(mode, func(t *testing.T) {
			cfg := testAgentConfig(t.TempDir(), 9)
			store := agentsecurity.NewStore(agentsecurity.PathForConfig(cfg.ConfigPath), nil)
			policy := agentsecurity.Policy{Version: 1, Mode: mode}
			runner := New(cfg)
			payload := model.RemoteOperationTaskPayload{
				RequestID: "plugin-op", ServerID: 9,
				Origin: model.RemoteExecOriginPlugin, Kind: model.RemoteOperationNetworkInfo,
			}
			for _, allow := range []bool{false, true, false} {
				policy.Allow.PluginsEnabled = allow
				policy.Allow.MCPEnabled = !allow
				if err := store.Save(policy); err != nil {
					t.Fatal(err)
				}
				status, result := runner.executeRemoteOperationTask(model.AgentTask{PayloadJSON: string(mustJSON(payload))})
				if allow {
					if status != "succeeded" || !strings.Contains(result, "interfaces") {
						t.Fatalf("plugin grant should work without MCP grant: %s %s", status, result)
					}
				} else if status != "failed" || !strings.Contains(result, "agent_local_gate_denied") {
					t.Fatalf("MCP grant must not bypass plugin deny: %s %s", status, result)
				}
			}
			if err := store.SetAllow("plugins", true); err != nil {
				t.Fatal(err)
			}
			for _, origin := range []string{"script", "", "unknown"} {
				payload.Origin = origin
				status, result := runner.executeRemoteOperationTask(model.AgentTask{PayloadJSON: string(mustJSON(payload))})
				if status != "failed" || !strings.Contains(result, "unsupported remote operation origin") {
					t.Fatalf("origin=%q: %s %s", origin, status, result)
				}
			}
			payload.Origin = model.RemoteExecOriginPlugin
			payload.Kind = "shell"
			status, result := runner.executeRemoteOperationTask(model.AgentTask{PayloadJSON: string(mustJSON(payload))})
			if status != "failed" || !strings.Contains(result, "unsupported") {
				t.Fatalf("unknown operation must not fall back to shell: %s %s", status, result)
			}
		})
	}
}

func TestPluginRemoteExecHasNoShellFallback(t *testing.T) {
	cfg := testAgentConfig(t.TempDir(), 9)
	store := agentsecurity.NewStore(agentsecurity.PathForConfig(cfg.ConfigPath), nil)
	if err := store.SetAllow("plugins", true); err != nil {
		t.Fatal(err)
	}
	runner := New(cfg)
	for _, origin := range []string{model.RemoteExecOriginPlugin, "script", "", "unknown"} {
		for _, command := range []model.RemoteExecCommand{
			{Mode: model.RemoteExecModeArgv, Argv: []string{"echo", "not-allowed"}},
			{Mode: model.RemoteExecModeShell, Shell: "echo not-allowed"},
		} {
			payload := model.RemoteExecTaskPayload{
				RequestID: "plugin-exec", ServerID: 9, Origin: origin, Command: command,
			}
			status, result := runner.executeRemoteExecTask(model.AgentTask{PayloadJSON: string(mustJSON(payload))})
			if status != "failed" || !strings.Contains(result, "remote exec requires an MCP or panel origin") {
				t.Fatalf("origin=%q mode=%s: %s %s", origin, command.Mode, status, result)
			}
		}
	}
}
