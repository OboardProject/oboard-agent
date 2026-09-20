package agent

import (
	"path/filepath"

	"github.com/OboardProject/oboard-agent/internal/agentsecurity"
	"github.com/OboardProject/oboard-agent/internal/model"
	"github.com/OboardProject/oboard-agent/internal/stealth"
)

func (r *Runner) localSecurityStore() *agentsecurity.Store {
	return agentsecurity.NewStore(r.localSecurityPath(), r.Config().StealthKey)
}

// localSecurityPath resolves the local-security file for this installation:
// the standard name beside the config in standard mode, a key-derived name in
// stealth mode.
func (r *Runner) localSecurityPath() string {
	configPath := r.configPath()
	if !r.stealthOn() {
		return agentsecurity.PathForConfig(configPath)
	}
	return filepath.Join(filepath.Dir(configPath), stealth.PhysicalName(r.Config().StealthKey, "local-security.json"))
}

func (r *Runner) localSecurityPolicy() agentsecurity.Policy {
	policy, err := r.localSecurityStore().Load()
	if err != nil {
		return agentsecurity.DefaultPolicy()
	}
	return policy
}

func (r *Runner) remoteAccessReport() model.RemoteAccessReport {
	policy := r.localSecurityPolicy()
	return model.RemoteAccessReport{
		Capabilities: []string{
			model.RemoteAccessCapabilityTerminal,
			model.RemoteAccessCapabilityTerminalLoginEnv,
			model.RemoteAccessCapabilityExec,
			model.RemoteAccessCapabilityInteractiveMCP,
			model.RemoteAccessCapabilityLocalGate,
			model.AgentCapabilityHostPower,
		},
		LocalMode:  policy.Mode,
		LocalAllow: policy.Allow,
	}
}

func (r *Runner) localGateAllows(feature string) bool {
	return r.localSecurityPolicy().Allows(feature)
}

func localGateFeatureForExec(origin, mode string) string {
	if origin == model.RemoteExecOriginPlugin {
		return "plugins"
	}
	return "mcp_enabled"
}
