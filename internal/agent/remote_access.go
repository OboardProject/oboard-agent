package agent

import (
	"github.com/OboardProject/oboard-agent/internal/agentsecurity"
	"github.com/OboardProject/oboard-agent/internal/model"
)

func (r *Runner) localSecurityStore() *agentsecurity.Store {
	return agentsecurity.NewStore(agentsecurity.PathForConfig(r.Config().ConfigPath))
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
		},
		LocalMode:  policy.Mode,
		LocalAllow: policy.Allow,
	}
}

func (r *Runner) localGateAllows(feature string) bool {
	return r.localSecurityPolicy().Allows(feature)
}

func localGateFeatureForExec(origin, mode string) string {
	return "mcp_enabled"
}
