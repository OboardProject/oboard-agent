package agent

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"

	"github.com/OboardProject/oboard-agent/internal/model"
)

func desiredStateID(value any) (string, error) {
	b, err := json.Marshal(value)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:]), nil
}

func portForwardDesiredStateID(plan model.PortForwardPlan) (string, error) {
	plan.Version = 0
	return desiredStateID(plan)
}

func tunnelDesiredStateID(plan model.TunnelPlan) (string, error) {
	plan.Version = 0
	return desiredStateID(plan)
}

func (r *Runner) resetRuntimeDesiredStateCaches() {
	r.forwardLifecycleMu.Lock()
	r.forwardDesiredState = ""
	r.forwardLifecycleMu.Unlock()
	r.tunnelLifecycleMu.Lock()
	r.tunnelDesiredState = ""
	r.tunnelLifecycleMu.Unlock()
	r.sshInboundLifecycleMu.Lock()
	r.sshInboundDesiredState = ""
	r.sshInboundLifecycleMu.Unlock()
}

func sshInboundDesiredStateID(plan model.SSHInboundPlan) (string, error) {
	plan.Version = 0
	for index := range plan.Inbounds {
		// Quota and speed policies are mutable runtime state. They can be updated
		// in place and must not force listeners or established SSH sessions to be
		// rebuilt.
		plan.Inbounds[index].Policies = nil
	}
	return desiredStateID(plan)
}
