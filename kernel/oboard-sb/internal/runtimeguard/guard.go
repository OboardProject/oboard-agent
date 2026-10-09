// Package runtimeguard applies the opt-in kernel process profile. It never
// changes UID, network capabilities, protocol configuration or authorization.
package runtimeguard

import (
	"os"
	"strings"
	"sync/atomic"
)

type State struct {
	UID                   int    `json:"uid"`
	GID                   int    `json:"gid"`
	EffectiveCapabilities string `json:"effective_capabilities,omitempty"`
	IdentitySupported     bool   `json:"identity_supported"`
	SensitiveArguments    bool   `json:"sensitive_arguments"`
	SensitiveEnvironment  bool   `json:"sensitive_environment"`
	LocalAPI              string `json:"local_api"`

	Mode              string `json:"mode"`
	Supported         bool   `json:"supported"`
	NoNewPrivileges   bool   `json:"no_new_privileges"`
	Dumpable          bool   `json:"dumpable"`
	CoreDumpsDisabled bool   `json:"core_dumps_disabled"`
}

var localAPI atomic.Value

func SetLocalAPI(listen string) {
	kind := "disabled"
	if strings.HasPrefix(listen, "unix:") {
		kind = "unix"
	} else if listen != "" {
		kind = "tcp"
	}
	localAPI.Store(kind)
}
func processEvidence(state *State) {
	if kind, ok := localAPI.Load().(string); ok {
		state.LocalAPI = kind
	} else {
		state.LocalAPI = "unknown"
	}
	for _, arg := range os.Args[1:] {
		name, _, _ := strings.Cut(strings.TrimLeft(strings.ToLower(arg), "-"), "=")
		switch strings.ReplaceAll(name, "-", "_") {
		case "token", "agent_token", "password", "passwd", "psk", "secret", "private_key":
			state.SensitiveArguments = true
		}
	}
	for _, value := range os.Environ() {
		name, _, _ := strings.Cut(value, "=")
		name = strings.ToUpper(name)
		if strings.Contains(name, "TOKEN") || strings.Contains(name, "PASSWORD") || strings.Contains(name, "SECRET") || strings.Contains(name, "PRIVATE_KEY") {
			state.SensitiveEnvironment = true
		}
	}
}
