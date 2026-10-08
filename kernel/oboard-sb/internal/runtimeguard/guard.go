// Package runtimeguard applies the opt-in kernel process profile. It never
// changes UID, network capabilities, protocol configuration or authorization.
package runtimeguard

type State struct {
	Mode              string `json:"mode"`
	Supported         bool   `json:"supported"`
	NoNewPrivileges   bool   `json:"no_new_privileges"`
	Dumpable          bool   `json:"dumpable"`
	CoreDumpsDisabled bool   `json:"core_dumps_disabled"`
}
