// SPDX-License-Identifier: GPL-3.0-or-later

package runtimeuser

// Capability strings advertised by the kernel for inbound adapters that can
// replace their user table without a process restart.
const (
	CapabilityVLESS           = "vless"
	CapabilityHysteria2       = "hysteria2"
	CapabilityShadowsocksMulti = "shadowsocks-multi"
	CapabilitySnellMulti      = "snell-multi"
)

// Spec is one inbound authentication identity. Exactly one of UUID, Password,
// or UserKey is used, depending on the protocol.
type Spec struct {
	Name     string
	UUID     string
	Password string
	UserKey  string
	Flow     string
}

// Inbound is implemented by OBoard inbound adapters that replace the
// upstream type and expose UpdateUsers.
type Inbound interface {
	UpdateRuntimeUsers([]Spec) error
	RuntimeUsersCapability() string
}

// Selector is implemented by the user-selector outbound.
type Selector interface {
	UpdateUsers(map[string]string) error
}
