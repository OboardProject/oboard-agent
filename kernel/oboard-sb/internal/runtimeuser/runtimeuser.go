// SPDX-License-Identifier: GPL-3.0-or-later

package runtimeuser

import (
	"context"
	"net"
)

// Capability strings advertised by the kernel for inbound adapters that can
// replace their user table without a process restart.
const (
	CapabilityVLESS            = "vless"
	CapabilityHysteria2        = "hysteria2"
	CapabilityShadowsocksMulti = "shadowsocks-multi"
	CapabilitySnellMulti       = "snell-multi"
	CapabilitySnellPSK         = "snell-psk"
)

// Spec is one inbound authentication identity. Exactly one of UUID, Password,
// or UserKey is used, depending on the protocol.
type Spec struct {
	Name     string
	UUID     string
	Password string
	UserKey  string
	PSK      string
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

type AdmissionGate interface {
	Admit(context.Context, string, string, net.Conn) (context.Context, error)
	WrapParent(net.Conn) net.Conn
	ParentContext(context.Context, net.Conn) context.Context
}
