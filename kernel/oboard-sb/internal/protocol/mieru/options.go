// SPDX-License-Identifier: GPL-3.0-or-later

package mieru

import (
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json/badoption"
)

const Type = "mieru"

type OutboundOptions struct {
	option.DialerOptions
	option.ServerOptions
	ServerPortRanges badoption.Listable[string] `json:"server_ports,omitempty"`
	Transport        string                     `json:"transport,omitempty"`
	Username         string                     `json:"username,omitempty"`
	Password         string                     `json:"password,omitempty"`
	Multiplexing     string                     `json:"multiplexing,omitempty"`
	TrafficPattern   string                     `json:"traffic_pattern,omitempty"`
}

type InboundOptions struct {
	option.ListenOptions
	ListenPortRanges    badoption.Listable[string] `json:"listen_ports,omitempty"`
	Users               []User                     `json:"users,omitempty"`
	Transport           string                     `json:"transport,omitempty"`
	TrafficPattern      string                     `json:"traffic_pattern,omitempty"`
	UserHintIsMandatory bool                       `json:"user_hint_is_mandatory,omitempty"`
}

type User struct {
	Name     string `json:"name,omitempty"`
	Password string `json:"password,omitempty"`
}
