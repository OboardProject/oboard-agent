// SPDX-License-Identifier: GPL-3.0-or-later
package snell

import (
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/sagernet/sing-box/option"
	"io"
)

type User struct {
	Name    string `json:"name"`
	PSK     string `json:"psk,omitempty"`
	UserKey string `json:"userkey,omitempty"`
}
type InboundOptions struct {
	option.ListenOptions
	Version  int    `json:"version"`
	AuthMode string `json:"auth_mode,omitempty"`
	PSK      string `json:"psk,omitempty"`
	Users    []User `json:"users,omitempty"`
	ObfsMode string `json:"obfs_mode,omitempty"`
	Mode     string `json:"mode,omitempty"`
}

func (o *InboundOptions) UnmarshalJSON(data []byte) error {
	type plain InboundOptions
	var candidate plain
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&candidate); err != nil {
		return err
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return fmt.Errorf("invalid snell options")
	}
	*o = InboundOptions(candidate)
	if o.AuthMode != "" && o.AuthMode != "multi_psk" {
		return fmt.Errorf("unknown snell auth_mode")
	}
	if o.AuthMode == "multi_psk" {
		if o.PSK != "" {
			return fmt.Errorf("multi_psk forbids a global psk")
		}
		if o.Mode == "unsafe-raw" {
			return fmt.Errorf("snell_unsafe_mode_not_allowed")
		}
		for _, u := range o.Users {
			if u.PSK == "" || u.UserKey != "" || u.Name == "" {
				return fmt.Errorf("snell runtime user requires name and psk")
			}
		}
	} else {
		for _, u := range o.Users {
			if u.PSK != "" {
				return fmt.Errorf("psk users require multi_psk")
			}
		}
	}
	return nil
}
