// SPDX-License-Identifier: GPL-3.0-or-later

package shadowsocks

import (
	"context"
	"fmt"
	"strings"

	"github.com/OboardProject/oboard-agent/kernel/oboard-sb/internal/runtimeuser"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/inbound"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	upstream "github.com/sagernet/sing-box/protocol/shadowsocks"
)

func RegisterInbound(registry *inbound.Registry) {
	inbound.Register[option.ShadowsocksInboundOptions](registry, C.TypeShadowsocks, NewInbound)
}

type runtimeInbound struct {
	adapter.Inbound
	multi *upstream.MultiInbound
}

var _ runtimeuser.Inbound = (*runtimeInbound)(nil)

func NewInbound(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options option.ShadowsocksInboundOptions) (adapter.Inbound, error) {
	wantMulti := options.Managed || options.Users != nil
	if !options.Managed && options.Users != nil && len(options.Users) == 0 {
		options.Managed = true
		options.Users = nil
		wantMulti = true
	}
	inner, err := upstream.NewInbound(ctx, router, logger, tag, options)
	if err != nil {
		return nil, err
	}
	multi, ok := inner.(*upstream.MultiInbound)
	if !ok {
		if wantMulti {
			return nil, fmt.Errorf("shadowsocks inbound %q is not multi-user", tag)
		}
		return inner, nil
	}
	return &runtimeInbound{Inbound: inner, multi: multi}, nil
}

func (h *runtimeInbound) UpdateRuntimeUsers(users []runtimeuser.Spec) error {
	names := make([]string, 0, len(users))
	passwords := make([]string, 0, len(users))
	seen := map[string]struct{}{}
	for _, user := range users {
		name := strings.TrimSpace(user.Name)
		if name == "" || strings.TrimSpace(user.Password) == "" {
			return fmt.Errorf("shadowsocks runtime user requires name and password")
		}
		if _, ok := seen[name]; ok {
			return fmt.Errorf("duplicate shadowsocks user %q", name)
		}
		seen[name] = struct{}{}
		names = append(names, name)
		passwords = append(passwords, user.Password)
	}
	return h.multi.UpdateUsers(names, passwords)
}

func (h *runtimeInbound) RuntimeUsersCapability() string {
	return runtimeuser.CapabilityShadowsocksMulti
}
