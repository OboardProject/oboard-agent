// SPDX-License-Identifier: GPL-3.0-or-later

package userselector

import (
	"context"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"

	"github.com/OboardProject/oboard-agent/kernel/oboard-sb/internal/runtimeuser"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/log"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/service"
)

func RegisterOutbound(registry *outbound.Registry) {
	outbound.Register[OutboundOptions](registry, Type, NewOutbound)
}

type Outbound struct {
	outbound.Adapter
	logger  log.ContextLogger
	manager adapter.OutboundManager
	mu      sync.RWMutex
	users   map[string]string
}

var (
	_ adapter.Outbound      = (*Outbound)(nil)
	_ runtimeuser.Selector  = (*Outbound)(nil)
)

func NewOutbound(ctx context.Context, _ adapter.Router, logger log.ContextLogger, tag string, options OutboundOptions) (adapter.Outbound, error) {
	if err := options.validate(); err != nil {
		return nil, err
	}
	manager := service.FromContext[adapter.OutboundManager](ctx)
	if manager == nil {
		return nil, fmt.Errorf("user-selector requires an outbound manager")
	}
	deps := uniqueTags(options.Users)
	for _, child := range deps {
		if _, ok := manager.Outbound(child); !ok {
			return nil, fmt.Errorf("user-selector outbound %q not found", child)
		}
	}
	return &Outbound{
		Adapter: outbound.NewAdapter(Type, tag, []string{N.NetworkTCP, N.NetworkUDP}, deps),
		logger:  logger,
		manager: manager,
		users:   cloneUsers(options.Users),
	}, nil
}

func (o *Outbound) UpdateUsers(users map[string]string) error {
	cleaned := cloneUsers(users)
	for user, tag := range cleaned {
		if _, ok := o.manager.Outbound(tag); !ok {
			return fmt.Errorf("user-selector outbound %q not found", tag)
		}
		_ = user
	}
	o.mu.Lock()
	o.users = cleaned
	o.mu.Unlock()
	return nil
}

func (o *Outbound) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	child, err := o.lookup(ctx)
	if err != nil {
		return nil, err
	}
	return child.DialContext(ctx, network, destination)
}

func (o *Outbound) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	child, err := o.lookup(ctx)
	if err != nil {
		return nil, err
	}
	return child.ListenPacket(ctx, destination)
}

func (o *Outbound) lookup(ctx context.Context) (adapter.Outbound, error) {
	metadata := adapter.ContextFrom(ctx)
	user := ""
	if metadata != nil {
		user = strings.TrimSpace(metadata.User)
	}
	if user == "" {
		return nil, os.ErrPermission
	}
	o.mu.RLock()
	tag := o.users[user]
	o.mu.RUnlock()
	if tag == "" {
		return nil, os.ErrPermission
	}
	child, ok := o.manager.Outbound(tag)
	if !ok {
		return nil, E.New("user-selector outbound ", tag, " is gone")
	}
	return child, nil
}

func uniqueTags(users map[string]string) []string {
	seen := map[string]struct{}{}
	var out []string
	for _, tag := range users {
		tag = strings.TrimSpace(tag)
		if tag == "" {
			continue
		}
		if _, ok := seen[tag]; ok {
			continue
		}
		seen[tag] = struct{}{}
		out = append(out, tag)
	}
	return out
}

func cloneUsers(users map[string]string) map[string]string {
	out := make(map[string]string, len(users))
	for user, tag := range users {
		user = strings.TrimSpace(user)
		tag = strings.TrimSpace(tag)
		if user == "" || tag == "" {
			continue
		}
		out[user] = tag
	}
	return out
}
