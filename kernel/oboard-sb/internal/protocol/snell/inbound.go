// SPDX-License-Identifier: GPL-3.0-or-later

package snell

import (
	"context"
	"fmt"
	"net"
	"strings"
	"sync"

	"github.com/OboardProject/oboard-agent/kernel/oboard-sb/internal/runtimeuser"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/inbound"
	"github.com/sagernet/sing-box/common/listener"
	"github.com/sagernet/sing-box/common/uot"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	snellprotocol "github.com/sagernet/sing-snell"
	"github.com/sagernet/sing-snell/snellv5"
	"github.com/sagernet/sing-snell/snellv6"
	"github.com/sagernet/sing/common/auth"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

func RegisterInbound(registry *inbound.Registry) {
	inbound.Register[option.SnellInboundOptions](registry, C.TypeSnell, NewInbound)
}

var (
	_ adapter.TCPInjectableInbound = (*Inbound)(nil)
	_ runtimeuser.Inbound          = (*Inbound)(nil)
)

type snellUserUpdater interface {
	UpdateUsers(users []string, userKeys [][]byte) error
}

type Inbound struct {
	inbound.Adapter
	router   adapter.ConnectionRouterEx
	logger   logger.ContextLogger
	listener *listener.Listener
	service  snellprotocol.Service
	updater  snellUserUpdater
	usersMu  sync.RWMutex
	users    []option.SnellUser
}

func NewInbound(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options option.SnellInboundOptions) (adapter.Inbound, error) {
	inbound := &Inbound{
		Adapter: inbound.NewAdapter(C.TypeSnell, tag),
		router:  uot.NewRouter(router, logger),
		logger:  logger,
		users:   options.Users,
	}
	multi := options.Users != nil
	var err error
	switch options.Version {
	case 5:
		var obfsMode snellprotocol.ObfsMode
		obfsMode, err = snellprotocol.ParseObfsMode(options.ObfsOptions.ObfsMode)
		if err != nil {
			return nil, err
		}
		serviceOptions := snellv5.ServiceOptions{
			PSK:      []byte(options.PSK),
			ObfsMode: obfsMode,
			Handler:  inbound,
		}
		if multi {
			var service *snellv5.MultiService[string]
			service, err = snellv5.NewMultiService[string](serviceOptions)
			if err != nil {
				return nil, err
			}
			if err = applySnellUsers(service, options.Users); err != nil {
				return nil, err
			}
			inbound.service = service
			inbound.updater = service
		} else {
			inbound.service, err = snellv5.NewService(serviceOptions)
		}
	case 6:
		var mode snellv6.Mode
		mode, err = snellv6.ParseMode(options.V6Options.Mode)
		if err != nil {
			return nil, err
		}
		serviceOptions := snellv6.ServerOptions{
			PSK:     []byte(options.PSK),
			Mode:    mode,
			Handler: inbound,
		}
		if multi {
			var service *snellv6.MultiService[string]
			service, err = snellv6.NewMultiService[string](serviceOptions)
			if err != nil {
				return nil, err
			}
			if err = applySnellUsers(service, options.Users); err != nil {
				return nil, err
			}
			inbound.service = service
			inbound.updater = service
		} else {
			inbound.service, err = snellv6.NewService(serviceOptions)
		}
	case 0:
		return nil, E.New("snell: missing version")
	default:
		return nil, E.New("snell: unsupported version: ", options.Version)
	}
	if err != nil {
		return nil, err
	}
	inbound.listener = listener.New(listener.Options{
		Context:           ctx,
		Logger:            logger,
		Network:           []string{N.NetworkTCP},
		Listen:            options.ListenOptions,
		ConnectionHandler: inbound,
	})
	return inbound, nil
}

func (h *Inbound) UpdateRuntimeUsers(users []runtimeuser.Spec) error {
	if h.updater == nil {
		return fmt.Errorf("snell inbound is single-PSK and cannot update users")
	}
	converted := make([]option.SnellUser, 0, len(users))
	for _, user := range users {
		name := strings.TrimSpace(user.Name)
		if name == "" || strings.TrimSpace(user.UserKey) == "" {
			return fmt.Errorf("snell runtime user requires name and userkey")
		}
		converted = append(converted, option.SnellUser{Name: name, UserKey: user.UserKey})
	}
	if err := applySnellUsers(h.updater, converted); err != nil {
		return err
	}
	h.usersMu.Lock()
	h.users = converted
	h.usersMu.Unlock()
	return nil
}

func (h *Inbound) RuntimeUsersCapability() string {
	if h.updater == nil {
		return ""
	}
	return runtimeuser.CapabilitySnellMulti
}

func applySnellUsers(updater snellUserUpdater, users []option.SnellUser) error {
	names := make([]string, 0, len(users))
	keys := make([][]byte, 0, len(users))
	seen := map[string]struct{}{}
	for _, user := range users {
		name := strings.TrimSpace(user.Name)
		if name == "" {
			return fmt.Errorf("snell user name is required")
		}
		if _, ok := seen[name]; ok {
			return fmt.Errorf("duplicate snell user %q", name)
		}
		seen[name] = struct{}{}
		names = append(names, name)
		keys = append(keys, []byte(user.UserKey))
	}
	return updater.UpdateUsers(names, keys)
}

func (h *Inbound) Start(stage adapter.StartStage) error {
	if stage != adapter.StartStateStart {
		return nil
	}
	return h.listener.Start()
}

func (h *Inbound) Close() error {
	return h.listener.Close()
}

func (h *Inbound) NewConnection(ctx context.Context, conn net.Conn, metadata adapter.InboundContext, onClose N.CloseHandlerFunc) {
	err := h.service.NewConnection(adapter.WithContext(ctx, &metadata), conn, metadata.Source, onClose)
	if err != nil {
		N.CloseOnHandshakeFailure(conn, onClose, err)
		if E.IsClosedOrCanceled(err) {
			h.logger.DebugContext(ctx, "connection closed: ", err)
		} else {
			h.logger.ErrorContext(ctx, E.Cause(err, "process connection from ", metadata.Source))
		}
	}
}

func (h *Inbound) NewConnectionEx(ctx context.Context, conn net.Conn, source M.Socksaddr, destination M.Socksaddr, onClose N.CloseHandlerFunc) {
	_, metadata := adapter.ExtendContext(ctx)
	if source.IsValid() {
		metadata.Source = source
	}
	if destination.IsValid() {
		metadata.Destination = destination
	}
	h.newConnection(ctx, conn, *metadata, onClose)
}

func (h *Inbound) NewPacketConnectionEx(ctx context.Context, conn N.PacketConn, source M.Socksaddr, destination M.Socksaddr, onClose N.CloseHandlerFunc) {
	_, metadata := adapter.ExtendContext(ctx)
	if source.IsValid() {
		metadata.Source = source
	}
	if destination.IsValid() {
		metadata.Destination = destination
	}
	h.newPacketConnection(ctx, conn, *metadata, onClose)
}

func (h *Inbound) newConnection(ctx context.Context, conn net.Conn, metadata adapter.InboundContext, onClose N.CloseHandlerFunc) {
	metadata.Inbound = h.Tag()
	metadata.InboundType = h.Type()
	if user, ok := auth.UserFromContext[string](ctx); ok && user != "" {
		metadata.User = user
		h.logger.InfoContext(ctx, "[", user, "] inbound connection to ", metadata.Destination)
	} else {
		h.logger.InfoContext(ctx, "inbound connection to ", metadata.Destination)
	}
	h.router.RouteConnectionEx(ctx, conn, metadata, onClose)
}

func (h *Inbound) newPacketConnection(ctx context.Context, conn N.PacketConn, metadata adapter.InboundContext, onClose N.CloseHandlerFunc) {
	metadata.Inbound = h.Tag()
	metadata.InboundType = h.Type()
	metadata.UDPDisableDomainUnmapping = true
	if user, ok := auth.UserFromContext[string](ctx); ok && user != "" {
		metadata.User = user
		h.logger.InfoContext(ctx, "[", user, "] inbound packet connection from ", metadata.Source)
	} else {
		h.logger.InfoContext(ctx, "inbound packet connection from ", metadata.Source)
	}
	h.router.RoutePacketConnectionEx(ctx, conn, metadata, onClose)
}
