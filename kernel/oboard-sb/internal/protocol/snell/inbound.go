// SPDX-License-Identifier: GPL-3.0-or-later

package snell

import (
	"context"
	"fmt"
	"github.com/sagernet/sing-snell/multipsk"
	"github.com/sagernet/sing/service"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/OboardProject/oboard-agent/kernel/oboard-sb/internal/runtimeuser"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/inbound"
	"github.com/sagernet/sing-box/common/listener"
	"github.com/sagernet/sing-box/common/uot"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
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
	inbound.Register[InboundOptions](registry, C.TypeSnell, NewInbound)
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
	router     adapter.ConnectionRouterEx
	logger     logger.ContextLogger
	listener   *listener.Listener
	service    snellprotocol.Service
	updater    snellUserUpdater
	usersMu    sync.RWMutex
	users      []User
	pskUpdater interface{ UpdatePSKs([]multipsk.User) error }
	version    int
	gate       runtimeuser.AdmissionGate
	ctx        context.Context
	lastError  atomic.Int64
	closed     atomic.Bool
}

func NewInbound(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options InboundOptions) (adapter.Inbound, error) {
	inbound := &Inbound{
		Adapter: inbound.NewAdapter(C.TypeSnell, tag),
		router:  uot.NewRouter(router, logger),
		logger:  logger,
		users:   options.Users,
		version: options.Version,
		ctx:     ctx,
		gate:    service.FromContext[runtimeuser.AdmissionGate](ctx),
	}
	multi := options.Users != nil
	if options.AuthMode == "multi_psk" {
		if options.PSK != "" || options.Mode == "unsafe-raw" {
			return nil, fmt.Errorf("snell_unsafe_mode_not_allowed")
		}
		var err error
		switch options.Version {
		case 5:
			mode, e := snellprotocol.ParseObfsMode(options.ObfsMode)
			if e != nil {
				return nil, e
			}
			svc, e := snellv5.NewPSKService(snellv5.ServiceOptions{ObfsMode: mode, Handler: inbound}, tag+":v4", inbound.admit)
			err = e
			if e == nil {
				inbound.service = svc
				inbound.pskUpdater = svc
			}
		case 6:
			mode, e := snellv6.ParseMode(options.Mode)
			if e != nil {
				return nil, e
			}
			svc, e := snellv6.NewPSKService(snellv6.ServerOptions{Mode: mode, Handler: inbound}, tag+":v6:"+options.Mode, inbound.admit)
			err = e
			if e == nil {
				inbound.service = svc
				inbound.pskUpdater = svc
			}
		default:
			return nil, fmt.Errorf("unsupported snell version")
		}
		if err != nil {
			return nil, err
		}
		specs := make([]runtimeuser.Spec, 0, len(options.Users))
		for _, u := range options.Users {
			if u.UserKey != "" {
				return nil, fmt.Errorf("multi_psk forbids userkey")
			}
			specs = append(specs, runtimeuser.Spec{Name: u.Name, PSK: u.PSK})
		}
		if err = inbound.UpdateRuntimeUsers(specs); err != nil {
			return nil, err
		}
	}

	var err error
	if inbound.pskUpdater == nil {
		switch options.Version {
		case 5:
			var obfsMode snellprotocol.ObfsMode
			obfsMode, err = snellprotocol.ParseObfsMode(options.ObfsMode)
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
			mode, err = snellv6.ParseMode(options.Mode)
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
	if h.pskUpdater != nil {
		converted := make([]multipsk.User, 0, len(users))
		for _, u := range users {
			if u.UserKey != "" || u.Password != "" || u.UUID != "" || strings.TrimSpace(u.Name) == "" || u.PSK == "" {
				return fmt.Errorf("snell runtime user requires name and psk")
			}
			converted = append(converted, multipsk.User{Name: u.Name, PSK: []byte(u.PSK)})
		}
		if err := h.pskUpdater.UpdatePSKs(converted); err != nil {
			return err
		}
		h.usersMu.Lock()
		h.users = make([]User, 0, len(converted))
		for _, u := range converted {
			h.users = append(h.users, User{Name: u.Name, PSK: string(u.PSK)})
		}
		h.usersMu.Unlock()
		return nil
	}

	if h.updater == nil {
		return fmt.Errorf("snell inbound is single-PSK and cannot update users")
	}
	converted := make([]User, 0, len(users))
	for _, user := range users {
		name := strings.TrimSpace(user.Name)
		if name == "" || strings.TrimSpace(user.UserKey) == "" {
			return fmt.Errorf("snell runtime user requires name and userkey")
		}
		converted = append(converted, User{Name: name, UserKey: user.UserKey})
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
	if h.pskUpdater != nil {
		return runtimeuser.CapabilitySnellPSK
	}
	if h.updater == nil {
		return ""
	}
	return runtimeuser.CapabilitySnellMulti
}

func applySnellUsers(updater snellUserUpdater, users []User) error {
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
	h.closed.Store(true)
	if gate, ok := service.FromContext[runtimeuser.AdmissionGate](h.ctx).(interface{ CloseSnellInbound(string) }); ok {
		gate.CloseSnellInbound(h.Tag())
	}
	return h.listener.Close()
}

func (h *Inbound) NewConnection(ctx context.Context, conn net.Conn, metadata adapter.InboundContext, onClose N.CloseHandlerFunc) {
	if h.closed.Load() {
		N.CloseOnHandshakeFailure(conn, onClose, net.ErrClosed)
		return
	}
	if h.pskUpdater != nil {
		gate := service.FromContext[runtimeuser.AdmissionGate](h.ctx)
		if gate == nil {
			N.CloseOnHandshakeFailure(conn, onClose, fmt.Errorf("snell authorization gate unavailable"))
			return
		}
		conn = gate.WrapParent(conn)
		ctx = gate.ParentContext(ctx, conn)
	}
	originalClose := onClose
	closeParent := func(err error) {
		_ = conn.Close()
		if originalClose != nil {
			originalClose(err)
		}
	}
	err := h.service.NewConnection(adapter.WithContext(ctx, &metadata), conn, metadata.Source, closeParent)
	if err != nil {
		N.CloseOnHandshakeFailure(conn, onClose, err)
		if h.pskUpdater != nil {
			if now := time.Now().Unix(); h.lastError.Swap(now) != now {
				h.logger.DebugContext(ctx, "snell authentication rejected")
			}
		} else if E.IsClosedOrCanceled(err) {
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

func (h *Inbound) admit(ctx context.Context, user string, conn net.Conn) (context.Context, error) {
	if h.closed.Load() {
		return nil, net.ErrClosed
	}
	gate := service.FromContext[runtimeuser.AdmissionGate](h.ctx)
	if gate == nil {
		return nil, fmt.Errorf("snell authorization gate unavailable")
	}
	admitted, err := gate.Admit(ctx, h.Tag(), user, conn)
	if err == nil && h.closed.Load() {
		multipsk.Release(admitted)
		_ = conn.Close()
		return nil, net.ErrClosed
	}
	return admitted, err
}

func (h *Inbound) ValidatePSK(psk string) error {
	minimum := 8
	if h.version == 6 {
		minimum = 12
	}
	if len(psk) < minimum || len(psk) > 255 {
		return fmt.Errorf("snell credential length is invalid")
	}
	return nil
}

func (h *Inbound) AuthenticationMetrics() map[string]uint64 {
	source, ok := h.service.(interface{ Metrics() *multipsk.Metrics })
	if !ok {
		return nil
	}
	m := source.Metrics()
	return map[string]uint64{"success": m.Success.Load(), "failure": m.Failure.Load(), "timeout": m.Timeout.Load(), "budget_rejected": m.BudgetRejected.Load(), "candidate_attempts": m.Attempts.Load(), "cache_hits": m.CacheHit.Load(), "queue_nanoseconds": m.QueueNanos.Load(), "active_credentials": uint64(max(0, m.ActiveCredentials.Load())), "pending": uint64(max(0, m.Pending.Load()))}
}
