// SPDX-License-Identifier: GPL-3.0-or-later
package snellv5

import (
	"bytes"
	"context"
	snell "github.com/sagernet/sing-snell"
	"github.com/sagernet/sing-snell/multipsk"
	"github.com/sagernet/sing/common/auth"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"io"
	"net"
)

type PSKService struct {
	manager *multipsk.Manager
	handler snell.Handler
	obfs    snell.ObfsConfig
}

func (s *PSKService) Metrics() *multipsk.Metrics { return &s.manager.Metrics }
func (s *PSKService) NewConnection(ctx context.Context, conn net.Conn, source M.Socksaddr, onClose N.CloseHandlerFunc) error {
	handshake, finish, err := s.manager.Begin(ctx, conn, source.Addr.String())
	if err != nil {
		return err
	}
	defer finish(false)
	conn = s.obfs.ServerConn(conn)
	users := s.manager.Candidates(source.Addr.String())
	if len(users) == 0 {
		return multipsk.ErrCredential
	}
	salt := make([]byte, snell.SaltLen)
	if _, err = io.ReadFull(conn, salt); err != nil {
		return err
	}
	header := make([]byte, snell.HeaderCipherLen)
	if _, err = io.ReadFull(conn, header); err != nil {
		return err
	}
	var matched *multipsk.Credential
	var r *reader
	for _, u := range users {
		aead, e := s.manager.Derive(handshake, u, salt)
		if e != nil {
			return e
		}
		plain, e := aead.Open(nil, make([]byte, snell.NonceLen), header, nil)
		if e != nil {
			continue
		}
		if plain[0] != snell.HeaderVersion {
			return snell.ErrBadVersion
		}
		matched = u
		// Probe does not advance the nonce. The reader consumes the saved header
		// with the same AEAD, then continues at nonce one for the payload.
		r = newReader(io.MultiReader(bytes.NewReader(header), conn), aead, make([]byte, snell.NonceLen))
		break
	}
	if matched == nil {
		return multipsk.ErrCredential
	}

	record, err := r.ReadRecord()
	if err != nil {
		return err
	}
	bound := &Service{psk: matched.PSK, handler: s.handler}
	request, err := bound.readRequest(record)
	if err != nil {
		record.Release()
		return err
	}
	if err = multipsk.CheckReplay(matched, salt); err != nil {
		record.Release()
		return err
	}
	bound.admit = func(requestCtx context.Context) (context.Context, error) {
		admitted, e := s.manager.Admit(requestCtx, matched, conn)
		if e != nil {
			return nil, e
		}
		return auth.ContextWithUser(admitted, matched.Name), nil
	}
	admitted, err := bound.admit(handshake)
	if err != nil {
		record.Release()
		return err
	}
	initialAdmission := admitted
	admitted = auth.ContextWithUser(multipsk.WithRelease(ctx, func() { multipsk.Release(initialAdmission) }), matched.Name)
	s.manager.Remember(source.Addr.String(), matched)
	// The initial request is fully validated before admission and any reply.
	// Reuse performs a fresh admission for every subsequent logical request.
	if request.Command == snell.CommandConnectV2 {
		multipsk.Release(admitted)
		finish(true)
		session := &serverReuseSession[struct{}]{Conn: conn, service: bound, reader: r}
		return session.Serve(ctx, source, onClose, record, request)
	}
	defer multipsk.Release(admitted)
	switch request.Command {
	case snell.CommandConnect:
		if record.IsEmpty() {
			record.Release()
		} else {
			r.SetCache(record)
		}
		finish(true)
		bound.handler.NewConnectionEx(admitted, &serverConn{Conn: conn, service: bound, reader: r}, source, request.Destination, onClose)
		return nil
	case snell.CommandUDP:

		record.Release()
		err = bound.newPacketConnection(admitted, &serverPacketConn{Conn: conn, service: bound, reader: r}, source, onClose)
		if err == nil {
			finish(true)
		}
		return err
	case snell.CommandPing:
		record.Release()
		err = bound.writePong(conn)
		if err == nil {
			finish(true)
		}
		_ = conn.Close()
		return err
	default:
		record.Release()
		return multipsk.ErrCredential
	}
}

func NewPSKService(options ServiceOptions, namespace string, admit multipsk.AdmitFunc) (*PSKService, error) {
	if options.ObfsMode != snell.ObfsModeNone && options.ObfsMode != snell.ObfsModeHTTP {
		return nil, multipsk.ErrCredential
	}
	return &PSKService{manager: multipsk.New(namespace, admit), handler: options.Handler, obfs: snell.ObfsConfig{Mode: options.ObfsMode}}, nil
}
func (s *PSKService) UpdatePSKs(users []multipsk.User) error { return s.manager.Update(users, 8) }
