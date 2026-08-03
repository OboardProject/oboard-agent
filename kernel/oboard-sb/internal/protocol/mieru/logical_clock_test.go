// SPDX-License-Identifier: GPL-3.0-or-later

package mieru

import (
	"context"
	"io"
	"net"
	"testing"
	"time"

	"github.com/enfein/mieru/v3/apis/client"
	"github.com/enfein/mieru/v3/apis/server"
	mierupb "github.com/enfein/mieru/v3/pkg/appctl/appctlpb"
	mierucipher "github.com/enfein/mieru/v3/pkg/cipher"
	mieruprotocol "github.com/enfein/mieru/v3/pkg/protocol"
	"google.golang.org/protobuf/proto"
)

// TestMieruWireUsesInjectedLogicalClock proves the Mieru fork derives its
// wire-visible frame timestamps and cipher salts from the injected clock:
// client and server with a shared +2h logical clock complete a session and
// exchange data, while a client left on the raw wall clock cannot.
func TestMieruWireUsesInjectedLogicalClock(t *testing.T) {
	logical := func() time.Time { return time.Now().Add(2 * time.Hour) }
	restore := func() {
		mierucipher.SetTimeFunc(nil)
		mieruprotocol.SetTimeFunc(nil)
	}
	t.Cleanup(restore)

	mieruPort := freeTCPPort(t)
	echoListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = echoListener.Close() })
	go func() {
		for {
			conn, err := echoListener.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				_, _ = io.Copy(conn, conn)
			}()
		}
	}()

	serverConfig := &server.ServerConfig{Config: &mierupb.ServerConfig{
		Users:            []*mierupb.User{{Name: proto.String("oboard-u"), Password: proto.String("secret")}},
		PortBindings:     []*mierupb.PortBinding{{Port: proto.Int32(int32(mieruPort)), Protocol: mierupb.TransportProtocol_TCP.Enum()}},
		AdvancedSettings: &mierupb.ServerAdvancedSettings{UserHintIsMandatory: proto.Bool(true)},
	}}
	clientConfig := &client.ClientConfig{Profile: &mierupb.ClientProfile{
		ProfileName: proto.String("oboard-test"),
		User:        &mierupb.User{Name: proto.String("oboard-u"), Password: proto.String("secret")},
		Servers: []*mierupb.ServerEndpoint{{
			IpAddress:    proto.String("127.0.0.1"),
			PortBindings: []*mierupb.PortBinding{{Port: proto.Int32(int32(mieruPort)), Protocol: mierupb.TransportProtocol_TCP.Enum()}},
		}},
	}}

	startPair := func() (client.Client, server.Server) {
		t.Helper()
		mieruClient := client.NewClient()
		if err := mieruClient.Store(clientConfig); err != nil {
			t.Fatalf("store client config: %v", err)
		}
		mieruServer := server.NewServer()
		if err := mieruServer.Store(serverConfig); err != nil {
			t.Fatalf("store server config: %v", err)
		}
		if err := mieruServer.Start(); err != nil {
			t.Fatalf("start server: %v", err)
		}
		if err := mieruClient.Start(); err != nil {
			_ = mieruServer.Stop()
			t.Fatalf("start client: %v", err)
		}
		t.Cleanup(func() { _ = mieruClient.Stop(); _ = mieruServer.Stop() })
		return mieruClient, mieruServer
	}

	t.Run("shared logical clock", func(t *testing.T) {
		mierucipher.SetTimeFunc(logical)
		mieruprotocol.SetTimeFunc(logical)
		mieruClient, mieruServer := startPair()
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		type acceptResult struct {
			conn net.Conn
			err  error
		}
		accepted := make(chan acceptResult, 1)
		go func() {
			conn, _, err := mieruServer.Accept()
			if err == nil {
				// The client's DialContext waits for the socks5 reply, so it
				// must be written as soon as the session is accepted.
				_, err = conn.Write([]byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0})
			}
			accepted <- acceptResult{conn: conn, err: err}
		}()
		session, err := mieruClient.DialContext(ctx, &net.TCPAddr{IP: net.ParseIP("1.2.3.4"), Port: 443})
		if err != nil {
			t.Fatalf("dial with injected logical clock failed: %v", err)
		}
		defer session.Close()
		var proxyConn net.Conn
		select {
		case result := <-accepted:
			if result.err != nil {
				t.Fatalf("server accept failed: %v", result.err)
			}
			proxyConn = result.conn
		case <-time.After(3 * time.Second):
			t.Fatal("server did not accept the session")
		}
		defer proxyConn.Close()
		if _, err := session.Write([]byte("ping")); err != nil {
			t.Fatal(err)
		}
		buf := make([]byte, 4)
		if _, err := io.ReadFull(proxyConn, buf); err != nil {
			t.Fatal(err)
		}
		if string(buf) != "ping" {
			t.Fatalf("echoed payload = %q", buf)
		}
		if _, err := proxyConn.Write([]byte("pong")); err != nil {
			t.Fatal(err)
		}
		if _, err := io.ReadFull(session, buf); err != nil {
			t.Fatal(err)
		}
		if string(buf) != "pong" {
			t.Fatalf("returned payload = %q", buf)
		}
	})

	t.Run("client left on wall clock", func(t *testing.T) {
		mierucipher.SetTimeFunc(logical)
		mieruprotocol.SetTimeFunc(logical)
		mieruClient, mieruServer := startPair()
		restore()
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		if _, err := mieruClient.DialContext(ctx, &net.TCPAddr{IP: net.ParseIP("1.2.3.4"), Port: 443}); err == nil {
			t.Fatal("client with a raw wall clock dialed a logical-time server")
		}
		acceptResult := make(chan error, 1)
		go func() {
			_, _, err := mieruServer.Accept()
			acceptResult <- err
		}()
		select {
		case err := <-acceptResult:
			if err == nil {
				t.Fatal("server accepted a session stamped with the raw wall clock")
			}
		case <-time.After(3 * time.Second):
		}
	})
}

func freeTCPPort(t *testing.T) int {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	_ = listener.Close()
	return port
}
