// SPDX-License-Identifier: GPL-3.0-or-later

package mieru

import (
	"context"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/enfein/mieru/v3/apis/client"
	"github.com/enfein/mieru/v3/apis/server"
	mierupb "github.com/enfein/mieru/v3/pkg/appctl/appctlpb"
	mierucipher "github.com/enfein/mieru/v3/pkg/cipher"
	mieruprotocol "github.com/enfein/mieru/v3/pkg/protocol"
	"google.golang.org/protobuf/proto"
)

const (
	mieruLogicalServerHelperEnv = "OBOARD_TEST_MIERU_LOGICAL_SERVER"
	mieruLogicalServerStatusEnv = "OBOARD_TEST_MIERU_STATUS_FILE"
	mieruLogicalServerPortEnv   = "OBOARD_TEST_MIERU_PORT"
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

	serverConfig := func(port int) *server.ServerConfig {
		return &server.ServerConfig{Config: &mierupb.ServerConfig{
			Users:            []*mierupb.User{{Name: proto.String("oboard-u"), Password: proto.String("secret")}},
			PortBindings:     []*mierupb.PortBinding{{Port: proto.Int32(int32(port)), Protocol: mierupb.TransportProtocol_TCP.Enum()}},
			AdvancedSettings: &mierupb.ServerAdvancedSettings{UserHintIsMandatory: proto.Bool(true)},
		}}
	}
	clientConfig := func(port int) *client.ClientConfig {
		return &client.ClientConfig{Profile: &mierupb.ClientProfile{
			ProfileName: proto.String("oboard-test"),
			User:        &mierupb.User{Name: proto.String("oboard-u"), Password: proto.String("secret")},
			Servers: []*mierupb.ServerEndpoint{{
				IpAddress:    proto.String("127.0.0.1"),
				PortBindings: []*mierupb.PortBinding{{Port: proto.Int32(int32(port)), Protocol: mierupb.TransportProtocol_TCP.Enum()}},
			}},
		}}
	}

	startServer := func(t *testing.T, port int) server.Server {
		t.Helper()
		mieruServer := server.NewServer()
		if err := mieruServer.Store(serverConfig(port)); err != nil {
			t.Fatalf("store server config: %v", err)
		}
		if err := mieruServer.Start(); err != nil {
			t.Fatalf("start server: %v", err)
		}
		t.Cleanup(func() { _ = mieruServer.Stop() })
		return mieruServer
	}
	startClient := func(t *testing.T, port int) client.Client {
		t.Helper()
		mieruClient := client.NewClient()
		if err := mieruClient.Store(clientConfig(port)); err != nil {
			t.Fatalf("store client config: %v", err)
		}
		if err := mieruClient.Start(); err != nil {
			t.Fatalf("start client: %v", err)
		}
		t.Cleanup(func() { _ = mieruClient.Stop() })
		return mieruClient
	}
	startPair := func(t *testing.T, port int) (client.Client, server.Server) {
		t.Helper()
		mieruServer := startServer(t, port)
		mieruClient := startClient(t, port)
		return mieruClient, mieruServer
	}

	t.Run("shared logical clock", func(t *testing.T) {
		mierucipher.SetTimeFunc(logical)
		mieruprotocol.SetTimeFunc(logical)
		mieruClient, mieruServer := startPair(t, freeTCPPort(t))
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
		// The injected clock is process-global and read at frame time, so a
		// wall-clock client and a logical-time server cannot coexist in one
		// process: restoring the clock would also switch the in-process
		// server back to the wall clock. Run the server in a helper
		// subprocess that keeps the injected +2h clock, and drive the client
		// from here with the raw wall clock, mirroring a remote peer that
		// does not run the corrected logical clock.
		restore()
		statusFile := filepath.Join(t.TempDir(), "status")
		helperPort := freeTCPPort(t)
		helper := exec.Command(os.Args[0],
			"-test.run", "^TestMieruLogicalClockServerHelper$",
			"-test.count", "1",
			"-test.timeout", "60s",
		)
		helper.Env = append(os.Environ(),
			mieruLogicalServerHelperEnv+"=1",
			mieruLogicalServerPortEnv+"="+strconv.Itoa(helperPort),
			mieruLogicalServerStatusEnv+"="+statusFile,
		)
		if err := helper.Start(); err != nil {
			t.Fatalf("start helper server: %v", err)
		}
		defer func() {
			_ = helper.Process.Kill()
			_, _ = helper.Process.Wait()
		}()
		waitStatus := func(deadline time.Duration, want ...string) string {
			t.Helper()
			end := time.Now().Add(deadline)
			for time.Now().Before(end) {
				data, err := os.ReadFile(statusFile)
				if err == nil {
					status := string(data)
					for _, w := range want {
						if strings.Contains(status, w) {
							return w
						}
					}
				}
				time.Sleep(50 * time.Millisecond)
			}
			return ""
		}
		switch s := waitStatus(10*time.Second, "ready", "error"); s {
		case "error":
			t.Fatal("helper server failed to start")
		case "ready":
		default:
			t.Fatal("helper server did not become ready")
		}

		mieruClient := startClient(t, helperPort)
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		session, err := mieruClient.DialContext(ctx, &net.TCPAddr{IP: net.ParseIP("1.2.3.4"), Port: 443})
		if err == nil {
			_ = session.Close()
			t.Fatal("client with a raw wall clock dialed a logical-time server")
		}
		data, _ := os.ReadFile(statusFile)
		switch status := string(data); {
		case strings.Contains(status, "accepted"):
			t.Fatal("server accepted a session stamped with the raw wall clock")
		case strings.Contains(status, "error"):
			t.Fatalf("helper server reported an unexpected error: %s", strings.TrimSpace(status))
		}
	})
}

// TestMieruLogicalClockServerHelper is a re-exec helper: it runs the Mieru
// server with an injected +2h logical clock, writes "ready" to the status
// file once the listener is up, and appends "accepted" if a session opens.
func TestMieruLogicalClockServerHelper(t *testing.T) {
	if os.Getenv(mieruLogicalServerHelperEnv) != "1" {
		return
	}
	writeStatus := func(s string) {
		f, err := os.OpenFile(os.Getenv(mieruLogicalServerStatusEnv), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
		if err != nil {
			return
		}
		_, _ = f.WriteString(s)
		_ = f.Close()
	}
	port, err := strconv.Atoi(os.Getenv(mieruLogicalServerPortEnv))
	if err != nil {
		writeStatus("error invalid port\n")
		os.Exit(1)
	}
	logical := func() time.Time { return time.Now().Add(2 * time.Hour) }
	mierucipher.SetTimeFunc(logical)
	mieruprotocol.SetTimeFunc(logical)
	cfg := &server.ServerConfig{Config: &mierupb.ServerConfig{
		Users:            []*mierupb.User{{Name: proto.String("oboard-u"), Password: proto.String("secret")}},
		PortBindings:     []*mierupb.PortBinding{{Port: proto.Int32(int32(port)), Protocol: mierupb.TransportProtocol_TCP.Enum()}},
		AdvancedSettings: &mierupb.ServerAdvancedSettings{UserHintIsMandatory: proto.Bool(true)},
	}}
	mieruServer := server.NewServer()
	if err := mieruServer.Store(cfg); err != nil {
		writeStatus("error store: " + err.Error() + "\n")
		os.Exit(1)
	}
	if err := mieruServer.Start(); err != nil {
		writeStatus("error start: " + err.Error() + "\n")
		os.Exit(1)
	}
	defer func() { _ = mieruServer.Stop() }()
	writeStatus("ready\n")
	for {
		conn, _, err := mieruServer.Accept()
		if err != nil {
			writeStatus("error accept: " + err.Error() + "\n")
			os.Exit(1)
		}
		writeStatus("accepted\n")
		_, _ = conn.Write([]byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0})
		_ = conn.Close()
	}
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
