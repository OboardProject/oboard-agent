package agent

import (
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

func dialKeepaliveTestSocket(t *testing.T, handler func(*websocket.Conn)) *websocket.Conn {
	t.Helper()
	upgrader := websocket.Upgrader{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer conn.Close()
		handler(conn)
	}))
	t.Cleanup(server.Close)

	conn, _, err := websocket.DefaultDialer.Dial("ws"+strings.TrimPrefix(server.URL, "http"), nil)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return conn
}

// A Controller ping both answers with a pong and refreshes the read deadline,
// so a link that carries no application traffic still survives.
func TestConfigureControllerSocketKeepsPingedLinkAlive(t *testing.T) {
	pongs := make(chan struct{}, 8)
	conn := dialKeepaliveTestSocket(t, func(server *websocket.Conn) {
		server.SetPongHandler(func(string) error {
			select {
			case pongs <- struct{}{}:
			default:
			}
			return nil
		})
		go func() {
			for {
				if _, _, err := server.ReadMessage(); err != nil {
					return
				}
			}
		}()
		ticker := time.NewTicker(40 * time.Millisecond)
		defer ticker.Stop()
		deadline := time.After(2 * time.Second)
		for {
			select {
			case <-deadline:
				return
			case <-ticker.C:
				if err := server.WriteControl(websocket.PingMessage, nil, time.Now().Add(time.Second)); err != nil {
					return
				}
			}
		}
	})

	configureControllerSocket(conn, 150*time.Millisecond)
	readErrors := make(chan error, 1)
	go func() {
		for {
			if _, _, err := conn.ReadMessage(); err != nil {
				readErrors <- err
				return
			}
		}
	}()

	select {
	case <-pongs:
	case <-time.After(2 * time.Second):
		t.Fatal("controller never received a pong")
	}
	select {
	case err := <-readErrors:
		t.Fatalf("pinged link dropped: %v", err)
	case <-time.After(600 * time.Millisecond):
	}
}

// A Controller that went away without closing TCP sends nothing. The Agent must
// notice and fall through to its reconnect loop instead of holding a socket that
// will never deliver another task.
func TestConfigureControllerSocketDropsSilentLink(t *testing.T) {
	conn := dialKeepaliveTestSocket(t, func(server *websocket.Conn) {
		<-time.After(3 * time.Second)
	})

	configureControllerSocket(conn, 150*time.Millisecond)
	start := time.Now()
	_, _, err := conn.ReadMessage()
	if err == nil {
		t.Fatal("silent link must not read successfully")
	}
	netErr, ok := err.(net.Error)
	if !ok || !netErr.Timeout() {
		t.Fatalf("expected a read timeout, got %v", err)
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Fatalf("silent link took %s to fail", elapsed)
	}
}
