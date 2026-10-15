package datachannel

import (
	"testing"
	"time"

	"github.com/ooni/minivpn/internal/model"
	"github.com/ooni/minivpn/internal/session"
	"github.com/ooni/minivpn/pkg/config"
)

func TestKeepaliveTimersFollowPushedValues(t *testing.T) {
	ping, restart := keepaliveTimers(model.TunnelInfo{PingSeconds: 3, PingRestartSeconds: 10})
	if ping != 3*time.Second || restart != 10*time.Second {
		t.Fatalf("got %s/%s", ping, restart)
	}
	ping, restart = keepaliveTimers(model.TunnelInfo{})
	if ping != defaultPingSeconds*time.Second || restart != defaultPingRestartSeconds*time.Second {
		t.Fatalf("defaults: got %s/%s", ping, restart)
	}
	ping, restart = keepaliveTimers(model.TunnelInfo{PingSeconds: 30, PingRestartSeconds: 2})
	if restart != minPingRestartSeconds*time.Second || ping >= restart {
		t.Fatalf("bounds: got %s/%s", ping, restart)
	}
}

func TestDataOpcodeFollowsPushedPeerID(t *testing.T) {
	manager, err := session.NewManager(config.NewConfig())
	if err != nil {
		t.Fatal(err)
	}
	if got := opcodeAndKeyHeader(manager) >> 3; got != byte(model.P_DATA_V1) {
		t.Fatalf("without peer-id the client must send P_DATA_V1, got opcode %d", got)
	}
	manager.UpdateTunnelInfo(&model.TunnelInfo{PeerIDPushed: true, PeerID: 7})
	if got := opcodeAndKeyHeader(manager) >> 3; got != byte(model.P_DATA_V2) {
		t.Fatalf("with peer-id the client must send P_DATA_V2, got opcode %d", got)
	}
}
