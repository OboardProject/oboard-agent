package session

import (
	"fmt"
	"strings"
	"testing"

	"github.com/ooni/minivpn/internal/model"
)

type tunnelLogger struct {
	model.NoopLogger
	messages []string
}

func (l *tunnelLogger) Info(msg string)                  { l.messages = append(l.messages, msg) }
func (l *tunnelLogger) Infof(format string, args ...any) { l.Info(fmt.Sprintf(format, args...)) }

func TestUpdateTunnelInfoDoesNotLogAddresses(t *testing.T) {
	logger := &tunnelLogger{}
	manager := &Manager{logger: logger}
	info := &model.TunnelInfo{IP: "192.0.2.10", GW: "192.0.2.1", PeerID: 71}
	manager.UpdateTunnelInfo(info)
	if got := manager.TunnelInfo(); got.IP != info.IP || got.GW != info.GW || got.PeerID != info.PeerID {
		t.Fatal("tunnel configuration lost")
	}
	logs := strings.Join(logger.messages, " ")
	for _, value := range []string{info.IP, info.GW, "71"} {
		if strings.Contains(logs, value) {
			t.Fatal("tunnel identity leaked to logs")
		}
	}
}
