package tlssession

import (
	"fmt"
	"strings"
	"testing"

	"github.com/ooni/minivpn/internal/model"
)

type pushLogger struct {
	model.NoopLogger
	messages []string
}

func (l *pushLogger) Info(msg string)                  { l.messages = append(l.messages, msg) }
func (l *pushLogger) Infof(format string, args ...any) { l.Info(fmt.Sprintf(format, args...)) }

func TestPushOptionsDoNotLeakToLogs(t *testing.T) {
	logger := &pushLogger{}
	info, err := parseServerPushReply(logger, []byte("PUSH_REPLY,ifconfig 192.0.2.10 255.255.255.0,route-gateway 192.0.2.1,auth-token private-token"))
	if err != nil {
		t.Fatal(err)
	}
	if info.IP != "192.0.2.10" || info.GW != "192.0.2.1" {
		t.Fatal("push options were not applied")
	}
	logs := strings.Join(logger.messages, " ")
	for _, value := range []string{info.IP, info.GW, "private-token", "auth-token"} {
		if strings.Contains(logs, value) {
			t.Fatal("push option leaked to logs")
		}
	}
}
