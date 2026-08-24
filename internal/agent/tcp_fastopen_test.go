package agent

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/OboardProject/oboard-agent/internal/model"
)

func TestTCPFastOpenFromFile(t *testing.T) {
	for _, tc := range []struct {
		name      string
		contents  string
		wantState string
		wantValue int
	}{
		{name: "linux default client only", contents: "1\n", wantState: model.TCPFastOpenStateClient, wantValue: 1},
		{name: "client and server", contents: "3\n", wantState: model.TCPFastOpenStateClientServer, wantValue: 3},
		{name: "disabled", contents: "0\n", wantState: model.TCPFastOpenStateDisabled},
		{name: "unparsable", contents: "unknown", wantState: model.TCPFastOpenStateUnavailable},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "tcp_fastopen")
			if err := os.WriteFile(path, []byte(tc.contents), 0o600); err != nil {
				t.Fatal(err)
			}
			state, value := tcpFastOpenFromFile(path)
			if state != tc.wantState || value != tc.wantValue {
				t.Fatalf("state/value = %q/%d, want %q/%d", state, value, tc.wantState, tc.wantValue)
			}
		})
	}
	if state, value := tcpFastOpenFromFile(filepath.Join(t.TempDir(), "absent")); state != model.TCPFastOpenStateUnavailable || value != 0 {
		t.Fatalf("missing sysctl = %q/%d", state, value)
	}
}
