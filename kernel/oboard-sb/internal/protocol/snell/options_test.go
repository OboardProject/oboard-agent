package snell

import (
	"encoding/json"
	"testing"
)

func TestSnellInboundRejectsRetiredSinglePSKMode(t *testing.T) {
	for _, raw := range []string{
		`{"version":5,"psk":"old-per-user-psk"}`,
		`{"version":6,"psk":"old-per-user-psk"}`,
		`{"version":5,"auth_mode":"multi_psk","users":[{"name":"alice","userkey":"old-key"}]}`,
	} {
		var options InboundOptions
		if err := json.Unmarshal([]byte(raw), &options); err == nil {
			t.Fatal("retired Snell inbound mode accepted")
		}
	}
	var options InboundOptions
	if err := json.Unmarshal([]byte(`{"version":6,"auth_mode":"multi_psk","users":[]}`), &options); err != nil {
		t.Fatal(err)
	}
}
