package agent

import "testing"

func TestSnellCoreConfigRequiresSharedPSKListeners(t *testing.T) {
	for _, raw := range []string{
		`{"inbounds":[{"type":"snell","version":5,"psk":"old-per-user-psk"}]}`,
		`{"inbounds":[{"type":"snell","version":6,"psk":"old-per-user-psk"}]}`,
		`{"inbounds":[{"type":"snell","version":5,"auth_mode":"multi_psk","psk":"global-fallback"}]}`,
	} {
		if err := validateSnellCoreConfig([]byte(raw)); err == nil {
			t.Fatal("retired single-PSK listener accepted")
		}
	}
	for _, raw := range []string{
		`{"inbounds":[{"type":"snell","version":5,"auth_mode":"multi_psk","users":[]}]}`,
		`{"inbounds":[{"type":"snell","version":6,"auth_mode":"multi_psk","users":[{"name":"alice","psk":"independent-standard-psk"}]}]}`,
	} {
		if err := validateSnellCoreConfig([]byte(raw)); err != nil {
			t.Fatal(err)
		}
	}
}
