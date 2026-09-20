package agentsecurity

import (
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"

	"github.com/OboardProject/oboard-agent/internal/model"
)

func TestPluginLocalPolicyRequiresExplicitGrant(t *testing.T) {
	for _, mode := range []string{model.RemoteAccessModeStandard, model.RemoteAccessModeHardened} {
		t.Run(mode, func(t *testing.T) {
			store := NewStore(filepath.Join(t.TempDir(), "local-security.json"), nil)
			if err := store.SetMode(mode); err != nil {
				t.Fatal(err)
			}
			for _, allow := range []bool{false, true, false} {
				if err := store.SetAllow("plugins", allow); err != nil {
					t.Fatal(err)
				}
				policy, err := store.Load()
				if err != nil {
					t.Fatal(err)
				}
				for _, feature := range []string{"plugins", "plugins_enabled"} {
					if policy.Allows(feature) != allow {
						t.Fatalf("feature=%s grant=%v policy=%+v", feature, allow, policy)
					}
				}
				if policy.Allows("host-power") {
					t.Fatal("plugin grant must not grant host power")
				}
				raw, err := json.Marshal(policy)
				if err != nil || !strings.Contains(string(raw), `"plugins_enabled":`) || strings.Contains(string(raw), "scripts_enabled") {
					t.Fatalf("policy JSON: %s, %v", raw, err)
				}
				for _, old := range []string{"scripts", "scripts_enabled"} {
					if policy.Allows(old) || store.SetAllow(old, true) == nil {
						t.Fatalf("retired gate %s must not be accepted", old)
					}
				}
			}
		})
	}
}

func TestPluginLocalPolicyDoesNotImportRetiredGrant(t *testing.T) {
	var policy Policy
	if err := json.Unmarshal([]byte(`{"version":1,"mode":"standard","allow":{"scripts_enabled":true}}`), &policy); err != nil {
		t.Fatal(err)
	}
	if policy.Allows("plugins") {
		t.Fatal("retired script grant must not grant plugin access")
	}
}
