package agent

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/OboardProject/oboard-agent/internal/model"
)

func validateSnellCoreFile(path string) error {
	raw, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	var config struct {
		Inbounds []struct {
			Type     string `json:"type"`
			Version  int    `json:"version"`
			AuthMode string `json:"auth_mode"`
			Mode     string `json:"mode"`
			PSK      string `json:"psk"`
			Users    []struct {
				Name    string `json:"name"`
				PSK     string `json:"psk"`
				UserKey string `json:"userkey"`
			} `json:"users"`
		} `json:"inbounds"`
	}
	if err = json.Unmarshal(raw, &config); err != nil {
		return err
	}
	for _, in := range config.Inbounds {
		if in.Type != "snell" || in.AuthMode != "multi_psk" {
			continue
		}
		if in.Mode == "unsafe-raw" {
			return fmt.Errorf("snell_unsafe_mode_not_allowed")
		}
		if in.Version != 5 && in.Version != 6 {
			return fmt.Errorf("snell_multi_psk_unsupported")
		}
		if in.PSK != "" {
			return fmt.Errorf("snell multi_psk forbids global psk")
		}
		if len(in.Users) > 64 {
			return fmt.Errorf("snell_credential_limit_exceeded")
		}
		names, keys := map[string]bool{}, map[string]bool{}
		for _, u := range in.Users {
			minimum := 8
			if in.Version == 6 {
				minimum = 12
			}
			if u.Name == "" || strings.TrimSpace(u.Name) != u.Name || names[u.Name] || len(u.PSK) < minimum || len(u.PSK) > 255 || u.UserKey != "" {
				return fmt.Errorf("snell credential is invalid")
			}
			if keys[u.PSK] {
				return fmt.Errorf("snell_duplicate_psk")
			}
			names[u.Name], keys[u.PSK] = true, true
		}
	}
	return nil
}
func validatePSKInstall(req model.UsersInstallRequest) error {
	keys := map[string]map[string]bool{}
	for _, entry := range req.Entries {
		c := entry.Credential
		if c == (model.UsersCredential{}) {
			if req.Mode != "delta" || entry.AuthorizationKey != "" {
				return fmt.Errorf("invalid users deletion")
			}
			continue
		}
		if c.PSK == "" {
			continue
		}
		if len(c.PSK) < 8 || len(c.PSK) > 255 || c.UserKey != "" || c.Password != "" || c.UUID != "" || c.Flow != "" || strings.TrimSpace(entry.AuthUser) == "" || entry.AuthorizationKey == "" {
			return fmt.Errorf("snell credential is invalid")
		}
		if keys[entry.InboundTag] == nil {
			keys[entry.InboundTag] = map[string]bool{}
		}
		if keys[entry.InboundTag][c.PSK] {
			return fmt.Errorf("snell_duplicate_psk")
		}
		keys[entry.InboundTag][c.PSK] = true
		if len(keys[entry.InboundTag]) > 64 {
			return fmt.Errorf("snell_credential_limit_exceeded")
		}
	}
	return nil
}
