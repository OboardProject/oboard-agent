package minibox

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"

	"github.com/OboardProject/oboard-agent/kernel/oboard-sb/internal/authorization"
)

// runtimeOnlyMetadataKeys are the `_oboard` members that carry runtime policy
// instead of operational data-plane state. They are pushed over the local API
// without restarting the kernel, so they must stay outside the operational
// digest that Agent uses to decide whether the running process matches the
// desired configuration.
var runtimeOnlyMetadataKeys = []string{"connection_audit", "authorization"}

// NormalizeOperationalConfig returns the canonical JSON form of a kernel
// configuration with runtime-only metadata removed. Agent implements the same
// normalization, so both sides derive an identical digest from identical bytes
// regardless of key order or formatting.
func NormalizeOperationalConfig(raw []byte) ([]byte, error) {
	if len(bytes.TrimSpace(raw)) == 0 {
		return nil, fmt.Errorf("core configuration is empty")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var root any
	if err := decoder.Decode(&root); err != nil {
		return nil, err
	}
	if _, err := decoder.Token(); err != io.EOF {
		return nil, fmt.Errorf("core configuration has trailing content")
	}
	object, ok := root.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("core configuration root must be a JSON object")
	}
	if metadata, ok := object["_oboard"].(map[string]any); ok {
		stripRuntimeUserFields(object, metadata)
		authorization.RetainInstalledKeys(metadata)
		for _, key := range runtimeOnlyMetadataKeys {
			delete(metadata, key)
		}
		if len(metadata) == 0 {
			delete(object, "_oboard")
		}
	}
	return json.Marshal(object)
}

func stripRuntimeUserFields(root map[string]any, metadata map[string]any) {
	declared, _ := metadata["runtime_users"].(map[string]any)
	if declared == nil {
		return
	}
	rawTags, _ := declared["inbounds"].([]any)
	if len(rawTags) == 0 {
		return
	}
	tags := map[string]struct{}{}
	for _, raw := range rawTags {
		tag, _ := raw.(string)
		if tag != "" {
			tags[tag] = struct{}{}
		}
	}
	if len(tags) == 0 {
		return
	}
	names := map[string]struct{}{}
	inbounds, _ := root["inbounds"].([]any)
	for _, raw := range inbounds {
		inbound, _ := raw.(map[string]any)
		tag, _ := inbound["tag"].(string)
		if _, ok := tags[tag]; !ok {
			continue
		}
		if users, ok := inbound["users"].([]any); ok {
			for _, userRaw := range users {
				user, _ := userRaw.(map[string]any)
				if name, _ := user["name"].(string); name != "" {
					names[name] = struct{}{}
				}
			}
		}
		delete(inbound, "users")
	}
	if limits, ok := metadata["rate_limits"].(map[string]any); ok {
		if users, ok := limits["users"].(map[string]any); ok {
			if len(names) == 0 {
				delete(limits, "users")
			} else {
				for name := range names {
					delete(users, name)
				}
				if len(users) == 0 {
					delete(limits, "users")
				}
			}
		}
	}
	outbounds, _ := root["outbounds"].([]any)
	for _, raw := range outbounds {
		outbound, _ := raw.(map[string]any)
		tag, _ := outbound["tag"].(string)
		kind, _ := outbound["type"].(string)
		if kind != "user-selector" {
			continue
		}
		for inboundTag := range tags {
			if tag == "userselector-"+inboundTag {
				delete(outbound, "users")
			}
		}
	}
}

// OperationalConfigDigest is the stable identity of the operational part of a
// kernel configuration.
func OperationalConfigDigest(raw []byte) (string, error) {
	normalized, err := NormalizeOperationalConfig(raw)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(normalized)
	return hex.EncodeToString(sum[:]), nil
}

// OperationalConfigDigestFile reads a configuration file and returns its
// operational digest.
func OperationalConfigDigestFile(path string) (string, error) {
	// #nosec G304 -- path is the explicit local CLI flag supplied by the Agent service.
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	return OperationalConfigDigest(data)
}
