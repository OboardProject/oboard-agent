package minibox

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
)

// runtimeOnlyMetadataKeys are the `_oboard` members that carry runtime policy
// instead of operational data-plane state. They are pushed over the local API
// without restarting the kernel, so they must stay outside the operational
// digest that Agent uses to decide whether the running process matches the
// desired configuration.
var runtimeOnlyMetadataKeys = []string{"rate_limits", "connection_audit"}

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
		for _, key := range runtimeOnlyMetadataKeys {
			delete(metadata, key)
		}
		if len(metadata) == 0 {
			delete(object, "_oboard")
		}
	}
	return json.Marshal(object)
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
