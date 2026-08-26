package security

import (
	"crypto/hmac"
	"encoding/json"
	"fmt"
	"strings"
)

type InteractiveEnvelope struct {
	Type      string `json:"type"`
	ServerID  int64  `json:"server_id"`
	SessionID string `json:"session_id"`
	Nonce     string `json:"nonce"`
	IssuedAt  string `json:"issued_at"`
	ExpiresAt string `json:"expires_at"`
	Kind      string `json:"kind"`
	Cols      int    `json:"cols"`
	Rows      int    `json:"rows"`
}

func SignInteractiveEnvelope(secret string, env InteractiveEnvelope) string {
	return sign(secret, canonicalInteractiveEnvelope(env))
}

func VerifyInteractiveEnvelope(secret string, env InteractiveEnvelope, signature string) bool {
	if secret == "" || signature == "" {
		return false
	}
	expected := SignInteractiveEnvelope(secret, env)
	return hmac.Equal([]byte(expected), []byte(signature))
}

func canonicalInteractiveEnvelope(env InteractiveEnvelope) string {
	b, _ := json.Marshal(struct {
		Type      string `json:"type"`
		ServerID  int64  `json:"server_id"`
		SessionID string `json:"session_id"`
		Nonce     string `json:"nonce"`
		IssuedAt  string `json:"issued_at"`
		ExpiresAt string `json:"expires_at"`
		Kind      string `json:"kind"`
		Cols      int    `json:"cols"`
		Rows      int    `json:"rows"`
	}{env.Type, env.ServerID, env.SessionID, env.Nonce, env.IssuedAt, env.ExpiresAt, env.Kind, env.Cols, env.Rows})
	return string(b)
}

func InteractiveProof(secret, sessionID string, serverID int64, nonce, expiresAt string) string {
	payload := fmt.Sprintf("%s|%d|%s|%s", sessionID, serverID, nonce, expiresAt)
	return sign(secret, payload)
}

func VerifyInteractiveProof(secret, sessionID string, serverID int64, nonce, expiresAt, proof string) bool {
	if secret == "" || proof == "" {
		return false
	}
	expected := InteractiveProof(secret, sessionID, serverID, nonce, expiresAt)
	return hmac.Equal([]byte(expected), []byte(proof))
}

func ControllerInteractiveWebSocketURL(raw string, sessionID string, devBuild bool, allowInsecure bool) (string, error) {
	u, err := ValidateControllerURL(raw, devBuild, allowInsecure)
	if err != nil {
		return "", err
	}
	switch strings.ToLower(u.Scheme) {
	case "http":
		u.Scheme = "ws"
	case "https":
		u.Scheme = "wss"
	}
	u.Path = strings.TrimRight(u.Path, "/") + "/api/v1/agent/interactive/" + sessionID
	u.RawQuery = ""
	u.Fragment = ""
	return u.String(), nil
}
