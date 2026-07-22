package security

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net"
	"net/url"
	"os"
	"strings"
)

func ValidateControllerURL(raw string, devBuild bool, allowInsecure bool) (*url.URL, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Scheme == "" || u.Host == "" {
		return nil, errors.New("controller_url must be a valid URL")
	}
	scheme := strings.ToLower(u.Scheme)
	switch scheme {
	case "https", "wss":
		return u, nil
	case "http", "ws":
		if devBuild || allowInsecure || EnvBool("OBOARD_ALLOW_INSECURE_AGENT_HTTP", false) || isLocalControllerHost(u.Hostname()) {
			return u, nil
		}
		return nil, errors.New("controller_url must use https/wss in production; http/ws is only allowed for localhost, dev builds, or explicit insecure override")
	default:
		return nil, errors.New("controller_url must use http(s) or ws(s)")
	}
}

func ControllerWebSocketURL(raw string, devBuild bool, allowInsecure bool) (string, error) {
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
	u.Path = strings.TrimRight(u.Path, "/") + "/api/v1/agent/connect"
	u.RawQuery = ""
	u.Fragment = ""
	return u.String(), nil
}

func EnvBool(key string, fallback bool) bool {
	switch os.Getenv(key) {
	case "1", "true", "TRUE", "yes", "YES", "on", "ON":
		return true
	case "0", "false", "FALSE", "no", "NO", "off", "OFF":
		return false
	default:
		return fallback
	}
}

func isLocalControllerHost(host string) bool {
	host = strings.Trim(strings.ToLower(strings.TrimSpace(host)), "[]")
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func HashSecret(secret string) string {
	sum := sha256.Sum256([]byte(secret))
	return hex.EncodeToString(sum[:])
}

type TaskEnvelope struct {
	ID            int64  `json:"id"`
	ServerID      int64  `json:"server_id"`
	Type          string `json:"type"`
	ConfigVersion int64  `json:"config_version"`
	Nonce         string `json:"nonce"`
	PayloadJSON   string `json:"payload_json"`
}

func SignTaskEnvelope(secret string, task TaskEnvelope) string {
	return sign(secret, canonicalTaskEnvelope(task))
}

func VerifyTaskEnvelopeSignature(secret string, task TaskEnvelope, signature string) bool {
	if secret == "" || signature == "" {
		return false
	}
	expected := SignTaskEnvelope(secret, task)
	return hmac.Equal([]byte(expected), []byte(signature))
}

func canonicalTaskEnvelope(task TaskEnvelope) string {
	// Fixed struct field order gives a stable canonical representation for this
	// narrowly scoped envelope and avoids signing mutable task status fields.
	b, _ := json.Marshal(struct {
		ID            int64  `json:"id"`
		ServerID      int64  `json:"server_id"`
		Type          string `json:"type"`
		ConfigVersion int64  `json:"config_version"`
		Nonce         string `json:"nonce"`
		PayloadJSON   string `json:"payload_json"`
	}{task.ID, task.ServerID, task.Type, task.ConfigVersion, task.Nonce, task.PayloadJSON})
	return string(b)
}

func sign(secret, payload string) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(payload))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}
