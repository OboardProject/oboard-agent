package agent

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/OboardProject/oboard-agent/internal/model"
	"golang.org/x/crypto/curve25519"
)

const (
	warpRegistrationURL      = "https://api.cloudflareclient.com/v0a2158/reg"
	warpPeerPublicKey        = "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo="
	warpBootstrapResolverTag = "bootstrap-primary"
)

func resolveWarpCommand(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	switch raw {
	case "", "auto":
		return "", nil
	case "none":
		return "", errors.New("warp_command is none; WARP auto request disabled on this agent")
	default:
		// Only allow an absolute path whose base name is wgcf.
		if !filepath.IsAbs(raw) {
			return "", errors.New("warp_command custom path must be absolute")
		}
		cleaned := filepath.Clean(raw)
		if filepath.Base(cleaned) != "wgcf" {
			return "", errors.New("warp_command custom binary base name must be wgcf")
		}
		return cleaned, nil
	}
}

func (r *Runner) requestWARPConfig(ctx context.Context, plan model.WARPRequestPlan) model.WARPConfigReport {
	report := model.WARPConfigReport{ServerID: plan.ServerID, ProfileID: plan.ProfileID, Status: model.WARPStatusFailed, MTU: plan.MTU}
	if plan.ProfileID == 0 {
		report.Error = "profile_id required"
		return report
	}
	if persisted, err := r.loadPersistedWARPConfig(plan); err == nil {
		return persisted
	}
	cfg := r.Config()
	if strings.TrimSpace(cfg.WarpCommand) == "none" {
		report.Error = "warp_command is none; WARP auto request disabled on this agent"
		return report
	}
	if strings.TrimSpace(cfg.WarpCommand) == "" || strings.TrimSpace(cfg.WarpCommand) == "auto" {
		outbound, err := registerWARPWireGuard(ctx, r.client, warpRegistrationURL, plan)
		if err != nil {
			report.Error = err.Error()
			return report
		}
		return r.persistReadyWARPReport(report, outbound)
	}
	wgcf, err := resolveWarpCommand(cfg.WarpCommand)
	if err != nil {
		report.Error = err.Error()
		return report
	}
	profileDir := filepath.Join(r.stateDir(), "warp", strconv.FormatInt(plan.ProfileID, 10))
	if err := os.MkdirAll(profileDir, 0o700); err != nil {
		report.Error = err.Error()
		return report
	}
	if _, err := os.Stat(filepath.Join(profileDir, "wgcf-account.toml")); errors.Is(err, os.ErrNotExist) {
		if out, err := commandOutputInDir(ctx, profileDir, r.commandTimeout(), wgcf, "register", "--accept-tos"); err != nil {
			report.Error = fmt.Sprintf("wgcf register failed: %v: %s", err, out)
			return report
		}
	}
	if out, err := commandOutputInDir(ctx, profileDir, r.commandTimeout(), wgcf, "generate"); err != nil {
		report.Error = fmt.Sprintf("wgcf generate failed: %v: %s", err, out)
		return report
	}
	// #nosec G304 -- profileDir is a fixed child of the Agent state directory and the file name is constant.
	raw, err := os.ReadFile(filepath.Join(profileDir, "wgcf-profile.conf"))
	if err != nil {
		report.Error = err.Error()
		return report
	}
	outbound, err := wgcfProfileToSingBox(string(raw), plan)
	if err != nil {
		report.Error = err.Error()
		return report
	}
	return r.persistReadyWARPReport(report, outbound)
}

func (r *Runner) loadPersistedWARPConfig(plan model.WARPRequestPlan) (model.WARPConfigReport, error) {
	path := filepath.Join(r.stateDir(), "warp", strconv.FormatInt(plan.ProfileID, 10), "endpoint.json")
	// #nosec G304 -- path is a fixed child of the Agent state directory.
	raw, err := os.ReadFile(path)
	if err != nil {
		return model.WARPConfigReport{}, err
	}
	var endpoint map[string]any
	if err := json.Unmarshal(raw, &endpoint); err != nil || !strings.EqualFold(strings.TrimSpace(fmt.Sprint(endpoint["type"])), "wireguard") {
		return model.WARPConfigReport{}, errors.New("persisted WARP endpoint is invalid")
	}
	resolverBefore, _ := json.Marshal(endpoint["domain_resolver"])
	normalizeWARPDomainResolver(endpoint, plan)
	resolverAfter, _ := json.Marshal(endpoint["domain_resolver"])
	report := model.WARPConfigReport{ServerID: plan.ServerID, ProfileID: plan.ProfileID, Status: model.WARPStatusReady, ConfigJSON: string(raw), ResultJSON: string(raw), MTU: plan.MTU}
	if mtu, ok := endpoint["mtu"].(float64); ok && mtu > 0 {
		report.MTU = int(mtu)
	}
	if !bytes.Equal(resolverBefore, resolverAfter) {
		return r.persistReadyWARPReport(report, endpoint), nil
	}
	return report, nil
}

func (r *Runner) persistReadyWARPReport(report model.WARPConfigReport, outbound map[string]any) model.WARPConfigReport {
	report = readyWARPReport(report, outbound)
	dir := filepath.Join(r.stateDir(), "warp", strconv.FormatInt(report.ProfileID, 10))
	if err := os.MkdirAll(dir, 0o700); err != nil {
		report.Status = model.WARPStatusFailed
		report.Error = err.Error()
		return report
	}
	if err := atomicWriteFile(filepath.Join(dir, "endpoint.json"), []byte(report.ConfigJSON), 0o600); err != nil {
		report.Status = model.WARPStatusFailed
		report.Error = err.Error()
	}
	return report
}

func readyWARPReport(report model.WARPConfigReport, outbound map[string]any) model.WARPConfigReport {
	b, _ := json.Marshal(outbound)
	report.ConfigJSON = string(b)
	report.Status = model.WARPStatusReady
	report.ResultJSON = string(b)
	if mtu, ok := outbound["mtu"].(int); ok {
		report.MTU = mtu
	}
	return report
}

type warpRegistrationResponse struct {
	ID     string `json:"id"`
	Config struct {
		ClientID  string `json:"client_id"`
		Interface struct {
			Addresses struct {
				V4 string `json:"v4"`
				V6 string `json:"v6"`
			} `json:"addresses"`
		} `json:"interface"`
	} `json:"config"`
}

func registerWARPWireGuard(ctx context.Context, client *http.Client, endpoint string, plan model.WARPRequestPlan) (map[string]any, error) {
	privateKey, publicKey, err := generateWireGuardKeyPair()
	if err != nil {
		return nil, fmt.Errorf("generate WARP wireguard key: %w", err)
	}
	installID, err := randomAlphaNumeric(22)
	if err != nil {
		return nil, fmt.Errorf("generate WARP install id: %w", err)
	}
	fcmSuffix, err := randomAlphaNumeric(134)
	if err != nil {
		return nil, fmt.Errorf("generate WARP device token: %w", err)
	}
	payload := map[string]any{
		"key": publicKey, "install_id": installID, "fcm_token": installID + ":APA91b" + fcmSuffix,
		"tos": time.Now().UTC().Format("2006-01-02T15:04:05.000Z"), "model": "PC", "serial_number": installID, "locale": "en_US",
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json; charset=UTF-8")
	req.Header.Set("User-Agent", "okhttp/3.12.1")
	req.Header.Set("CF-Client-Version", "a-6.10-2158")
	if client == nil {
		client = &http.Client{Timeout: 20 * time.Second}
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("register WARP device: %w", err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("read WARP registration response: %w", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("WARP registration returned HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(raw)))
	}
	var registration warpRegistrationResponse
	if err := json.Unmarshal(raw, &registration); err != nil {
		return nil, fmt.Errorf("decode WARP registration response: %w", err)
	}
	if registration.ID == "" || registration.Config.Interface.Addresses.V4 == "" || registration.Config.Interface.Addresses.V6 == "" {
		return nil, errors.New("WARP registration response is missing id or interface addresses")
	}
	reserved, err := warpReservedBytes(registration.Config.ClientID)
	if err != nil {
		return nil, err
	}
	addresses := []string{addressWithPrefix(registration.Config.Interface.Addresses.V4, 32), addressWithPrefix(registration.Config.Interface.Addresses.V6, 128)}
	mtu := plan.MTU
	if mtu <= 0 {
		mtu = 1280
	}
	peer := map[string]any{
		"address": "engage.cloudflareclient.com", "port": 2408, "public_key": warpPeerPublicKey,
		"allowed_ips": []string{"0.0.0.0/0", "::/0"}, "reserved": reserved,
	}
	out := map[string]any{
		"type": "wireguard", "tag": fmt.Sprintf("warp-%d", plan.ProfileID), "address": addresses,
		"private_key": privateKey, "mtu": mtu, "peers": []map[string]any{peer},
	}
	normalizeWARPDomainResolver(out, plan)
	return out, nil
}

func generateWireGuardKeyPair() (string, string, error) {
	private := make([]byte, curve25519.ScalarSize)
	if _, err := rand.Read(private); err != nil {
		return "", "", err
	}
	private[0] &= 248
	private[31] &= 127
	private[31] |= 64
	public, err := curve25519.X25519(private, curve25519.Basepoint)
	if err != nil {
		return "", "", err
	}
	return base64.StdEncoding.EncodeToString(private), base64.StdEncoding.EncodeToString(public), nil
}

func randomAlphaNumeric(length int) (string, error) {
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
	random := make([]byte, length)
	if _, err := rand.Read(random); err != nil {
		return "", err
	}
	out := make([]byte, length)
	for i, value := range random {
		out[i] = alphabet[int(value)%len(alphabet)]
	}
	return string(out), nil
}

func warpReservedBytes(clientID string) ([]int, error) {
	decoded, err := base64.StdEncoding.DecodeString(strings.TrimSpace(clientID))
	if err != nil || len(decoded) < 3 {
		return []int{0, 0, 0}, nil
	}
	return []int{int(decoded[0]), int(decoded[1]), int(decoded[2])}, nil
}

func addressWithPrefix(address string, bits int) string {
	address = strings.TrimSpace(address)
	if strings.Contains(address, "/") {
		return address
	}
	return address + "/" + strconv.Itoa(bits)
}

func commandOutputInDir(ctx context.Context, dir string, timeout time.Duration, name string, args ...string) (string, error) {
	if timeout <= 0 {
		timeout = 20 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	// #nosec G204 -- name is resolved by resolveWarpCommand and restricted to the wgcf binary.
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Dir = dir
	var out limitBuffer
	out.limit = commandOutputLimit
	cmd.Stdout = &out
	cmd.Stderr = &out
	err := cmd.Run()
	if ctx.Err() == context.DeadlineExceeded {
		return out.String(), fmt.Errorf("command timed out after %s", timeout)
	}
	return out.String(), err
}

func wgcfProfileToSingBox(profile string, plan model.WARPRequestPlan) (map[string]any, error) {
	sections := parseINI(profile)
	iface := sections["Interface"]
	peer := sections["Peer"]
	privateKey := iface["PrivateKey"]
	publicKey := peer["PublicKey"]
	endpoint := peer["Endpoint"]
	if privateKey == "" || publicKey == "" || endpoint == "" {
		return nil, errors.New("wgcf profile is missing PrivateKey/PublicKey/Endpoint")
	}
	host, port, err := net.SplitHostPort(endpoint)
	if err != nil {
		parts := strings.Split(endpoint, ":")
		if len(parts) < 2 {
			return nil, fmt.Errorf("invalid WARP endpoint %q", endpoint)
		}
		host = strings.Join(parts[:len(parts)-1], ":")
		port = parts[len(parts)-1]
	}
	serverPort, _ := strconv.Atoi(port)
	if serverPort == 0 {
		serverPort = 2408
	}
	if plan.IPStack == model.IPStackIPv6Only && net.ParseIP(strings.Trim(host, "[]")) != nil && net.ParseIP(strings.Trim(host, "[]")).To4() != nil {
		host = "engage.cloudflareclient.com"
	}
	mtu := plan.MTU
	if mtu == 0 {
		if parsed, _ := strconv.Atoi(iface["MTU"]); parsed > 0 {
			mtu = parsed
		}
	}
	if mtu == 0 && plan.IPStack == model.IPStackIPv6Only {
		mtu = 1280
	}
	if mtu == 0 {
		mtu = 1280
	}
	allowedIPs := splitCSV(peer["AllowedIPs"])
	if len(allowedIPs) == 0 {
		allowedIPs = []string{"0.0.0.0/0", "::/0"}
	}
	localAddress := splitCSV(iface["Address"])
	if len(localAddress) == 0 {
		return nil, errors.New("wgcf profile missing local Address")
	}
	peerConfig := map[string]any{
		"address":     strings.Trim(host, "[]"),
		"port":        serverPort,
		"public_key":  publicKey,
		"allowed_ips": allowedIPs,
	}
	reservedRaw := peer["Reserved"]
	if reservedRaw == "" {
		reservedRaw = iface["Reserved"]
	}
	if reserved := parseReserved(reservedRaw); len(reserved) > 0 {
		peerConfig["reserved"] = reserved
	}
	out := map[string]any{
		"type":        "wireguard",
		"tag":         fmt.Sprintf("warp-%d", plan.ProfileID),
		"address":     localAddress,
		"private_key": privateKey,
		"mtu":         mtu,
		"peers":       []map[string]any{peerConfig},
	}
	normalizeWARPDomainResolver(out, plan)
	return out, nil
}

func normalizeWARPDomainResolver(endpoint map[string]any, plan model.WARPRequestPlan) {
	strategy := strings.TrimSpace(plan.DNSStrategy)
	if strategy == "" || strings.EqualFold(strategy, "auto") {
		delete(endpoint, "domain_resolver")
		return
	}
	endpoint["domain_resolver"] = map[string]any{"server": warpBootstrapResolverTag, "strategy": strategy}
}

func parseINI(raw string) map[string]map[string]string {
	out := map[string]map[string]string{}
	section := ""
	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			section = strings.Trim(line, "[]")
			if out[section] == nil {
				out[section] = map[string]string{}
			}
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok || section == "" {
			continue
		}
		out[section][strings.TrimSpace(key)] = strings.TrimSpace(value)
	}
	return out
}

func splitCSV(v string) []string {
	out := []string{}
	for _, part := range strings.Split(v, ",") {
		part = strings.TrimSpace(part)
		if part != "" {
			out = append(out, part)
		}
	}
	return out
}

func parseReserved(v string) []int {
	parts := splitCSV(v)
	out := make([]int, 0, len(parts))
	for _, part := range parts {
		n, err := strconv.Atoi(part)
		if err == nil && n >= 0 && n <= 255 {
			out = append(out, n)
		}
	}
	return out
}

func reportToMap(report model.WARPConfigReport) map[string]any {
	return map[string]any{
		"server_id":   report.ServerID,
		"profile_id":  report.ProfileID,
		"status":      report.Status,
		"config_json": report.ConfigJSON,
		"mtu":         report.MTU,
		"error":       report.Error,
		"result_json": report.ResultJSON,
	}
}
