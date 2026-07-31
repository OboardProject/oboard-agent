package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/OboardProject/oboard-agent/internal/core"
	"github.com/OboardProject/oboard-agent/internal/model"
	"golang.org/x/crypto/ssh"
)

const (
	tunnelsCurrent         = "tunnels.json"
	tunnelsLastGood        = "tunnels.last-good.json"
	tunnelsDir             = "tunnels"
	managedSSHUser         = "oboard_tunnel"
	managedSSHHome         = "/var/lib/oboard-ssh"
	managedSSHReadyTimeout = 150 * time.Second
)

type sshTunnelConfig struct {
	ManagedPair      bool     `json:"managed_pair"`
	Role             string   `json:"role"`
	User             string   `json:"user"`
	KeyPath          string   `json:"key_path"`
	ClientPrivateKey string   `json:"client_private_key"`
	AuthorizedKey    string   `json:"authorized_key"`
	PermitOpen       string   `json:"permit_open"`
	ServerPort       int      `json:"server_port"`
	LocalForward     string   `json:"local_forward"`
	RemoteForward    string   `json:"remote_forward"`
	ExtraArgs        []string `json:"extra_args"`
	ManagedBy        string   `json:"managed_by"`
	PathID           int64    `json:"path_id"`
	StepID           int64    `json:"step_id"`
}

type tunnelApplyResult struct {
	Version      int64             `json:"version"`
	Unchanged    bool              `json:"unchanged,omitempty"`
	Applied      int               `json:"applied"`
	WireGuard    int               `json:"wireguard"`
	SSH          int               `json:"ssh"`
	Capabilities map[string]bool   `json:"capabilities"`
	Warnings     []string          `json:"warnings,omitempty"`
	Tunnels      map[string]string `json:"tunnels,omitempty"`
}

func (r *Runner) applyTunnels(plan model.TunnelPlan) (tunnelApplyResult, error) {
	r.tunnelLifecycleMu.Lock()
	defer r.tunnelLifecycleMu.Unlock()
	result := tunnelApplyResult{Version: plan.Version, Capabilities: detectTunnelCapabilities(), Tunnels: map[string]string{}}
	desiredState, err := tunnelDesiredStateID(plan)
	if err != nil {
		return result, err
	}
	if desiredState != "" && desiredState == r.tunnelDesiredState {
		result.Unchanged = true
		return result, nil
	}
	stateDir := r.stateDir()
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		return tunnelApplyResult{}, err
	}
	if err := r.prepareTunnelDependencies(plan.Tunnels); err != nil {
		return result, err
	}
	result.Capabilities = detectTunnelCapabilities()
	current := filepath.Join(stateDir, tunnelsCurrent)
	backup := filepath.Join(stateDir, tunnelsLastGood)
	// #nosec G304 -- current is a fixed file below the Agent's configured state directory.
	if b, err := os.ReadFile(current); err == nil {
		if err := atomicWriteFile(backup, b, 0o600); err != nil {
			return result, err
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return result, err
	} else if err := os.Remove(backup); err != nil && !errors.Is(err, os.ErrNotExist) {
		return result, err
	}
	data, err := json.MarshalIndent(plan, "", "  ")
	if err != nil {
		return result, err
	}
	if err := r.applyTunnelSet(plan.Tunnels, &result); err != nil {
		if rollbackErr := r.restoreLastGoodTunnels(backup); rollbackErr != nil {
			result.Warnings = append(result.Warnings, fmt.Sprintf("restore last-good tunnels: %v", rollbackErr))
		}
		return result, err
	}
	if err := atomicWriteFile(current, data, 0o600); err != nil {
		if rollbackErr := r.restoreLastGoodTunnels(backup); rollbackErr != nil {
			result.Warnings = append(result.Warnings, fmt.Sprintf("restore last-good tunnels: %v", rollbackErr))
		}
		return result, err
	}
	r.tunnelDesiredState = desiredState
	return result, nil
}

func (r *Runner) restoreManagedTunnelsOnStartup() error {
	b, err := os.ReadFile(filepath.Join(r.stateDir(), tunnelsCurrent))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	var plan model.TunnelPlan
	if err := json.Unmarshal(b, &plan); err != nil {
		return err
	}
	_, err = r.applyTunnels(plan)
	return err
}

func (r *Runner) restoreLastGoodTunnels(path string) error {
	// #nosec G304 -- path is the fixed last-good file assembled below the Agent state directory.
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		result := tunnelApplyResult{Capabilities: detectTunnelCapabilities(), Tunnels: map[string]string{}}
		return r.applyTunnelSet(nil, &result)
	}
	if err != nil {
		return err
	}
	var plan model.TunnelPlan
	if err := json.Unmarshal(b, &plan); err != nil {
		return err
	}
	result := tunnelApplyResult{Version: plan.Version, Capabilities: detectTunnelCapabilities(), Tunnels: map[string]string{}}
	return r.applyTunnelSet(plan.Tunnels, &result)
}

func detectTunnelCapabilities() map[string]bool {
	_, wgQuickErr := exec.LookPath("wg-quick")
	_, wgErr := exec.LookPath("wg")
	_, sshErr := exec.LookPath("ssh")
	return map[string]bool{
		"wireguard":  runtime.GOOS == "linux" && wgQuickErr == nil && wgErr == nil,
		"ssh":        sshErr == nil,
		"ssh_server": sshServerBinary() != "",
		"linux":      runtime.GOOS == "linux",
	}
}

func (r *Runner) prepareTunnelDependencies(tunnels []model.Tunnel) error {
	needWireGuard, needSSHClient, needSSHServer := false, false, false
	for _, tunnel := range tunnels {
		switch tunnel.Type {
		case model.TunnelTypeWireGuard:
			needWireGuard = true
		case model.TunnelTypeSSH:
			cfg := parseSSHTunnelConfig(tunnel.ConfigJSON)
			if cfg.ManagedPair && cfg.Role == "server" {
				needSSHServer = true
			} else {
				needSSHClient = true
			}
		}
	}
	if needWireGuard {
		if err := r.ensureTunnelPackage("wireguard"); err != nil {
			return err
		}
	}
	if needSSHClient {
		if err := r.ensureTunnelPackage("ssh_client"); err != nil {
			return err
		}
	}
	if needSSHServer {
		if err := r.ensureTunnelPackage("ssh_server"); err != nil {
			return err
		}
	}
	return nil
}

func (r *Runner) ensureTunnelPackage(kind string) error {
	available := func() bool {
		switch kind {
		case "wireguard":
			_, wgErr := exec.LookPath("wg")
			_, quickErr := exec.LookPath("wg-quick")
			return runtime.GOOS == "linux" && wgErr == nil && quickErr == nil
		case "ssh_client":
			_, err := exec.LookPath("ssh")
			return err == nil
		case "ssh_server":
			return sshServerBinary() != ""
		default:
			return false
		}
	}
	if available() {
		return nil
	}
	if runtime.GOOS != "linux" || os.Geteuid() != 0 {
		return fmt.Errorf("%s tunnel dependency is missing and automatic installation requires root on Linux", kind)
	}
	distro := detectDistroInfo()
	name, args, env, err := tunnelPackageInstallCommand(distro.PackageManager, kind)
	if err != nil {
		return err
	}
	if distro.PackageManager == "apt" {
		if err := runCommandEnv(2*time.Minute, env, "apt-get", "update"); err != nil {
			return fmt.Errorf("refresh apt package index for %s tunnel dependency: %w", kind, err)
		}
	}
	if err := runCommandEnv(2*time.Minute, env, name, args...); err != nil {
		return fmt.Errorf("install %s tunnel dependency with %s: %w", kind, distro.PackageManager, err)
	}
	if !available() {
		return fmt.Errorf("%s tunnel dependency is still unavailable after package installation", kind)
	}
	return nil
}

func tunnelPackageInstallCommand(packageManager, kind string) (string, []string, []string, error) {
	packages := map[string]map[string]string{
		"apk":    {"wireguard": "wireguard-tools", "ssh_client": "openssh-client-default", "ssh_server": "openssh-server"},
		"apt":    {"wireguard": "wireguard-tools", "ssh_client": "openssh-client", "ssh_server": "openssh-server"},
		"dnf":    {"wireguard": "wireguard-tools", "ssh_client": "openssh-clients", "ssh_server": "openssh-server"},
		"yum":    {"wireguard": "wireguard-tools", "ssh_client": "openssh-clients", "ssh_server": "openssh-server"},
		"pacman": {"wireguard": "wireguard-tools", "ssh_client": "openssh", "ssh_server": "openssh"},
		"zypper": {"wireguard": "wireguard-tools", "ssh_client": "openssh", "ssh_server": "openssh"},
	}
	pkg := packages[packageManager][kind]
	if pkg == "" {
		return "", nil, nil, fmt.Errorf("cannot automatically install %s tunnel dependency with package manager %q", kind, packageManager)
	}
	switch packageManager {
	case "apk":
		return "apk", []string{"add", "--no-cache", pkg}, nil, nil
	case "apt":
		return "apt-get", []string{"install", "-y", "--no-install-recommends", pkg}, []string{"DEBIAN_FRONTEND=noninteractive"}, nil
	case "dnf", "yum":
		return packageManager, []string{"install", "-y", pkg}, nil, nil
	case "pacman":
		return "pacman", []string{"-Sy", "--noconfirm", pkg}, nil, nil
	case "zypper":
		return "zypper", []string{"--non-interactive", "install", pkg}, nil, nil
	default:
		return "", nil, nil, fmt.Errorf("unsupported package manager %q", packageManager)
	}
}

func runCommandEnv(timeout time.Duration, extraEnv []string, name string, args ...string) error {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	// #nosec G204 -- name and args come from the package-manager allowlist in dependencyInstallCommand.
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Env = append(os.Environ(), extraEnv...)
	var out limitBuffer
	out.limit = commandOutputLimit
	cmd.Stdout = &out
	cmd.Stderr = &out
	err := cmd.Run()
	if ctx.Err() == context.DeadlineExceeded {
		return fmt.Errorf("command timed out after %s", timeout)
	}
	if err != nil {
		return fmt.Errorf("%s %v: %w: %s", name, args, err, out.String())
	}
	return nil
}

func sshServerBinary() string {
	if path, err := exec.LookPath("sshd"); err == nil {
		return path
	}
	for _, path := range []string{"/usr/sbin/sshd", "/usr/local/sbin/sshd"} {
		if info, err := os.Stat(path); err == nil && !info.IsDir() {
			return path
		}
	}
	return ""
}

func (r *Runner) applyTunnelSet(tunnels []model.Tunnel, result *tunnelApplyResult) error {
	if err := validateTunnelSet(tunnels, result.Capabilities); err != nil {
		return err
	}
	dir := filepath.Join(r.stateDir(), tunnelsDir)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	if err := r.stopManagedTunnels(dir, result); err != nil {
		return err
	}
	if err := validateManagedSSHServerPortsAvailable(tunnels); err != nil {
		return err
	}
	if err := r.reconcileSSHServerAccount(dir, tunnels); err != nil {
		return err
	}
	for _, t := range tunnels {
		switch t.Type {
		case model.TunnelTypeWireGuard:
			if err := r.applyWireGuardTunnel(dir, t); err != nil {
				return err
			}
			result.WireGuard++
		case model.TunnelTypeSSH:
			cfg := parseSSHTunnelConfig(t.ConfigJSON)
			if !cfg.ManagedPair || cfg.Role != "server" {
				if err := r.applySSHTunnel(dir, t); err != nil {
					return err
				}
			}
			result.SSH++
		default:
			return fmt.Errorf("unsupported tunnel type %q", t.Type)
		}
		result.Applied++
		result.Tunnels[fmt.Sprint(t.ID)] = string(t.Type)
	}
	return nil
}

func validateTunnelSet(tunnels []model.Tunnel, capabilities map[string]bool) error {
	for _, tunnel := range tunnels {
		if err := core.ValidateTunnelConfig(tunnel); err != nil {
			return err
		}
		if strings.TrimSpace(tunnel.TargetEndpoint) != "" {
			if err := core.ValidateTunnelEndpoint(tunnel.TargetEndpoint); err != nil {
				return err
			}
		}
		switch tunnel.Type {
		case model.TunnelTypeWireGuard:
			if !capabilities["wireguard"] {
				return fmt.Errorf("tunnel %q requires wg and wg-quick on Linux", tunnel.Name)
			}
		case model.TunnelTypeSSH:
			cfg := parseSSHTunnelConfig(tunnel.ConfigJSON)
			if cfg.ManagedPair && cfg.Role == "server" {
				if !capabilities["ssh_server"] {
					return fmt.Errorf("tunnel %q requires sshd", tunnel.Name)
				}
			} else {
				if !capabilities["ssh"] {
					return fmt.Errorf("tunnel %q requires ssh binary", tunnel.Name)
				}
				if strings.TrimSpace(tunnel.TargetEndpoint) == "" {
					return fmt.Errorf("ssh tunnel %q requires target_endpoint", tunnel.Name)
				}
			}
		default:
			return fmt.Errorf("unsupported tunnel type %q", tunnel.Type)
		}
	}
	return nil
}

func (r *Runner) stopManagedTunnels(dir string, result *tunnelApplyResult) error {
	if pids, err := filepath.Glob(filepath.Join(dir, "ssh-*.pid")); err == nil {
		for _, pidPath := range pids {
			if err := stopManagedProcess(pidPath); err != nil {
				result.Warnings = append(result.Warnings, fmt.Sprintf("stop ssh tunnel %s: %v", filepath.Base(pidPath), err))
			}
		}
	}
	if pids, err := filepath.Glob(filepath.Join(dir, "sshd-*.pid")); err == nil {
		for _, pidPath := range pids {
			if err := stopManagedProcess(pidPath); err != nil {
				result.Warnings = append(result.Warnings, fmt.Sprintf("stop managed sshd %s: %v", filepath.Base(pidPath), err))
			}
		}
	}
	if keys, err := filepath.Glob(filepath.Join(dir, "ssh-*.key")); err == nil {
		for _, keyPath := range keys {
			if err := os.Remove(keyPath); err != nil && !errors.Is(err, os.ErrNotExist) {
				result.Warnings = append(result.Warnings, fmt.Sprintf("remove managed SSH key %s: %v", filepath.Base(keyPath), err))
			}
		}
	}
	if !result.Capabilities["wireguard"] {
		return nil
	}
	if configs, err := filepath.Glob(filepath.Join(dir, "obw*.conf")); err == nil {
		for _, path := range configs {
			if err := runCommand(r.commandTimeout(), "wg-quick", "down", path); err != nil {
				result.Warnings = append(result.Warnings, fmt.Sprintf("down wireguard %s: %v", filepath.Base(path), err))
			}
		}
	}
	return nil
}

func (r *Runner) applyWireGuardTunnel(dir string, t model.Tunnel) error {
	var cfg struct {
		PrivateKey          string   `json:"private_key"`
		PeerPublicKey       string   `json:"peer_public_key"`
		AllowedIPs          []string `json:"allowed_ips"`
		PersistentKeepalive int      `json:"persistent_keepalive"`
	}
	_ = json.Unmarshal([]byte(t.ConfigJSON), &cfg)
	if cfg.PrivateKey == "" || cfg.PeerPublicKey == "" {
		return fmt.Errorf("wireguard tunnel %q requires config_json.private_key and peer_public_key", t.Name)
	}
	if len(cfg.AllowedIPs) == 0 && strings.TrimSpace(t.PeerAddress) != "" {
		cfg.AllowedIPs = []string{t.PeerAddress}
	}
	if cfg.PersistentKeepalive == 0 {
		cfg.PersistentKeepalive = 25
	}
	name := fmt.Sprintf("obw%d", t.ID)
	path := filepath.Join(dir, name+".conf")
	var b strings.Builder
	b.WriteString("# Generated by OBoard Agent. Do not edit manually.\n")
	b.WriteString("[Interface]\n")
	b.WriteString("PrivateKey = " + cfg.PrivateKey + "\n")
	if t.LocalAddress != "" {
		b.WriteString("Address = " + t.LocalAddress + "\n")
	}
	if t.ListenPort > 0 {
		b.WriteString(fmt.Sprintf("ListenPort = %d\n", t.ListenPort))
	}
	b.WriteString("\n[Peer]\n")
	b.WriteString("PublicKey = " + cfg.PeerPublicKey + "\n")
	if t.TargetEndpoint != "" && t.TargetPort > 0 {
		b.WriteString("Endpoint = " + net.JoinHostPort(t.TargetEndpoint, fmt.Sprint(t.TargetPort)) + "\n")
	}
	if len(cfg.AllowedIPs) > 0 {
		b.WriteString("AllowedIPs = " + strings.Join(cfg.AllowedIPs, ",") + "\n")
	}
	b.WriteString(fmt.Sprintf("PersistentKeepalive = %d\n", cfg.PersistentKeepalive))
	if err := os.WriteFile(path, []byte(b.String()), 0o600); err != nil {
		return err
	}
	_ = runCommand(r.commandTimeout(), "wg-quick", "down", path)
	if err := runCommand(r.commandTimeout(), "wg-quick", "up", path); err != nil {
		return err
	}
	return waitForWireGuardHandshake(name, t.PeerAddress, 40*time.Second)
}

func waitForWireGuardHandshake(interfaceName, peerAddress string, timeout time.Duration) error {
	peerIP, err := wireGuardPeerIP(peerAddress)
	if err != nil {
		return err
	}
	deadline := time.Now().Add(timeout)
	for {
		triggerWireGuardPeer(peerIP)
		output, showErr := commandOutput(2*time.Second, "wg", "show", interfaceName, "latest-handshakes")
		if showErr == nil {
			for _, line := range strings.Split(output, "\n") {
				fields := strings.Fields(line)
				if len(fields) < 2 {
					continue
				}
				stamp, parseErr := strconv.ParseInt(fields[len(fields)-1], 10, 64)
				if parseErr == nil && stamp > 0 {
					return nil
				}
			}
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("wireguard interface %s did not complete a peer handshake within %s", interfaceName, timeout)
		}
		time.Sleep(250 * time.Millisecond)
	}
}

func wireGuardPeerIP(raw string) (netip.Addr, error) {
	raw = strings.TrimSpace(raw)
	if prefix, err := netip.ParsePrefix(raw); err == nil {
		return prefix.Addr(), nil
	}
	if address, err := netip.ParseAddr(raw); err == nil {
		return address, nil
	}
	return netip.Addr{}, fmt.Errorf("wireguard peer address %q is invalid", raw)
}

func triggerWireGuardPeer(peer netip.Addr) {
	address := net.UDPAddr{IP: net.IP(peer.AsSlice()), Port: 9}
	conn, err := net.DialUDP("udp", nil, &address)
	if err != nil {
		return
	}
	_, _ = conn.Write([]byte{0})
	_ = conn.Close()
}

func parseSSHTunnelConfig(raw string) sshTunnelConfig {
	var cfg sshTunnelConfig
	_ = json.Unmarshal([]byte(raw), &cfg)
	return cfg
}

func (r *Runner) reconcileSSHServerAccount(dir string, tunnels []model.Tunnel) error {
	serverTunnels := make([]model.Tunnel, 0)
	for _, tunnel := range tunnels {
		if tunnel.Type != model.TunnelTypeSSH {
			continue
		}
		cfg := parseSSHTunnelConfig(tunnel.ConfigJSON)
		if cfg.ManagedPair && cfg.Role == "server" {
			serverTunnels = append(serverTunnels, tunnel)
		}
	}
	marker := filepath.Join(dir, "ssh-account-managed")
	if len(serverTunnels) == 0 {
		if _, err := os.Stat(marker); errors.Is(err, os.ErrNotExist) {
			return nil
		}
	}
	if runtime.GOOS != "linux" || os.Geteuid() != 0 {
		return errors.New("managed SSH server account requires root on Linux")
	}
	account, err := ensureManagedSSHAccount(marker)
	if err != nil {
		return err
	}
	sshDir := filepath.Join(managedSSHHome, ".ssh")
	if err := os.MkdirAll(sshDir, 0o700); err != nil {
		return err
	}
	uid, err := strconv.Atoi(account.Uid)
	if err != nil {
		return err
	}
	gid, err := strconv.Atoi(account.Gid)
	if err != nil {
		return err
	}
	if err := os.Chown(managedSSHHome, uid, gid); err != nil {
		return err
	}
	// #nosec G302 -- this is a directory and 0700 is the intended private-directory mode.
	if err := os.Chmod(managedSSHHome, 0o700); err != nil {
		return err
	}
	if err := os.Chown(sshDir, uid, gid); err != nil {
		return err
	}
	sort.Slice(serverTunnels, func(i, j int) bool { return serverTunnels[i].ID < serverTunnels[j].ID })
	lines := make([]string, 0, len(serverTunnels))
	for _, tunnel := range serverTunnels {
		cfg := parseSSHTunnelConfig(tunnel.ConfigJSON)
		publicKey, _, _, _, err := ssh.ParseAuthorizedKey([]byte(cfg.AuthorizedKey))
		if err != nil {
			return fmt.Errorf("ssh tunnel %q authorized key: %w", tunnel.Name, err)
		}
		canonicalKey := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(publicKey)))
		lines = append(lines, fmt.Sprintf("command=\"/bin/false\",no-agent-forwarding,no-X11-forwarding,no-pty,no-user-rc,permitopen=\"%s\" %s oboard-tunnel-%d", cfg.PermitOpen, canonicalKey, tunnel.ID))
	}
	authorizedKeys := filepath.Join(sshDir, "authorized_keys")
	content := ""
	if len(lines) > 0 {
		content = strings.Join(lines, "\n") + "\n"
	}
	if err := atomicWriteFile(authorizedKeys, []byte(content), 0o600); err != nil {
		return err
	}
	if err := os.Chown(authorizedKeys, uid, gid); err != nil {
		return err
	}
	ports := map[int]bool{}
	for _, tunnel := range serverTunnels {
		ports[parseSSHTunnelConfig(tunnel.ConfigJSON).ServerPort] = true
	}
	for port := range ports {
		if err := startManagedSSHServer(dir, port); err != nil {
			return err
		}
	}
	return nil
}

func validateManagedSSHServerPortsAvailable(tunnels []model.Tunnel) error {
	ports := map[int]bool{}
	for _, tunnel := range tunnels {
		if tunnel.Type != model.TunnelTypeSSH {
			continue
		}
		cfg := parseSSHTunnelConfig(tunnel.ConfigJSON)
		if cfg.ManagedPair && cfg.Role == "server" {
			ports[cfg.ServerPort] = true
		}
	}
	for port := range ports {
		if err := managedSSHServerPortAvailable(port); err != nil {
			return err
		}
	}
	return nil
}

func managedSSHServerPortAvailable(port int) error {
	if port <= 0 || port > 65535 {
		return errors.New("managed SSH server port is invalid")
	}
	addresses, err := managedSSHListenAddresses()
	if err != nil {
		return err
	}
	for _, address := range addresses {
		listener, err := net.Listen(address.network, net.JoinHostPort(address.host, strconv.Itoa(port)))
		if err != nil {
			return fmt.Errorf("目标端隧道服务端口 %d 已被其他进程占用", port)
		}
		if err := listener.Close(); err != nil {
			return err
		}
	}
	return nil
}

type managedSSHListenAddress struct {
	network string
	host    string
}

func managedSSHListenAddresses() ([]managedSSHListenAddress, error) {
	addresses := []managedSSHListenAddress{{network: "tcp4", host: "127.0.0.1"}, {network: "tcp4", host: "0.0.0.0"}}
	seen := map[string]bool{"tcp4|127.0.0.1": true, "tcp4|0.0.0.0": true}
	ipv6 := tcp6Available()
	if ipv6 {
		addresses = append(addresses, managedSSHListenAddress{network: "tcp6", host: "::1"}, managedSSHListenAddress{network: "tcp6", host: "::"})
		seen["tcp6|::1"] = true
		seen["tcp6|::"] = true
	}
	interfaces, err := net.Interfaces()
	if err != nil {
		return nil, fmt.Errorf("list local interfaces for managed SSH port check: %w", err)
	}
	for _, iface := range interfaces {
		interfaceAddresses, err := iface.Addrs()
		if err != nil {
			return nil, fmt.Errorf("list addresses for interface %s: %w", iface.Name, err)
		}
		for _, raw := range interfaceAddresses {
			var ip net.IP
			switch address := raw.(type) {
			case *net.IPNet:
				ip = address.IP
			case *net.IPAddr:
				ip = address.IP
			}
			if ip == nil || ip.IsUnspecified() || ip.IsMulticast() {
				continue
			}
			network, host := "tcp6", ip.String()
			if ipv4 := ip.To4(); ipv4 != nil {
				network, host = "tcp4", ipv4.String()
			} else if !ipv6 {
				continue
			} else if ip.IsLinkLocalUnicast() {
				host += "%" + iface.Name
			}
			key := network + "|" + host
			if !seen[key] {
				seen[key] = true
				addresses = append(addresses, managedSSHListenAddress{network: network, host: host})
			}
		}
	}
	return addresses, nil
}

func tcp6Available() bool {
	listener, err := net.Listen("tcp6", "[::]:0")
	if err != nil {
		return false
	}
	_ = listener.Close()
	return true
}

func ensureManagedSSHAccount(marker string) (*user.User, error) {
	account, lookupErr := user.Lookup(managedSSHUser)
	markerExists := false
	if _, err := os.Stat(marker); err == nil {
		markerExists = true
	}
	if lookupErr == nil {
		if !markerExists {
			return nil, fmt.Errorf("refusing to modify existing unmanaged account %q", managedSSHUser)
		}
		if err := setManagedSSHPasswordHash(); err != nil {
			return nil, err
		}
		return account, nil
	}
	if _, ok := lookupErr.(user.UnknownUserError); !ok {
		return nil, lookupErr
	}
	if err := os.MkdirAll(managedSSHHome, 0o700); err != nil {
		return nil, err
	}
	nologin := "/usr/sbin/nologin"
	if _, err := os.Stat(nologin); err != nil {
		nologin = "/sbin/nologin"
		if _, err := os.Stat(nologin); err != nil {
			nologin = "/bin/false"
		}
	}
	if _, err := exec.LookPath("useradd"); err == nil {
		if err := runCommand(20*time.Second, "useradd", "--system", "--user-group", "--home-dir", managedSSHHome, "--shell", nologin, managedSSHUser); err != nil {
			return nil, err
		}
	} else if _, err := exec.LookPath("adduser"); err == nil {
		if err := runCommand(20*time.Second, "adduser", "-S", "-D", "-H", "-h", managedSSHHome, "-s", nologin, managedSSHUser); err != nil {
			return nil, err
		}
	} else {
		return nil, errors.New("managed SSH account requires useradd or adduser")
	}
	if err := atomicWriteFile(marker, []byte(managedSSHUser+"\n"), 0o600); err != nil {
		return nil, err
	}
	if err := setManagedSSHPasswordHash(); err != nil {
		return nil, err
	}
	account, err := user.Lookup(managedSSHUser)
	if err != nil {
		return nil, err
	}
	return account, nil
}

func setManagedSSHPasswordHash() error {
	// OpenSSH rejects accounts whose shadow hash begins with ! or *. A literal
	// invalid hash keeps the account enabled for public-key forwarding while no
	// password can ever verify against it.
	if path, err := exec.LookPath("chpasswd"); err == nil {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		// #nosec G204 -- path is returned by exec.LookPath for the fixed chpasswd executable.
		cmd := exec.CommandContext(ctx, path, "-e")
		cmd.Stdin = strings.NewReader(managedSSHUser + ":x\n")
		var out limitBuffer
		out.limit = commandOutputLimit
		cmd.Stdout = &out
		cmd.Stderr = &out
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("enable managed SSH account: %w: %s", err, out.String())
		}
		return nil
	}
	if _, err := exec.LookPath("usermod"); err == nil {
		return runCommand(10*time.Second, "usermod", "-p", "x", managedSSHUser)
	}
	return errors.New("managed SSH account requires chpasswd or usermod")
}

func startManagedSSHServer(dir string, port int) error {
	if port <= 0 {
		return errors.New("managed SSH server port is invalid")
	}
	sshd := sshServerBinary()
	if sshd == "" {
		return errors.New("sshd is unavailable")
	}
	hostKeyPath := filepath.Join(dir, "sshd-host-ed25519")
	if _, err := os.Stat(hostKeyPath); errors.Is(err, os.ErrNotExist) {
		if _, keygenErr := exec.LookPath("ssh-keygen"); keygenErr != nil {
			return errors.New("managed sshd requires ssh-keygen")
		}
		if err := runCommand(20*time.Second, "ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", hostKeyPath); err != nil {
			return err
		}
	} else if err != nil {
		return err
	}
	configPath := filepath.Join(dir, fmt.Sprintf("sshd-%d.conf", port))
	pidPath := filepath.Join(dir, fmt.Sprintf("sshd-%d.pid", port))
	logPath := filepath.Join(dir, fmt.Sprintf("sshd-%d.log", port))
	config := strings.Join([]string{
		"Port " + strconv.Itoa(port),
		"AddressFamily any",
		"HostKey " + hostKeyPath,
		"PidFile /run/oboard-sshd-" + strconv.Itoa(port) + ".pid",
		"AuthorizedKeysFile " + filepath.Join(managedSSHHome, ".ssh", "authorized_keys"),
		"AuthenticationMethods publickey",
		"PubkeyAuthentication yes",
		"PasswordAuthentication no",
		"KbdInteractiveAuthentication no",
		"PermitRootLogin no",
		"AllowUsers " + managedSSHUser,
		"AllowTcpForwarding local",
		"AllowAgentForwarding no",
		"GatewayPorts no",
		"X11Forwarding no",
		"PermitTTY no",
		"PermitUserRC no",
		"ForceCommand /bin/false",
		"UsePAM no",
		"StrictModes yes",
		"LogLevel ERROR",
		"", // final newline
	}, "\n")
	if err := atomicWriteFile(configPath, []byte(config), 0o600); err != nil {
		return err
	}
	// #nosec G301 -- OpenSSH requires /run/sshd to be searchable by the daemon before privilege separation.
	if err := os.MkdirAll("/run/sshd", 0o755); err != nil {
		return err
	}
	if err := runCommand(10*time.Second, sshd, "-t", "-f", configPath); err != nil {
		return fmt.Errorf("validate managed sshd config: %w", err)
	}
	_ = stopManagedProcess(pidPath)
	// #nosec G304 -- logPath is a fixed file name below the private tunnel state directory.
	logFile, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return err
	}
	// #nosec G204 -- sshd is resolved from a fixed executable name or fixed absolute paths; no shell is involved.
	cmd := exec.Command(sshd, "-D", "-e", "-f", configPath)
	cmd.Stdout = logFile
	cmd.Stderr = logFile
	if err := cmd.Start(); err != nil {
		_ = logFile.Close()
		return err
	}
	_ = logFile.Close()
	waitCh := make(chan error, 1)
	go func() { waitCh <- cmd.Wait() }()
	select {
	case err := <-waitCh:
		return fmt.Errorf("managed sshd exited before ready: %w%s", err, sshFailureLogSuffix(logPath))
	case <-time.After(300 * time.Millisecond):
	}
	if err := writeManagedPIDFile(pidPath, cmd.Process.Pid, "sshd"); err != nil {
		_ = cmd.Process.Kill()
		return err
	}
	address := net.JoinHostPort("127.0.0.1", strconv.Itoa(port))
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", address, 300*time.Millisecond)
		if err == nil {
			_ = conn.Close()
			return nil
		}
		time.Sleep(100 * time.Millisecond)
	}
	_ = stopManagedProcess(pidPath)
	return fmt.Errorf("managed sshd is not listening on %s%s", address, sshFailureLogSuffix(logPath))
}

func (r *Runner) applySSHTunnel(dir string, t model.Tunnel) error {
	// Re-validate at apply time so a compromised controller cannot smuggle
	// ProxyCommand-style extra_args past an older validation path.
	if err := core.ValidateTunnelConfig(t); err != nil {
		return err
	}
	if err := core.ValidateTunnelEndpoint(t.TargetEndpoint); err != nil {
		return fmt.Errorf("ssh tunnel %q target_endpoint: %w", t.Name, err)
	}
	cfg := parseSSHTunnelConfig(t.ConfigJSON)
	if cfg.User == "" {
		return fmt.Errorf("ssh tunnel %q requires config_json.user", t.Name)
	}
	if t.TargetEndpoint == "" {
		return fmt.Errorf("ssh tunnel %q requires target_endpoint or a target server address", t.Name)
	}
	pidPath := filepath.Join(dir, fmt.Sprintf("ssh-%d.pid", t.ID))
	_ = stopManagedProcess(pidPath)
	keyPath := cfg.KeyPath
	if cfg.ManagedPair {
		if cfg.Role != "client" {
			return fmt.Errorf("ssh tunnel %q cannot start non-client managed role %q", t.Name, cfg.Role)
		}
		keyPath = filepath.Join(dir, fmt.Sprintf("ssh-%d.key", t.ID))
		if err := atomicWriteFile(keyPath, []byte(cfg.ClientPrivateKey), 0o600); err != nil {
			return err
		}
	}
	if keyPath == "" {
		return fmt.Errorf("ssh tunnel %q requires an explicit private key", t.Name)
	}
	args := []string{
		"-N",
		"-o", "ExitOnForwardFailure=yes",
		"-o", "ServerAliveInterval=30",
		"-o", "ServerAliveCountMax=3",
		"-o", "ConnectTimeout=5",
		"-o", "BatchMode=yes",
		"-o", "IdentitiesOnly=yes",
		"-o", "PasswordAuthentication=no",
		"-o", "KbdInteractiveAuthentication=no",
		"-o", "PreferredAuthentications=publickey",
		"-i", keyPath,
	}
	if cfg.ManagedPair {
		knownHostsPath := filepath.Join(dir, "ssh-known-hosts")
		// #nosec G304 -- knownHostsPath is a fixed file below the private tunnel state directory.
		knownHostsFile, err := os.OpenFile(knownHostsPath, os.O_CREATE|os.O_WRONLY, 0o600)
		if err != nil {
			return err
		}
		_ = knownHostsFile.Close()
		args = append(args, "-o", "StrictHostKeyChecking=accept-new", "-o", "UserKnownHostsFile="+knownHostsPath)
	}
	if cfg.LocalForward != "" {
		args = append(args, "-L", cfg.LocalForward)
	}
	if cfg.RemoteForward != "" {
		args = append(args, "-R", cfg.RemoteForward)
	}
	// Intentionally no ExtraArgs: OpenSSH option injection is rejected by ValidateTunnelConfig.
	endpoint := t.TargetEndpoint
	if t.TargetPort > 0 {
		args = append(args, "-p", fmt.Sprint(t.TargetPort))
	}
	args = append(args, cfg.User+"@"+endpoint)
	logPath := filepath.Join(dir, fmt.Sprintf("ssh-%d.log", t.ID))
	_ = os.Remove(logPath)
	deadline := time.Now()
	if cfg.ManagedPair {
		deadline = deadline.Add(managedSSHReadyTimeout)
	}
	var lastErr error
	for {
		// #nosec G204 -- the executable is the fixed OpenSSH client and validated fields are separate argv entries.
		cmd := exec.Command("ssh", args...)
		// #nosec G304 -- logPath is a fixed file below the private tunnel state directory.
		logFile, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
		if err != nil {
			return err
		}
		cmd.Stdout = logFile
		cmd.Stderr = logFile
		if err := cmd.Start(); err != nil {
			_ = logFile.Close()
			lastErr = err
		} else {
			_ = logFile.Close()
			waitCh := make(chan error, 1)
			go func() { waitCh <- cmd.Wait() }()
			if address, ok := sshLocalForwardAddress(cfg.LocalForward); cfg.ManagedPair && ok {
				ready, waitErr := waitForSSHLocalForward(cmd, waitCh, address, 7*time.Second)
				if ready {
					// The wait goroutine reaps the managed process after a later desired-state update.
					return writeManagedPIDFile(pidPath, cmd.Process.Pid, "ssh")
				}
				lastErr = waitErr
			} else {
				select {
				case err := <-waitCh:
					if err == nil {
						lastErr = errors.New("process exited before forwarding became ready")
					} else {
						lastErr = err
					}
				case <-time.After(500 * time.Millisecond):
					return writeManagedPIDFile(pidPath, cmd.Process.Pid, "ssh")
				}
			}
		}
		if !cfg.ManagedPair || time.Now().After(deadline) {
			return fmt.Errorf("ssh tunnel %q failed before forwarding became ready: %w%s", t.Name, lastErr, sshFailureLogSuffix(logPath))
		}
		time.Sleep(500 * time.Millisecond)
	}
}

func waitForSSHLocalForward(cmd *exec.Cmd, waitCh <-chan error, address string, timeout time.Duration) (bool, error) {
	deadline := time.Now().Add(timeout)
	var lastDialErr error
	for {
		select {
		case err := <-waitCh:
			if err == nil {
				err = errors.New("process exited before forwarding became ready")
			}
			return false, err
		default:
		}
		conn, err := net.DialTimeout("tcp", address, 200*time.Millisecond)
		if err == nil {
			_ = conn.Close()
			return true, nil
		}
		lastDialErr = err
		if time.Now().After(deadline) {
			_ = cmd.Process.Kill()
			select {
			case <-waitCh:
			case <-time.After(time.Second):
			}
			return false, fmt.Errorf("local forward %s is not usable: %w", address, lastDialErr)
		}
		time.Sleep(100 * time.Millisecond)
	}
}

func sshFailureLogSuffix(path string) string {
	// #nosec G304 -- path is a fixed managed-SSH log below the private tunnel state directory.
	b, err := os.ReadFile(path)
	if err != nil || len(b) == 0 {
		return ""
	}
	if len(b) > 2048 {
		b = b[len(b)-2048:]
	}
	text := strings.TrimSpace(string(b))
	text = strings.Map(func(r rune) rune {
		if r == '\n' || r == '\t' || (r >= 32 && r != 127) {
			return r
		}
		return -1
	}, text)
	if text == "" {
		return ""
	}
	return ": " + text
}

func sshLocalForwardAddress(spec string) (string, bool) {
	parts := strings.Split(spec, ":")
	if len(parts) == 3 {
		return net.JoinHostPort("127.0.0.1", parts[0]), true
	}
	if len(parts) == 4 {
		return net.JoinHostPort(parts[0], parts[1]), true
	}
	return "", false
}
