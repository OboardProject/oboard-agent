package agent

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/subtle"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/OboardProject/oboard-agent/internal/model"
)

const (
	sshInboundsCurrent  = "ssh-inbounds.json"
	sshInboundsLastGood = "ssh-inbounds.last-good.json"
	sshInboundHostKey   = "ssh-inbounds-host-key"
	sshInboundIOChunk   = 32 << 10
)

type sshInboundApplyResult struct {
	Version            int64    `json:"version"`
	Unchanged          bool     `json:"unchanged,omitempty"`
	Applied            int      `json:"applied"`
	Listeners          int      `json:"listeners"`
	Users              int      `json:"users"`
	HostPublicKey      string   `json:"host_public_key"`
	HostKeyFingerprint string   `json:"host_key_fingerprint"`
	Warnings           []string `json:"warnings,omitempty"`
}

// sshInboundManager owns only the Agent-native SSH proxy listeners. Keeping
// this separate from the SSH tunnel machinery prevents an inbound deployment
// from changing the host's sshd configuration or user accounts.
type sshInboundManager struct {
	mu        sync.RWMutex
	listeners map[int64]*managedSSHInbound
	signer    ssh.Signer
	usage     map[int64]*sshInboundUserUsage
}

type managedSSHInbound struct {
	plan     model.SSHInbound
	listener net.Listener
	auth     map[string]sshInboundCredential
	counters map[int64]*sshInboundCounter
	audit    *connectionAuditAccumulator

	mu    sync.Mutex
	conns map[net.Conn]int64
}

type sshInboundCredential struct {
	userID   int64
	password string
}

type sshInboundCounter struct {
	mu                   sync.RWMutex
	policy               model.TrafficRuntimePolicy
	upload               atomic.Int64
	download             atomic.Int64
	acknowledgedUpload   atomic.Int64
	acknowledgedDownload atomic.Int64
	usage                *sshInboundUserUsage
}

type sshInboundUserUsage struct {
	mu      sync.Mutex
	periods map[string]*sshInboundUsagePeriod
}

type sshInboundUsagePeriod struct {
	upload               atomic.Int64
	download             atomic.Int64
	acknowledgedUpload   atomic.Int64
	acknowledgedDownload atomic.Int64
}

type directTCPIPPayload struct {
	DestAddr   string
	DestPort   uint32
	OriginAddr string
	OriginPort uint32
}

func (r *Runner) applySSHInbounds(plan model.SSHInboundPlan) (sshInboundApplyResult, error) {
	r.sshInboundLifecycleMu.Lock()
	defer r.sshInboundLifecycleMu.Unlock()

	result := sshInboundApplyResult{Version: plan.Version}
	if err := os.MkdirAll(r.stateDir(), 0o700); err != nil {
		return result, err
	}
	hostSigner, err := r.loadSSHInboundHostSigner()
	if err != nil {
		return result, err
	}
	result.HostPublicKey = strings.TrimSpace(string(ssh.MarshalAuthorizedKey(hostSigner.PublicKey())))
	result.HostKeyFingerprint = ssh.FingerprintSHA256(hostSigner.PublicKey())
	desiredState, err := sshInboundDesiredStateID(plan)
	if err != nil {
		return result, err
	}
	if desiredState != "" && desiredState == r.sshInboundDesiredState {
		if err := r.reconcileSSHAndCoreTrafficPolicies(context.Background(), plan); err != nil {
			return result, fmt.Errorf("reconcile shared core/SSH quota lease: %w", err)
		}
		result.Unchanged = true
		return result, nil
	}
	if err := validateSSHInboundPlan(plan); err != nil {
		return result, err
	}
	if err := r.validateSSHInboundServerIDs(plan); err != nil {
		return result, err
	}
	current := filepath.Join(r.stateDir(), sshInboundsCurrent)
	backup := filepath.Join(r.stateDir(), sshInboundsLastGood)
	var previousPlan []byte
	if b, err := os.ReadFile(current); err == nil { // #nosec G304 -- current is a fixed filename under the locally configured Agent state directory.
		previousPlan = b
		if err := atomicWriteFile(backup, b, 0o600); err != nil {
			return result, err
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return result, err
	} else if err := os.Remove(backup); err != nil && !errors.Is(err, os.ErrNotExist) {
		return result, err
	}

	manager, err := r.newSSHInboundManager(plan)
	if err != nil {
		return result, err
	}
	old := r.swapSSHInboundManager(manager)
	if old != nil {
		old.close()
	}
	if err := manager.start(); err != nil {
		manager.close()
		// The current manager is intentionally empty at this point. Restore the
		// last known plan so a failed update never leaves an old inbound exposed.
		if rollbackErr := r.restoreLastGoodSSHInboundsLocked(); rollbackErr != nil {
			result.Warnings = append(result.Warnings, fmt.Sprintf("restore last-good SSH inbounds: %v", rollbackErr))
		}
		return result, err
	}

	b, err := json.MarshalIndent(plan, "", "  ")
	if err != nil {
		manager.close()
		_ = r.restoreLastGoodSSHInboundsLocked()
		return result, err
	}
	if err := atomicWriteFile(current, b, 0o600); err != nil {
		manager.close()
		if rollbackErr := r.restoreLastGoodSSHInboundsLocked(); rollbackErr != nil {
			result.Warnings = append(result.Warnings, fmt.Sprintf("restore last-good SSH inbounds: %v", rollbackErr))
		}
		return result, err
	}
	r.sshInboundDesiredState = desiredState
	if err := r.reconcileSSHAndCoreTrafficPolicies(context.Background(), plan); err != nil {
		rollbackErr := restoreSSHInboundPlanFile(current, previousPlan)
		if managerErr := r.restoreSSHInboundPlanLocked(previousPlan); managerErr != nil {
			if rollbackErr == nil {
				rollbackErr = managerErr
			} else {
				rollbackErr = fmt.Errorf("restore plan file: %v; restore runtime: %w", rollbackErr, managerErr)
			}
		}
		if rollbackErr != nil {
			return result, fmt.Errorf("reconcile shared core/SSH quota lease: %w; rollback SSH inbounds: %v", err, rollbackErr)
		}
		return result, fmt.Errorf("reconcile shared core/SSH quota lease: %w", err)
	}
	for _, inbound := range plan.Inbounds {
		if !inbound.Enabled {
			continue
		}
		result.Applied++
		result.Listeners++
		for _, user := range inbound.Users {
			if user.Enabled {
				result.Users++
			}
		}
	}
	return result, nil
}

func (r *Runner) restoreManagedSSHInboundsOnStartup() error {
	r.sshInboundLifecycleMu.Lock()
	defer r.sshInboundLifecycleMu.Unlock()
	b, err := os.ReadFile(filepath.Join(r.stateDir(), sshInboundsCurrent))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	var plan model.SSHInboundPlan
	if err := json.Unmarshal(b, &plan); err != nil {
		return err
	}
	if err := validateSSHInboundPlan(plan); err != nil {
		return fmt.Errorf("validate persisted SSH inbounds: %w", err)
	}
	if err := r.validateSSHInboundServerIDs(plan); err != nil {
		return err
	}
	manager, err := r.newSSHInboundManager(plan)
	if err != nil {
		return err
	}
	old := r.swapSSHInboundManager(manager)
	if old != nil {
		old.close()
	}
	if err := manager.start(); err != nil {
		manager.close()
		return err
	}
	desiredState, err := sshInboundDesiredStateID(plan)
	if err != nil {
		manager.close()
		return err
	}
	r.sshInboundDesiredState = desiredState
	if err := r.reconcileSSHAndCoreTrafficPolicies(context.Background(), plan); err != nil {
		old := r.swapSSHInboundManager(nil)
		if old != nil {
			old.close()
		}
		r.sshInboundDesiredState = ""
		return err
	}
	return nil
}

func (r *Runner) validateSSHInboundServerIDs(plan model.SSHInboundPlan) error {
	serverID := r.Config().ServerID
	if serverID == 0 {
		return nil
	}
	for _, inbound := range plan.Inbounds {
		if inbound.ServerID != serverID {
			return fmt.Errorf("SSH inbound %d belongs to server %d, enrolled server is %d", inbound.InboundID, inbound.ServerID, serverID)
		}
	}
	return nil
}

func (r *Runner) restoreLastGoodSSHInboundsLocked() error {
	path := filepath.Join(r.stateDir(), sshInboundsLastGood)
	b, err := os.ReadFile(path) // #nosec G304 -- path is a fixed filename under the locally configured Agent state directory.
	if errors.Is(err, os.ErrNotExist) {
		return r.restoreSSHInboundPlanLocked(nil)
	}
	if err != nil {
		return err
	}
	return r.restoreSSHInboundPlanLocked(b)
}

func (r *Runner) restoreSSHInboundPlanLocked(b []byte) error {
	if len(b) == 0 {
		old := r.swapSSHInboundManager(nil)
		if old != nil {
			old.close()
		}
		r.sshInboundDesiredState = ""
		return nil
	}
	var plan model.SSHInboundPlan
	if err := json.Unmarshal(b, &plan); err != nil {
		return err
	}
	if err := validateSSHInboundPlan(plan); err != nil {
		return err
	}
	if err := r.validateSSHInboundServerIDs(plan); err != nil {
		return err
	}
	manager, err := r.newSSHInboundManager(plan)
	if err != nil {
		return err
	}
	old := r.swapSSHInboundManager(manager)
	if old != nil {
		old.close()
	}
	if err := manager.start(); err != nil {
		manager.close()
		return err
	}
	desiredState, err := sshInboundDesiredStateID(plan)
	if err != nil {
		manager.close()
		return err
	}
	r.sshInboundDesiredState = desiredState
	return nil
}

func restoreSSHInboundPlanFile(path string, plan []byte) error {
	if len(plan) > 0 {
		return atomicWriteFile(path, plan, 0o600)
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

func (r *Runner) swapSSHInboundManager(next *sshInboundManager) *sshInboundManager {
	r.mu.Lock()
	old := r.sshInboundManager
	r.sshInboundManager = next
	r.mu.Unlock()
	return old
}

func (r *Runner) reconcileSSHAndCoreTrafficPolicies(ctx context.Context, plan model.SSHInboundPlan) error {
	policies := collectSSHInboundTrafficPolicies(plan)
	explicitUsers := runtimePolicyUsers(policies)
	corePolicies, err := r.currentCoreTrafficPolicies()
	if err != nil {
		return err
	}
	for key, policy := range corePolicies {
		if explicitUsers[policy.UserID] {
			continue
		}
		policies["core:"+key] = policy
	}
	if len(policies) == 0 {
		return nil
	}
	return r.pushTrafficPolicies(ctx, policies, r.trafficAcknowledgements())
}

func collectSSHInboundTrafficPolicies(plan model.SSHInboundPlan) map[string]interface{} {
	policies := map[string]interface{}{}
	for _, inbound := range plan.Inbounds {
		for key, policy := range inbound.Policies {
			policies[fmt.Sprintf("ssh-inbound:%d:%s", inbound.InboundID, key)] = policy
		}
	}
	return policies
}

func runtimePolicyUsers(policies map[string]interface{}) map[int64]bool {
	users := map[int64]bool{}
	for _, raw := range policies {
		encoded, err := json.Marshal(raw)
		if err != nil {
			continue
		}
		var policy model.TrafficRuntimePolicy
		if json.Unmarshal(encoded, &policy) == nil && policy.UserID > 0 {
			users[policy.UserID] = true
		}
	}
	return users
}

func (r *Runner) newSSHInboundManager(plan model.SSHInboundPlan) (*sshInboundManager, error) {
	plan, err := r.partitionSSHInboundPlanPolicies(plan)
	if err != nil {
		return nil, err
	}
	signer, err := r.loadSSHInboundHostSigner()
	if err != nil {
		return nil, err
	}
	manager := &sshInboundManager{listeners: make(map[int64]*managedSSHInbound), signer: signer, usage: map[int64]*sshInboundUserUsage{}}
	for _, planInbound := range plan.Inbounds {
		if !planInbound.Enabled {
			continue
		}
		inbound, err := newManagedSSHInbound(planInbound, manager.usage, r.connectionAudit)
		if err != nil {
			return nil, err
		}
		manager.listeners[planInbound.InboundID] = inbound
	}
	return manager, nil
}

func (r *Runner) partitionSSHInboundPlanPolicies(plan model.SSHInboundPlan) (model.SSHInboundPlan, error) {
	coreUsers, err := r.currentCoreTrafficPolicyUsers()
	if err != nil {
		return model.SSHInboundPlan{}, err
	}
	plan.Inbounds = append([]model.SSHInbound(nil), plan.Inbounds...)
	for index := range plan.Inbounds {
		policies := make(map[string]model.TrafficRuntimePolicy, len(plan.Inbounds[index].Policies))
		for key, policy := range plan.Inbounds[index].Policies {
			if coreUsers[policy.UserID] && policy.LeaseEnforced {
				policy.LeaseBytes /= 2
				policy.ResetLeaseBytes /= 2
			}
			policies[key] = policy
		}
		plan.Inbounds[index].Policies = policies
	}
	return plan, nil
}

func (r *Runner) loadSSHInboundHostSigner() (ssh.Signer, error) {
	path := filepath.Join(r.stateDir(), sshInboundHostKey)
	if b, err := os.ReadFile(path); err == nil { // #nosec G304 -- path is the fixed managed SSH host key under Agent state.
		return ssh.ParsePrivateKey(b)
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	pemBlock, err := ssh.MarshalPrivateKey(privateKey, "")
	if err != nil {
		return nil, err
	}
	pemBytes := pem.EncodeToMemory(pemBlock)
	if err := atomicWriteFile(path, pemBytes, 0o600); err != nil {
		return nil, err
	}
	return ssh.ParsePrivateKey(pemBytes)
}

func validateSSHInboundPlan(plan model.SSHInboundPlan) error {
	seenIDs := map[int64]struct{}{}
	seenEndpoints := map[string]struct{}{}
	for _, inbound := range plan.Inbounds {
		if inbound.InboundID <= 0 {
			return errors.New("SSH inbound requires a valid inbound_id")
		}
		if _, exists := seenIDs[inbound.InboundID]; exists {
			return fmt.Errorf("SSH inbound_id %d is duplicated", inbound.InboundID)
		}
		seenIDs[inbound.InboundID] = struct{}{}
		if inbound.ServerID <= 0 {
			return fmt.Errorf("SSH inbound %d requires a valid server_id", inbound.InboundID)
		}
		if !inbound.Enabled {
			continue
		}
		if inbound.Port < 1 || inbound.Port > 65535 {
			return fmt.Errorf("SSH inbound %d has invalid port", inbound.InboundID)
		}
		listenIP := strings.TrimSpace(inbound.ListenIP)
		if listenIP == "" {
			listenIP = "0.0.0.0"
		}
		if net.ParseIP(listenIP) == nil {
			return fmt.Errorf("SSH inbound %d has invalid listen_ip", inbound.InboundID)
		}
		endpoint := net.JoinHostPort(listenIP, strconv.Itoa(inbound.Port))
		if _, exists := seenEndpoints[endpoint]; exists {
			return fmt.Errorf("SSH inbound listener %s is duplicated", endpoint)
		}
		seenEndpoints[endpoint] = struct{}{}
		seenUsers := map[string]struct{}{}
		for _, user := range inbound.Users {
			if !user.Enabled {
				continue
			}
			if user.UserID <= 0 || !validSSHInboundUsername(user.Username) {
				return fmt.Errorf("SSH inbound %d has an invalid user", inbound.InboundID)
			}
			if _, exists := seenUsers[user.Username]; exists {
				return fmt.Errorf("SSH inbound %d repeats username %q", inbound.InboundID, user.Username)
			}
			seenUsers[user.Username] = struct{}{}
			if strings.TrimSpace(user.Password) == "" {
				return fmt.Errorf("SSH inbound user %q has no password", user.Username)
			}
		}
	}
	return nil
}

func validSSHInboundUsername(value string) bool {
	if len(value) == 0 || len(value) > 64 {
		return false
	}
	for _, char := range value {
		if (char >= 'a' && char <= 'z') || (char >= 'A' && char <= 'Z') || (char >= '0' && char <= '9') || char == '-' || char == '_' || char == '.' {
			continue
		}
		return false
	}
	return true
}

func newManagedSSHInbound(plan model.SSHInbound, usageByUser map[int64]*sshInboundUserUsage, audit *connectionAuditAccumulator) (*managedSSHInbound, error) {
	inbound := &managedSSHInbound{plan: plan, auth: map[string]sshInboundCredential{}, counters: map[int64]*sshInboundCounter{}, audit: audit, conns: map[net.Conn]int64{}}
	for _, user := range plan.Users {
		if !user.Enabled {
			continue
		}
		inbound.auth[user.Username] = sshInboundCredential{userID: user.UserID, password: user.Password}
		usage := usageByUser[user.UserID]
		if usage == nil {
			usage = &sshInboundUserUsage{periods: map[string]*sshInboundUsagePeriod{}}
			usageByUser[user.UserID] = usage
		}
		counter := &sshInboundCounter{usage: usage}
		if policy, ok := sshInboundPolicyForUser(plan.Policies, user.UserID); ok {
			counter.setPolicy(policy)
		}
		inbound.counters[user.UserID] = counter
	}
	return inbound, nil
}

func sshInboundPolicyForUser(policies map[string]model.TrafficRuntimePolicy, userID int64) (model.TrafficRuntimePolicy, bool) {
	for key, policy := range policies {
		if policy.UserID == userID || key == fmt.Sprintf("user:%d", userID) || key == strconv.FormatInt(userID, 10) {
			policy.UserID = userID
			return policy, true
		}
	}
	return model.TrafficRuntimePolicy{}, false
}

func (m *sshInboundManager) start() error {
	for _, inbound := range m.listeners {
		listenIP := strings.TrimSpace(inbound.plan.ListenIP)
		if listenIP == "" {
			listenIP = "0.0.0.0"
		}
		listener, err := net.Listen("tcp", net.JoinHostPort(listenIP, strconv.Itoa(inbound.plan.Port)))
		if err != nil {
			m.close()
			return fmt.Errorf("listen SSH inbound %q: %w", inbound.plan.Name, err)
		}
		inbound.listener = listener
		go inbound.serve(listener, m.signer)
	}
	return nil
}

func (m *sshInboundManager) close() {
	if m == nil {
		return
	}
	m.mu.Lock()
	inbounds := make([]*managedSSHInbound, 0, len(m.listeners))
	for _, inbound := range m.listeners {
		inbounds = append(inbounds, inbound)
	}
	m.mu.Unlock()
	for _, inbound := range inbounds {
		inbound.close()
	}
}

func (m *managedSSHInbound) close() {
	m.mu.Lock()
	listener := m.listener
	m.listener = nil
	connections := make([]net.Conn, 0, len(m.conns))
	for conn := range m.conns {
		connections = append(connections, conn)
	}
	m.mu.Unlock()
	if listener != nil {
		_ = listener.Close()
	}
	for _, conn := range connections {
		_ = conn.Close()
	}
}

func (m *managedSSHInbound) serve(listener net.Listener, signer ssh.Signer) {
	for {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		m.mu.Lock()
		m.conns[conn] = 0
		m.mu.Unlock()
		go func(raw net.Conn) {
			defer func() {
				m.mu.Lock()
				delete(m.conns, raw)
				m.mu.Unlock()
				_ = raw.Close()
			}()
			m.handle(raw, signer)
		}(conn)
	}
}

func (m *managedSSHInbound) handle(raw net.Conn, signer ssh.Signer) {
	serverConfig := &ssh.ServerConfig{ServerVersion: "SSH-2.0-OBoard-RestrictedSSH"}
	serverConfig.PasswordCallback = func(metadata ssh.ConnMetadata, password []byte) (*ssh.Permissions, error) {
		credential, ok := m.auth[metadata.User()]
		if !ok || subtle.ConstantTimeCompare([]byte(credential.password), password) != 1 {
			return nil, errors.New("password is not authorized")
		}
		counter := m.counterFor(credential.userID)
		if counter == nil || !counter.allowNewConnection() {
			return nil, errors.New("user traffic quota is exhausted")
		}
		return &ssh.Permissions{Extensions: map[string]string{"oboard_user_id": strconv.FormatInt(credential.userID, 10), "oboard_inbound_id": strconv.FormatInt(m.plan.InboundID, 10)}}, nil
	}
	serverConfig.AddHostKey(signer)
	connection, channels, requests, err := ssh.NewServerConn(raw, serverConfig)
	if err != nil {
		return
	}
	defer connection.Close()
	if connection.Permissions != nil {
		if userID, parseErr := strconv.ParseInt(connection.Permissions.Extensions["oboard_user_id"], 10, 64); parseErr == nil && userID > 0 {
			m.mu.Lock()
			if _, ok := m.conns[raw]; ok {
				m.conns[raw] = userID
			}
			m.mu.Unlock()
		}
	}
	go ssh.DiscardRequests(requests)
	for newChannel := range channels {
		if newChannel.ChannelType() != "direct-tcpip" {
			_ = newChannel.Reject(ssh.UnknownChannelType, "only direct-tcpip forwarding is permitted")
			continue
		}
		m.handleDirectTCPIP(connection, newChannel)
	}
}

func (m *managedSSHInbound) handleDirectTCPIP(connection *ssh.ServerConn, newChannel ssh.NewChannel) {
	if connection.Permissions == nil {
		_ = newChannel.Reject(ssh.Prohibited, "missing authenticated OBoard user")
		return
	}
	userID, err := strconv.ParseInt(connection.Permissions.Extensions["oboard_user_id"], 10, 64)
	if err != nil || userID <= 0 {
		_ = newChannel.Reject(ssh.Prohibited, "invalid authenticated OBoard user")
		return
	}
	counter := m.counterFor(userID)
	if counter == nil || !counter.allowNewConnection() {
		_ = newChannel.Reject(ssh.Prohibited, "user traffic quota is exhausted")
		return
	}
	var payload directTCPIPPayload
	if err := ssh.Unmarshal(newChannel.ExtraData(), &payload); err != nil {
		_ = newChannel.Reject(ssh.ConnectionFailed, "invalid direct-tcpip request")
		return
	}
	if isBadVPNUDPGatewayDestination(payload.DestAddr, payload.DestPort) {
		channel, requests, err := newChannel.Accept()
		if err != nil {
			return
		}
		go ssh.DiscardRequests(requests)
		go serveBadVPNUDPGateway(channel, counter, m.audit, userID, m.plan.InboundID, sourceIPFromNetAddr(connection.RemoteAddr()))
		return
	}
	addresses, err := resolvePermittedSSHDestination(context.Background(), payload.DestAddr, payload.DestPort)
	if err != nil {
		_ = newChannel.Reject(ssh.Prohibited, err.Error())
		return
	}
	target, err := dialPermittedSSHAddresses(context.Background(), addresses, payload.DestPort)
	if err != nil {
		_ = newChannel.Reject(ssh.ConnectionFailed, "destination connection failed")
		return
	}
	channel, requests, err := newChannel.Accept()
	if err != nil {
		_ = target.Close()
		return
	}
	go ssh.DiscardRequests(requests)
	finishAudit := m.audit.start(connectionAuditSnapshotItem{
		UserID:          userID,
		InboundID:       m.plan.InboundID,
		SourceIP:        sourceIPFromNetAddr(connection.RemoteAddr()),
		Network:         "tcp",
		Destination:     strings.ToLower(strings.TrimSpace(payload.DestAddr)),
		DestinationPort: int(payload.DestPort),
		OutboundTag:     "direct",
		OutboundType:    "direct",
	})
	go func() {
		defer finishAudit()
		proxySSHDirectTCPIP(channel, target, counter)
	}()
}

func (m *managedSSHInbound) counterFor(userID int64) *sshInboundCounter {
	return m.counters[userID]
}

func resolvePermittedSSHDestination(ctx context.Context, host string, port uint32) ([]netip.Addr, error) {
	host = strings.TrimSpace(host)
	if host == "" || port == 0 || port > 65535 {
		return nil, errors.New("invalid destination")
	}
	if parsed, err := netip.ParseAddr(host); err == nil {
		parsed = parsed.Unmap()
		if !isPermittedSSHDestination(parsed) {
			return nil, errors.New("destination is not allowed")
		}
		return []netip.Addr{parsed}, nil
	}
	if !validSSHInboundHostname(host) {
		return nil, errors.New("invalid destination hostname")
	}
	resolved, err := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
	if err != nil || len(resolved) == 0 {
		return nil, errors.New("destination hostname could not be resolved")
	}
	addresses := make([]netip.Addr, 0, len(resolved))
	for _, address := range resolved {
		address = address.Unmap()
		if !isPermittedSSHDestination(address) {
			return nil, errors.New("destination is not allowed")
		}
		addresses = append(addresses, address)
	}
	return addresses, nil
}

func validSSHInboundHostname(host string) bool {
	if len(host) > 253 || strings.HasSuffix(host, ".") {
		return false
	}
	for _, label := range strings.Split(host, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, char := range label {
			if (char >= 'a' && char <= 'z') || (char >= 'A' && char <= 'Z') || (char >= '0' && char <= '9') || char == '-' {
				continue
			}
			return false
		}
	}
	return true
}

func isPermittedSSHDestination(address netip.Addr) bool {
	address = address.Unmap()
	return address.IsValid() && address.IsGlobalUnicast() && !address.IsPrivate() && !address.IsLoopback() && !address.IsLinkLocalUnicast() && !address.IsLinkLocalMulticast() && !address.IsMulticast() && !address.IsUnspecified()
}

func dialPermittedSSHAddresses(ctx context.Context, addresses []netip.Addr, port uint32) (net.Conn, error) {
	dialer := net.Dialer{Timeout: 10 * time.Second}
	var lastErr error
	for _, address := range addresses {
		conn, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(address.String(), strconv.FormatUint(uint64(port), 10)))
		if err == nil {
			return conn, nil
		}
		lastErr = err
	}
	if lastErr == nil {
		lastErr = errors.New("no permitted destination addresses")
	}
	return nil, lastErr
}

func proxySSHDirectTCPIP(channel ssh.Channel, target net.Conn, counter *sshInboundCounter) {
	defer channel.Close()
	defer target.Close()
	done := make(chan struct{}, 2)
	go func() {
		copySSHInboundTraffic(target, channel, counter, true)
		_ = target.Close()
		done <- struct{}{}
	}()
	go func() {
		copySSHInboundTraffic(channel, target, counter, false)
		_ = channel.Close()
		done <- struct{}{}
	}()
	<-done
	<-done
}

func copySSHInboundTraffic(dst io.Writer, src io.Reader, counter *sshInboundCounter, upload bool) {
	buffer := make([]byte, sshInboundIOChunk)
	for {
		if !counter.allowTransfer() {
			return
		}
		n, readErr := src.Read(buffer)
		if n > 0 {
			written, writeErr := dst.Write(buffer[:n])
			counter.addTraffic(upload, int64(written))
			if writeErr != nil || written != n {
				return
			}
		}
		if readErr != nil {
			return
		}
	}
}

func (c *sshInboundCounter) setPolicy(policy model.TrafficRuntimePolicy) {
	c.mu.Lock()
	previous := c.policy
	if previous.PeriodKey != "" && policy.PeriodKey != "" && previous.PeriodKey != policy.PeriodKey {
		c.upload.Store(0)
		c.download.Store(0)
		c.acknowledgedUpload.Store(0)
		c.acknowledgedDownload.Store(0)
	}
	c.policy = policy
	c.mu.Unlock()
}

func (c *sshInboundCounter) currentPolicy() model.TrafficRuntimePolicy {
	c.mu.RLock()
	policy := c.policy
	c.mu.RUnlock()
	if !trafficPolicyExpired(policy, time.Now()) {
		return policy
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	policy = c.policy
	if !trafficPolicyExpired(policy, time.Now()) {
		return policy
	}
	loc := time.FixedZone("Asia/Shanghai", 8*60*60)
	if policy.Timezone != "" {
		if loaded, err := time.LoadLocation(policy.Timezone); err == nil {
			loc = loaded
		}
	}
	periodKey, start, end := agentTrafficWindow(time.Now(), policy.ResetMode, policy.ResetDay, loc)
	if policy.PeriodKey != periodKey {
		c.upload.Store(0)
		c.download.Store(0)
		c.acknowledgedUpload.Store(0)
		c.acknowledgedDownload.Store(0)
	}
	policy.PeriodKey = periodKey
	policy.PeriodStart = start.UTC().Format(time.RFC3339Nano)
	policy.PeriodEnd = end.UTC().Format(time.RFC3339Nano)
	policy.UsedBaselineBytes = 0
	if policy.LeaseEnforced {
		policy.LeaseBytes = policy.ResetLeaseBytes
	}
	policy.QuotaState = "active"
	c.policy = policy
	return policy
}

func trafficPolicyExpired(policy model.TrafficRuntimePolicy, now time.Time) bool {
	if policy.PeriodEnd == "" {
		return false
	}
	end, err := time.Parse(time.RFC3339Nano, policy.PeriodEnd)
	return err == nil && !now.Before(end)
}

func agentTrafficWindow(now time.Time, mode string, day int, loc *time.Location) (string, time.Time, time.Time) {
	if loc == nil {
		loc = time.FixedZone("Asia/Shanghai", 8*60*60)
	}
	now = now.In(loc)
	if day < 1 {
		day = 1
	}
	if day > 31 {
		day = 31
	}
	if mode != "month_day" {
		start := time.Date(now.Year(), now.Month(), 1, 0, 0, 0, 0, loc)
		return start.Format("2006-01-02"), start, start.AddDate(0, 1, 0)
	}
	start := time.Date(now.Year(), now.Month(), agentClampedMonthDay(now.Year(), now.Month(), day), 0, 0, 0, 0, loc)
	if now.Before(start) {
		previous := start.AddDate(0, -1, 0)
		start = time.Date(previous.Year(), previous.Month(), agentClampedMonthDay(previous.Year(), previous.Month(), day), 0, 0, 0, 0, loc)
	}
	next := start.AddDate(0, 1, 0)
	end := time.Date(next.Year(), next.Month(), agentClampedMonthDay(next.Year(), next.Month(), day), 0, 0, 0, 0, loc)
	return start.Format("2006-01-02"), start, end
}

func agentClampedMonthDay(year int, month time.Month, day int) int {
	last := time.Date(year, month+1, 0, 0, 0, 0, 0, time.UTC).Day()
	if day > last {
		return last
	}
	if day < 1 {
		return 1
	}
	return day
}

func (c *sshInboundCounter) allowNewConnection() bool { return !c.quotaExceeded() }
func (c *sshInboundCounter) allowTransfer() bool {
	if c.currentPolicy().EnforcementMode == "reject_new" {
		return true
	}
	return !c.quotaExceeded()
}

func (c *sshInboundCounter) quotaExceeded() bool {
	policy := c.currentPolicy()
	if policy.QuotaState == "quota_exceeded" {
		return true
	}
	if policy.TrafficLimitBytes <= 0 {
		return false
	}
	capBytes := policy.TrafficLimitBytes
	if policy.LeaseEnforced && policy.UsedBaselineBytes+policy.LeaseBytes < capBytes {
		capBytes = policy.UsedBaselineBytes + policy.LeaseBytes
	}
	return policy.UsedBaselineBytes+c.unacknowledged(policy.PeriodKey) >= capBytes
}

func (c *sshInboundCounter) addTraffic(upload bool, bytes int64) {
	if bytes <= 0 {
		return
	}
	policy := c.currentPolicy()
	if upload {
		c.upload.Add(bytes)
	} else {
		c.download.Add(bytes)
	}
	if c.usage != nil {
		period := c.usage.period(policy.PeriodKey)
		if upload {
			period.upload.Add(bytes)
		} else {
			period.download.Add(bytes)
		}
	}
}

func (c *sshInboundCounter) acknowledge(checkpoint trafficCounterCheckpoint) {
	if c == nil || checkpoint.PeriodKey == "" {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.policy.PeriodKey != checkpoint.PeriodKey {
		return
	}
	upload := minInt64(checkpoint.Upload, c.upload.Load())
	download := minInt64(checkpoint.Download, c.download.Load())
	if upload < 0 {
		upload = 0
	}
	if download < 0 {
		download = 0
	}
	previousUpload := c.acknowledgedUpload.Load()
	previousDownload := c.acknowledgedDownload.Load()
	if upload < previousUpload {
		upload = previousUpload
	}
	if download < previousDownload {
		download = previousDownload
	}
	c.acknowledgedUpload.Store(upload)
	c.acknowledgedDownload.Store(download)
	if c.usage != nil {
		period := c.usage.period(checkpoint.PeriodKey)
		period.acknowledgedUpload.Add(upload - previousUpload)
		period.acknowledgedDownload.Add(download - previousDownload)
	}
}

func (c *sshInboundCounter) unacknowledged(periodKey string) int64 {
	if c.usage != nil {
		return c.usage.period(periodKey).unacknowledged()
	}
	return positiveDifference(c.upload.Load(), c.acknowledgedUpload.Load()) + positiveDifference(c.download.Load(), c.acknowledgedDownload.Load())
}

func (u *sshInboundUserUsage) period(periodKey string) *sshInboundUsagePeriod {
	u.mu.Lock()
	defer u.mu.Unlock()
	if u.periods == nil {
		u.periods = map[string]*sshInboundUsagePeriod{}
	}
	period := u.periods[periodKey]
	if period == nil {
		period = &sshInboundUsagePeriod{}
		u.periods[periodKey] = period
	}
	return period
}

func (p *sshInboundUsagePeriod) unacknowledged() int64 {
	return positiveDifference(p.upload.Load(), p.acknowledgedUpload.Load()) + positiveDifference(p.download.Load(), p.acknowledgedDownload.Load())
}

func positiveDifference(total, acknowledged int64) int64 {
	if total <= acknowledged {
		return 0
	}
	return total - acknowledged
}

func minInt64(left, right int64) int64 {
	if left < right {
		return left
	}
	return right
}

func (m *sshInboundManager) snapshot() []trafficSnapshotItem {
	if m == nil {
		return nil
	}
	m.mu.RLock()
	inbounds := make([]*managedSSHInbound, 0, len(m.listeners))
	for _, inbound := range m.listeners {
		inbounds = append(inbounds, inbound)
	}
	m.mu.RUnlock()
	items := make([]trafficSnapshotItem, 0)
	for _, inbound := range inbounds {
		for userID, counter := range inbound.counters {
			policy := counter.currentPolicy()
			upload, download := counter.upload.Load(), counter.download.Load()
			if upload == 0 && download == 0 {
				continue
			}
			periodKey := policy.PeriodKey
			items = append(items, trafficSnapshotItem{Key: fmt.Sprintf("ssh-inbound:%d:user:%d", inbound.plan.InboundID, userID), UserID: userID, InboundID: inbound.plan.InboundID, PeriodKey: periodKey, Upload: upload, Download: download})
		}
	}
	return items
}

func (m *sshInboundManager) updatePolicies(policies map[string]interface{}, acknowledged map[string]trafficCounterCheckpoint) {
	if m == nil || (len(policies) == 0 && len(acknowledged) == 0) {
		return
	}
	parsed := make([]model.TrafficRuntimePolicy, 0, len(policies))
	for _, raw := range policies {
		encoded, err := json.Marshal(raw)
		if err != nil {
			continue
		}
		var policy model.TrafficRuntimePolicy
		if json.Unmarshal(encoded, &policy) == nil && policy.UserID > 0 {
			parsed = append(parsed, policy)
		}
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	for _, inbound := range m.listeners {
		for userID, counter := range inbound.counters {
			key := fmt.Sprintf("ssh-inbound:%d:user:%d", inbound.plan.InboundID, userID)
			if checkpoint, ok := acknowledged[key]; ok {
				counter.acknowledge(checkpoint)
			}
		}
		for _, policy := range parsed {
			if policy.InboundID != 0 && policy.InboundID != inbound.plan.InboundID {
				continue
			}
			if counter := inbound.counterFor(policy.UserID); counter != nil {
				counter.setPolicy(policy)
				if policy.EnforcementMode != "reject_new" && counter.quotaExceeded() {
					inbound.closeUserConnections(policy.UserID)
				}
			}
		}
	}
}

func (m *sshInboundManager) trafficPolicyUsers() map[int64]bool {
	out := map[int64]bool{}
	if m == nil {
		return out
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	for _, inbound := range m.listeners {
		for userID := range inbound.counters {
			out[userID] = true
		}
	}
	return out
}

func (m *managedSSHInbound) closeUserConnections(userID int64) {
	m.mu.Lock()
	connections := make([]net.Conn, 0)
	for connection, connectedUserID := range m.conns {
		if connectedUserID == userID {
			connections = append(connections, connection)
		}
	}
	m.mu.Unlock()
	for _, connection := range connections {
		_ = connection.Close()
	}
}
