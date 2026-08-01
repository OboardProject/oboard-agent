package agent

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/OboardProject/oboard-agent/internal/core"
	"github.com/OboardProject/oboard-agent/internal/model"
)

const (
	portForwardsCurrent  = "port-forwards.json"
	portForwardsLastGood = "port-forwards.last-good.json"
	realmConfigFile      = "realm.toml"
	realmPIDFile         = "realm.pid"
	realmLogFile         = "realm.log"
	nftConfigFile        = "nftables-oboard.nft"
	nftTableName         = "oboard_forward"
)

type forwardApplyResult struct {
	Version      int64             `json:"version"`
	Unchanged    bool              `json:"unchanged,omitempty"`
	Applied      int               `json:"applied"`
	RealmRules   int               `json:"realm_rules"`
	NFTRules     int               `json:"nft_rules"`
	BuiltinRules int               `json:"builtin_rules"`
	TrustedRules int               `json:"trusted_rules"`
	Capabilities map[string]bool   `json:"capabilities"`
	Warnings     []string          `json:"warnings,omitempty"`
	Backends     map[string]string `json:"backends,omitempty"`
}

type forwardRule struct {
	model.PortForward
	ResolvedBackend model.ForwardBackend `json:"resolved_backend"`
}

type forwardHandoff struct {
	currentPath      string
	retainedPlan     model.PortForwardPlan
	originalResolved []forwardRule
	conflicts        []model.PortForward
}

type inboundListenEndpoint struct {
	Address string
	Port    int
	TCP     bool
	UDP     bool
}

func (r *Runner) applyPortForwards(plan model.PortForwardPlan) (forwardApplyResult, error) {
	r.forwardLifecycleMu.Lock()
	defer r.forwardLifecycleMu.Unlock()
	result := forwardApplyResult{Version: plan.Version, Capabilities: detectForwardCapabilities(), Backends: map[string]string{}}
	desiredState, err := portForwardDesiredStateID(plan)
	if err != nil {
		return result, err
	}
	if desiredState != "" && desiredState == r.forwardDesiredState {
		result.Unchanged = true
		return result, nil
	}

	stateDir := r.stateDir()
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		return forwardApplyResult{}, err
	}

	resolved, err := resolveForwardBackends(plan.Rules, result.Capabilities)
	if err != nil {
		return result, err
	}
	for _, rule := range resolved {
		result.Backends[fmt.Sprint(rule.ID)] = string(rule.ResolvedBackend)
	}

	current := filepath.Join(stateDir, portForwardsCurrent)
	backup := filepath.Join(stateDir, portForwardsLastGood)
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

	if err := r.applyResolvedForwards(resolved, &result); err != nil {
		if rollbackErr := r.restoreLastGoodForwards(backup); rollbackErr != nil {
			result.Warnings = append(result.Warnings, fmt.Sprintf("restore last-good forwards: %v", rollbackErr))
		}
		return result, err
	}
	if err := atomicWriteFile(current, data, 0o600); err != nil {
		if rollbackErr := r.restoreLastGoodForwards(backup); rollbackErr != nil {
			result.Warnings = append(result.Warnings, fmt.Sprintf("restore last-good forwards: %v", rollbackErr))
		}
		return result, err
	}
	r.forwardDesiredState = desiredState
	return result, nil
}

func (r *Runner) restoreManagedPortForwardsOnStartup() error {
	b, err := os.ReadFile(filepath.Join(r.stateDir(), portForwardsCurrent))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	var plan model.PortForwardPlan
	if err := json.Unmarshal(b, &plan); err != nil {
		return err
	}
	_, err = r.applyPortForwards(plan)
	return err
}

func (r *Runner) suspendConflictingForwards(candidateConfig []byte) (*forwardHandoff, error) {
	endpoints := inboundListenEndpoints(candidateConfig)
	if len(endpoints) == 0 {
		return nil, nil
	}
	currentPath := filepath.Join(r.stateDir(), portForwardsCurrent)
	// #nosec G304 -- currentPath is a fixed file below the Agent's configured state directory.
	b, err := os.ReadFile(currentPath)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read current port-forward plan before core handoff: %w", err)
	}
	var current model.PortForwardPlan
	if err := json.Unmarshal(b, &current); err != nil {
		return nil, fmt.Errorf("parse current port-forward plan before core handoff: %w", err)
	}
	originalResolved, err := resolveForwardBackends(current.Rules, detectForwardCapabilities())
	if err != nil {
		return nil, fmt.Errorf("resolve current port-forward plan before core handoff: %w", err)
	}
	retained := current
	retained.Rules = make([]model.PortForward, 0, len(current.Rules))
	conflicts := make([]model.PortForward, 0)
	for _, rule := range current.Rules {
		if forwardConflictsWithInbounds(rule, endpoints) {
			conflicts = append(conflicts, rule)
			continue
		}
		retained.Rules = append(retained.Rules, rule)
	}
	if len(conflicts) == 0 {
		return nil, nil
	}
	retainedResolved, err := resolveForwardBackends(retained.Rules, detectForwardCapabilities())
	if err != nil {
		return nil, fmt.Errorf("resolve retained port-forward plan before core handoff: %w", err)
	}
	handoff := &forwardHandoff{
		currentPath: currentPath, retainedPlan: retained,
		originalResolved: originalResolved, conflicts: conflicts,
	}
	if err := r.applyResolvedForwards(retainedResolved, &forwardApplyResult{}); err != nil {
		if restoreErr := r.applyResolvedForwards(originalResolved, &forwardApplyResult{}); restoreErr != nil {
			return nil, fmt.Errorf("suspend conflicting port forwards: %w; restore original forwards: %v", err, restoreErr)
		}
		return nil, fmt.Errorf("suspend conflicting port forwards: %w", err)
	}
	return handoff, nil
}

func (r *Runner) commitForwardHandoff(handoff *forwardHandoff) error {
	if handoff == nil {
		return nil
	}
	b, err := json.MarshalIndent(handoff.retainedPlan, "", "  ")
	if err != nil {
		return err
	}
	if err := atomicWriteFile(handoff.currentPath, b, 0o600); err != nil {
		return err
	}
	// The runtime now owns only the retained subset. Force the next deployment
	// to reconcile even when its original desired plan is otherwise unchanged.
	r.forwardDesiredState = ""
	return nil
}

func (r *Runner) rollbackForwardHandoff(handoff *forwardHandoff) error {
	if handoff == nil {
		return nil
	}
	return r.applyResolvedForwards(handoff.originalResolved, &forwardApplyResult{})
}

func (h *forwardHandoff) conflictIDs() []int64 {
	ids := make([]int64, 0, len(h.conflicts))
	for _, rule := range h.conflicts {
		ids = append(ids, rule.ID)
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
	return ids
}

func (h *forwardHandoff) conflictPorts() []int {
	seen := map[int]bool{}
	ports := make([]int, 0, len(h.conflicts))
	for _, rule := range h.conflicts {
		if seen[rule.ListenPort] {
			continue
		}
		seen[rule.ListenPort] = true
		ports = append(ports, rule.ListenPort)
	}
	sort.Ints(ports)
	return ports
}

func inboundListenEndpoints(raw []byte) []inboundListenEndpoint {
	if len(strings.TrimSpace(string(raw))) == 0 {
		return nil
	}
	var cfg struct {
		Inbounds []map[string]any `json:"inbounds"`
		OBoard   struct {
			TrustedForward struct {
				Receivers []struct {
					Listen     string `json:"listen"`
					ListenPort int    `json:"listen_port"`
					Network    string `json:"network"`
				} `json:"receivers"`
			} `json:"trusted_forward"`
		} `json:"_oboard"`
	}
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return nil
	}
	endpoints := make([]inboundListenEndpoint, 0, len(cfg.Inbounds))
	for _, inbound := range cfg.Inbounds {
		port := intFromJSONValue(inbound["listen_port"])
		if port <= 0 {
			continue
		}
		endpoint := inboundListenEndpoint{Address: normalizeForwardListenAddress(fmt.Sprint(inbound["listen"])), Port: port}
		typeName := strings.ToLower(strings.TrimSpace(fmt.Sprint(inbound["type"])))
		switch typeName {
		case "hysteria2", "hy2", "tuic":
			endpoint.UDP = true
		case "shadowsocks":
			network := strings.ToLower(strings.TrimSpace(fmt.Sprint(inbound["network"])))
			switch network {
			case "tcp":
				endpoint.TCP = true
			case "udp":
				endpoint.UDP = true
			default:
				endpoint.TCP = true
				endpoint.UDP = true
			}
		default:
			endpoint.TCP = true
		}
		endpoints = append(endpoints, endpoint)
	}
	for _, receiver := range cfg.OBoard.TrustedForward.Receivers {
		if receiver.ListenPort <= 0 {
			continue
		}
		endpoint := inboundListenEndpoint{Address: normalizeForwardListenAddress(receiver.Listen), Port: receiver.ListenPort}
		switch receiver.Network {
		case string(model.ForwardProtocolTCP):
			endpoint.TCP = true
		case string(model.ForwardProtocolUDP):
			endpoint.UDP = true
		default:
			endpoint.TCP = true
			endpoint.UDP = true
		}
		endpoints = append(endpoints, endpoint)
	}
	return endpoints
}

func intFromJSONValue(value any) int {
	switch typed := value.(type) {
	case float64:
		return int(typed)
	case int:
		return typed
	case json.Number:
		var value int
		_, _ = fmt.Sscanf(typed.String(), "%d", &value)
		return value
	case string:
		var value int
		_, _ = fmt.Sscanf(typed, "%d", &value)
		return value
	default:
		return 0
	}
}

func forwardConflictsWithInbounds(rule model.PortForward, endpoints []inboundListenEndpoint) bool {
	for _, endpoint := range endpoints {
		if endpoint.Port != rule.ListenPort || !forwardListenAddressesOverlap(endpoint.Address, rule.ListenIP) {
			continue
		}
		switch rule.Protocol {
		case model.ForwardProtocolTCP:
			if endpoint.TCP {
				return true
			}
		case model.ForwardProtocolUDP:
			if endpoint.UDP {
				return true
			}
		case model.ForwardProtocolTCPUDP:
			if endpoint.TCP || endpoint.UDP {
				return true
			}
		}
	}
	return false
}

func forwardListenAddressesOverlap(left, right string) bool {
	left = normalizeForwardListenAddress(left)
	right = normalizeForwardListenAddress(right)
	leftAddr, leftErr := netip.ParseAddr(left)
	rightAddr, rightErr := netip.ParseAddr(right)
	if leftErr != nil || rightErr != nil {
		return left == right
	}
	leftAddr = leftAddr.Unmap()
	rightAddr = rightAddr.Unmap()
	if leftAddr.IsUnspecified() && rightAddr.IsUnspecified() {
		return true
	}
	if leftAddr.IsUnspecified() {
		return leftAddr.Is6() || rightAddr.Is4()
	}
	if rightAddr.IsUnspecified() {
		return rightAddr.Is6() || leftAddr.Is4()
	}
	return leftAddr == rightAddr
}

func normalizeForwardListenAddress(address string) string {
	address = strings.TrimSpace(address)
	if address == "" || address == "<nil>" {
		return "0.0.0.0"
	}
	return address
}

func (r *Runner) restoreLastGoodForwards(path string) error {
	// #nosec G304 -- path is the fixed last-good file assembled below the Agent state directory.
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return r.applyResolvedForwards(nil, &forwardApplyResult{})
	}
	if err != nil {
		return err
	}
	var plan model.PortForwardPlan
	if err := json.Unmarshal(b, &plan); err != nil {
		return err
	}
	resolved, err := resolveForwardBackends(plan.Rules, detectForwardCapabilities())
	if err != nil {
		return err
	}
	return r.applyResolvedForwards(resolved, &forwardApplyResult{})
}

func (r *Runner) applyResolvedForwards(rules []forwardRule, result *forwardApplyResult) error {
	sort.SliceStable(rules, func(i, j int) bool {
		if rules[i].Priority == rules[j].Priority {
			return rules[i].ID < rules[j].ID
		}
		return rules[i].Priority < rules[j].Priority
	})
	realmRules := make([]forwardRule, 0)
	nftRules := make([]forwardRule, 0)
	builtinRules := make([]forwardRule, 0)
	for _, rule := range rules {
		if rule.TrustedForward != nil && result != nil {
			result.TrustedRules++
		}
		switch rule.ResolvedBackend {
		case model.ForwardBackendRealm:
			realmRules = append(realmRules, rule)
		case model.ForwardBackendNFT:
			nftRules = append(nftRules, rule)
		case model.ForwardBackendBuiltin:
			builtinRules = append(builtinRules, rule)
		}
	}
	if err := r.applyBuiltinForwards(builtinRules); err != nil {
		return err
	}
	if err := r.applyRealmForwards(realmRules); err != nil {
		return err
	}
	if err := r.applyNFTForwards(nftRules, result); err != nil {
		return err
	}
	if result != nil {
		result.Applied = len(rules)
		result.RealmRules = len(realmRules)
		result.NFTRules = len(nftRules)
		result.BuiltinRules = len(builtinRules)
	}
	r.setForwardProbeRules(rules)
	return nil
}

func resolveForwardBackends(rules []model.PortForward, caps map[string]bool) ([]forwardRule, error) {
	out := make([]forwardRule, 0, len(rules))
	for _, rule := range rules {
		backend := rule.Backend
		if rule.TrustedForward != nil {
			if _, err := trustedForwardKey(rule.TrustedForward); err != nil {
				return nil, fmt.Errorf("port forward %q: %w", rule.Name, err)
			}
			backend = model.ForwardBackendBuiltin
		}
		if backend == "" || backend == model.ForwardBackendAuto {
			switch {
			case caps["realm"]:
				backend = model.ForwardBackendRealm
			case caps["nft"]:
				backend = model.ForwardBackendNFT
			case caps["builtin"]:
				backend = model.ForwardBackendBuiltin
			default:
				return nil, fmt.Errorf("port forward %q has backend=auto but no supported backend was detected", rule.Name)
			}
		}
		switch backend {
		case model.ForwardBackendRealm:
			if !caps["realm"] {
				return nil, fmt.Errorf("port forward %q requires realm but realm binary was not found", rule.Name)
			}
		case model.ForwardBackendNFT:
			if !caps["nft"] {
				return nil, fmt.Errorf("port forward %q requires nft but Linux nftables/root capability is unavailable", rule.Name)
			}
		case model.ForwardBackendBuiltin:
			if rule.Protocol != model.ForwardProtocolTCP && rule.Protocol != model.ForwardProtocolUDP && rule.Protocol != model.ForwardProtocolTCPUDP {
				return nil, fmt.Errorf("builtin backend does not support protocol %q for rule %q", rule.Protocol, rule.Name)
			}
		default:
			return nil, fmt.Errorf("unsupported forward backend %q", backend)
		}
		out = append(out, forwardRule{PortForward: rule, ResolvedBackend: backend})
	}
	return out, nil
}

func detectForwardCapabilities() map[string]bool {
	_, realmErr := exec.LookPath("realm")
	_, nftErr := exec.LookPath("nft")
	root := runningAsRoot()
	return map[string]bool{
		"realm":              realmErr == nil,
		"nft":                runtime.GOOS == "linux" && nftErr == nil && root,
		"builtin":            true,
		"trusted_forward_v1": true,
		"linux":              runtime.GOOS == "linux",
		"root":               root,
	}
}

func (r *Runner) applyBuiltinForwards(rules []forwardRule) error {
	r.mu.Lock()
	old := r.builtinForwardStops
	r.builtinForwardStops = map[int64]func(){}
	r.mu.Unlock()
	for _, stop := range old {
		stop()
	}
	for _, rule := range rules {
		stop, err := r.startBuiltinForward(rule)
		if err != nil {
			return err
		}
		r.mu.Lock()
		r.builtinForwardStops[rule.ID] = stop
		r.mu.Unlock()
	}
	return nil
}

func (r *Runner) startBuiltinForward(rule forwardRule) (func(), error) {
	stops := make([]func(), 0, 2)
	if rule.Protocol == model.ForwardProtocolTCP || rule.Protocol == model.ForwardProtocolTCPUDP {
		stop, err := r.startBuiltinTCPForward(rule)
		if err != nil {
			return nil, err
		}
		stops = append(stops, stop)
	}
	if rule.Protocol == model.ForwardProtocolUDP || rule.Protocol == model.ForwardProtocolTCPUDP {
		stop, err := r.startBuiltinUDPForward(rule)
		if err != nil {
			for _, closeForward := range stops {
				closeForward()
			}
			return nil, err
		}
		stops = append(stops, stop)
	}
	var once sync.Once
	return func() {
		once.Do(func() {
			for _, stop := range stops {
				stop()
			}
		})
	}, nil
}

func (r *Runner) startBuiltinTCPForward(rule forwardRule) (func(), error) {
	listenIP := strings.TrimSpace(rule.ListenIP)
	if listenIP == "" {
		listenIP = "0.0.0.0"
	}
	ln, err := net.Listen("tcp", net.JoinHostPort(listenIP, fmt.Sprint(rule.ListenPort)))
	if err != nil {
		return nil, err
	}
	stop := func() { _ = ln.Close() }
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go r.handleBuiltinForwardConn(conn, rule)
		}
	}()
	return stop, nil
}

type builtinUDPSession struct {
	conn      *net.UDPConn
	client    *net.UDPAddr
	lastSeen  time.Time
	sessionID [8]byte
	counter   uint32
}

func (r *Runner) startBuiltinUDPForward(rule forwardRule) (func(), error) {
	listenIP := strings.TrimSpace(rule.ListenIP)
	if listenIP == "" {
		listenIP = "0.0.0.0"
	}
	listenAddr, err := net.ResolveUDPAddr("udp", net.JoinHostPort(listenIP, fmt.Sprint(rule.ListenPort)))
	if err != nil {
		return nil, err
	}
	targetAddr, err := net.ResolveUDPAddr("udp", net.JoinHostPort(rule.TargetAddress, fmt.Sprint(rule.TargetPort)))
	if err != nil {
		return nil, err
	}
	listener, err := net.ListenUDP("udp", listenAddr)
	if err != nil {
		return nil, err
	}
	const maxSessions = 4096
	const idleTimeout = 2 * time.Minute
	var mu sync.Mutex
	sessions := map[string]*builtinUDPSession{}
	closed := false
	closeSession := func(key string, session *builtinUDPSession) {
		if current := sessions[key]; current == session {
			delete(sessions, key)
		}
		_ = session.conn.Close()
	}
	startSession := func(client *net.UDPAddr) (*builtinUDPSession, error) {
		conn, err := net.DialUDP("udp", nil, targetAddr)
		if err != nil {
			return nil, err
		}
		session := &builtinUDPSession{conn: conn, client: client, lastSeen: time.Now()}
		if rule.TrustedForward != nil {
			if _, err := rand.Read(session.sessionID[:]); err != nil {
				_ = conn.Close()
				return nil, err
			}
		}
		key := client.String()
		go func() {
			buf := make([]byte, 64*1024)
			for {
				n, err := conn.Read(buf)
				if err != nil {
					return
				}
				if _, err := listener.WriteToUDP(buf[:n], client); err != nil {
					return
				}
				mu.Lock()
				if current := sessions[key]; current == session {
					current.lastSeen = time.Now()
				}
				mu.Unlock()
			}
		}()
		return session, nil
	}
	go func() {
		buf := make([]byte, 64*1024)
		for {
			n, client, err := listener.ReadFromUDP(buf)
			if err != nil {
				return
			}
			key := client.String()
			mu.Lock()
			session := sessions[key]
			if session == nil && !closed && len(sessions) < maxSessions {
				session, err = startSession(client)
				if err == nil {
					sessions[key] = session
				}
			}
			if session != nil {
				session.lastSeen = time.Now()
				if rule.TrustedForward != nil {
					session.counter++
					if session.counter == 0 {
						closeSession(key, session)
						session = nil
					}
				}
			}
			counter := uint32(0)
			if session != nil {
				counter = session.counter
			}
			mu.Unlock()
			if err == nil && session != nil {
				payload := buf[:n]
				if rule.TrustedForward != nil {
					source, sourceErr := trustedForwardSource(client)
					if sourceErr != nil {
						continue
					}
					payload, err = encodeTrustedForwardUDPAt(rule.TrustedForward, source, session.sessionID, counter, payload, trustedForwardUDPData, r.clock.Now())
					if err != nil {
						continue
					}
				}
				_, _ = session.conn.Write(payload)
			}
		}
	}()
	go func() {
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()
		for range ticker.C {
			mu.Lock()
			if closed {
				mu.Unlock()
				return
			}
			now := time.Now()
			for key, session := range sessions {
				if now.Sub(session.lastSeen) > idleTimeout {
					closeSession(key, session)
				}
			}
			mu.Unlock()
		}
	}()
	var once sync.Once
	return func() {
		once.Do(func() {
			_ = listener.Close()
			mu.Lock()
			closed = true
			for key, session := range sessions {
				closeSession(key, session)
			}
			mu.Unlock()
		})
	}, nil
}

func (r *Runner) handleBuiltinForwardConn(src net.Conn, rule forwardRule) {
	defer src.Close()
	var trustedPreface []byte
	if rule.TrustedForward != nil {
		_ = src.SetReadDeadline(time.Now().Add(5 * time.Second))
		first := make([]byte, trustedForwardTCPFirstBytes)
		n, err := src.Read(first)
		_ = src.SetReadDeadline(time.Time{})
		if err != nil || n == 0 {
			return
		}
		source, err := trustedForwardSource(src.RemoteAddr())
		if err != nil {
			return
		}
		trustedPreface, err = encodeTrustedForwardTCPAt(rule.TrustedForward, source, first[:n], trustedForwardTCPData, r.clock.Now())
		if err != nil {
			return
		}
	}
	start := time.Now()
	target := net.JoinHostPort(rule.TargetAddress, fmt.Sprint(rule.TargetPort))
	dst, err := net.DialTimeout("tcp", target, 5*time.Second)
	latency := time.Since(start)
	if shouldSample(rule.SampleRate) {
		details, _ := json.Marshal(map[string]any{"kind": "passive_target_connect", "target": target})
		res := model.PortForwardProbeResult{PortForwardID: rule.ID, Mode: "sampled", Available: err == nil, LatencyMS: latency.Milliseconds(), SampleCount: 1, ResultJSON: string(details)}
		if err != nil {
			res.Error = err.Error()
		}
		go r.reportForwardProbe(context.Background(), res)
	}
	if err != nil {
		return
	}
	defer dst.Close()
	if len(trustedPreface) > 0 {
		if err := writeTrustedForward(dst, trustedPreface); err != nil {
			return
		}
	}
	go func() { _, _ = io.Copy(dst, src); _ = dst.Close() }()
	_, _ = io.Copy(src, dst)
}

func shouldSample(rate float64) bool {
	if rate <= 0 {
		return false
	}
	if rate >= 1 {
		return true
	}
	var raw [8]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return false
	}
	value := binary.BigEndian.Uint64(raw[:]) >> 11
	return float64(value)/float64(uint64(1)<<53) < rate
}

func (r *Runner) setForwardProbeRules(rules []forwardRule) {
	out := make([]model.PortForward, 0, len(rules))
	for _, rule := range rules {
		if rule.ProbeMode == "" || rule.ProbeMode == "never" {
			continue
		}
		out = append(out, rule.PortForward)
	}
	r.mu.Lock()
	r.forwardProbeRules = out
	now := time.Now()
	nextLast := make(map[int64]time.Time, len(out))
	for _, rule := range out {
		if previous := r.lastForwardProbe[rule.ID]; !previous.IsZero() {
			nextLast[rule.ID] = previous
		} else if rule.ProbeMode == "apply" || rule.ProbeMode == "periodic" || rule.ProbeMode == "periodic_sampled" {
			// Applying a plan should not immediately fan out a second probe task.
			nextLast[rule.ID] = now
		}
	}
	r.lastForwardProbe = nextLast
	r.mu.Unlock()
}

func (r *Runner) maybeRunPeriodicForwardProbes(ctx context.Context) error {
	r.mu.Lock()
	rules := append([]model.PortForward(nil), r.forwardProbeRules...)
	last := make(map[int64]time.Time, len(r.lastForwardProbe))
	for id, value := range r.lastForwardProbe {
		last[id] = value
	}
	r.mu.Unlock()
	due := make([]model.PortForward, 0)
	now := time.Now()
	for _, rule := range rules {
		if rule.ProbeMode != "apply" && rule.ProbeMode != "periodic" && rule.ProbeMode != "periodic_sampled" {
			continue
		}
		interval := time.Duration(rule.ProbeIntervalSeconds) * time.Second
		minimum := 5 * time.Minute
		if r.resources.Profile == ResourceProfileSmall {
			minimum = 15 * time.Minute
		}
		if interval < minimum {
			interval = minimum
		}
		if now.Sub(last[rule.ID]) >= interval {
			due = append(due, rule)
			last[rule.ID] = now
		}
	}
	if len(due) == 0 {
		return nil
	}
	r.mu.Lock()
	r.lastForwardProbe = last
	r.mu.Unlock()
	_, err := r.runForwardProbeTask(ctx, due, "periodic")
	return err
}

func (r *Runner) runForwardProbeTask(ctx context.Context, rules []model.PortForward, mode string) ([]model.PortForwardProbeResult, error) {
	results := make([]model.PortForwardProbeResult, 0, len(rules))
	var reportErr error
	for _, rule := range rules {
		if rule.ProbeMode == "never" {
			continue
		}
		res := r.probeForward(rule, mode)
		results = append(results, res)
		if err := r.reportForwardProbe(ctx, res); err != nil && reportErr == nil {
			reportErr = err
		}
	}
	return results, reportErr
}

func probeForward(rule model.PortForward, mode string) model.PortForwardProbeResult {
	return probeForwardAt(rule, mode, time.Now)
}

func (r *Runner) probeForward(rule model.PortForward, mode string) model.PortForwardProbeResult {
	return probeForwardAt(rule, mode, r.clock.Now)
}

func probeForwardAt(rule model.PortForward, mode string, now func() time.Time) model.PortForwardProbeResult {
	if rule.TrustedForward != nil {
		return probeTrustedForwardAt(rule, mode, now)
	}
	res := model.PortForwardProbeResult{PortForwardID: rule.ID, Mode: mode, ResultJSON: "{}"}
	if rule.Protocol == model.ForwardProtocolUDP {
		listenerOK, listenerErr := udpPortBound(rule.ListenIP, rule.ListenPort)
		targetOK, targetErr := udpSignalProbe(rule.TargetAddress, rule.TargetPort, defaultProbeSamples, defaultProbeInterval, defaultProbeTimeout)
		res.Available = listenerOK && targetOK
		res.SampleCount = defaultProbeSamples
		if targetOK {
			res.SampleCount = defaultProbeSamples
		}
		details := map[string]any{
			"kind": "udp_signal", "listener_ok": listenerOK, "target_signal_ok": targetOK,
			"target":        net.JoinHostPort(rule.TargetAddress, fmt.Sprint(rule.TargetPort)),
			"confirmed_rtt": false,
		}
		if listenerErr != nil {
			details["listener_error"] = listenerErr.Error()
		}
		if targetErr != nil {
			details["target_error"] = targetErr.Error()
		}
		if !res.Available {
			res.Error = "UDP 转发监听或目标发包失败"
		}
		res.ResultJSON = marshalProbeDetails(details)
		return res
	}
	localHost := localProbeHost(rule.ListenIP)
	listenerLatencies, listenerFailures := tcpProbeSamples(localHost, rule.ListenPort, 1, 0, defaultProbeTimeout)
	targetLatencies, targetFailures := tcpProbeSamples(rule.TargetAddress, rule.TargetPort, defaultProbeSamples, defaultProbeInterval, defaultProbeTimeout)
	stats := model.InboundProbeResult{}
	applyProbeStats(&stats, targetLatencies, defaultProbeSamples)
	res.LatencyMS = stats.LatencyMS
	res.SampleCount = stats.SampleCount
	listenerOK := len(listenerLatencies) == 1
	targetOK := stats.SuccessCount >= requiredProbeSuccesses(defaultProbeSamples)
	res.Available = listenerOK && targetOK
	details := map[string]any{
		"kind": "active_forward_path", "listener_ok": listenerOK,
		"target":        net.JoinHostPort(rule.TargetAddress, fmt.Sprint(rule.TargetPort)),
		"success_count": stats.SuccessCount, "sample_count": stats.SampleCount,
		"latencies_ms": targetLatencies, "min_latency_ms": stats.MinLatencyMS,
		"p95_latency_ms": stats.P95LatencyMS, "jitter_ms": stats.JitterMS,
	}
	if len(listenerFailures) > 0 {
		details["listener_failures"] = listenerFailures
	}
	if len(targetFailures) > 0 {
		details["target_failures"] = targetFailures
	}
	if !res.Available {
		res.Error = fmt.Sprintf("转发探测失败：本地监听=%t，A-B 目标成功=%d/%d", listenerOK, stats.SuccessCount, stats.SampleCount)
	}
	res.ResultJSON = marshalProbeDetails(details)
	return res
}

func udpSignalProbe(host string, port, count int, interval, timeout time.Duration) (bool, error) {
	address, err := net.ResolveUDPAddr("udp", net.JoinHostPort(strings.Trim(host, "[]"), fmt.Sprint(port)))
	if err != nil {
		return false, err
	}
	conn, err := net.DialUDP("udp", nil, address)
	if err != nil {
		return false, err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))
	for i := 0; i < count; i++ {
		if _, err := conn.Write([]byte{0}); err != nil {
			return false, err
		}
		if i+1 < count {
			time.Sleep(interval)
		}
	}
	return true, nil
}

func (r *Runner) reportForwardProbe(ctx context.Context, result model.PortForwardProbeResult) error {
	if result.ResultJSON == "" {
		result.ResultJSON = "{}"
	}
	return r.postControllerJSON(ctx, "/api/v1/agent/port-forward-probes", result, nil, true)
}

func runningAsRoot() bool {
	if runtime.GOOS != "linux" && runtime.GOOS != "darwin" && runtime.GOOS != "freebsd" && runtime.GOOS != "openbsd" && runtime.GOOS != "netbsd" {
		return false
	}
	out, err := commandOutput(2*time.Second, "id", "-u")
	return err == nil && strings.TrimSpace(out) == "0"
}

func (r *Runner) applyRealmForwards(rules []forwardRule) error {
	stateDir := r.stateDir()
	pidPath := filepath.Join(stateDir, realmPIDFile)
	if len(rules) == 0 {
		return stopManagedProcess(pidPath)
	}
	if _, err := exec.LookPath("realm"); err != nil {
		return err
	}
	config, err := generateRealmConfig(rules)
	if err != nil {
		return err
	}
	configPath := filepath.Join(stateDir, realmConfigFile)
	if err := os.WriteFile(configPath, []byte(config), 0o600); err != nil {
		return err
	}
	_ = stopManagedProcess(pidPath)
	logPath := filepath.Join(stateDir, realmLogFile)
	// #nosec G304 -- logPath is a fixed file below the private Agent state directory.
	logFile, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return err
	}
	// #nosec G204 -- the executable and option are fixed and configPath is a separate argv entry.
	cmd := exec.Command("realm", "-c", configPath)
	cmd.Stdout = logFile
	cmd.Stderr = logFile
	if err := cmd.Start(); err != nil {
		_ = logFile.Close()
		return err
	}
	_ = logFile.Close()
	return writeManagedPIDFile(pidPath, cmd.Process.Pid, "realm")
}

func stopManagedProcess(pidPath string) error {
	// #nosec G304 -- pidPath is assembled from fixed names below the private Agent state directory.
	b, err := os.ReadFile(pidPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	var record struct {
		PID        int    `json:"pid"`
		Command    string `json:"command"`
		StartToken string `json:"start_token"`
	}
	if json.Unmarshal(b, &record) != nil {
		record.PID, err = parsePID(strings.TrimSpace(string(b)))
	}
	if err != nil || record.PID <= 0 {
		_ = os.Remove(pidPath)
		return nil
	}
	expected := record.Command
	if expected == "" {
		base := filepath.Base(pidPath)
		if strings.HasPrefix(base, "ssh-") {
			expected = "ssh"
		} else if strings.Contains(base, "realm") {
			expected = "realm"
		}
	}
	if !managedProcessMatches(record.PID, expected, record.StartToken) {
		_ = os.Remove(pidPath)
		return fmt.Errorf("refusing to stop PID %d because it no longer matches managed %s process", record.PID, expected)
	}
	if proc, err := os.FindProcess(record.PID); err == nil {
		_ = proc.Kill()
	}
	_ = os.Remove(pidPath)
	return nil
}

func writeManagedPIDFile(path string, pid int, command string) error {
	record := map[string]any{"pid": pid, "command": command, "start_token": processStartToken(pid)}
	b, err := json.Marshal(record)
	if err != nil {
		return err
	}
	return atomicWriteFile(path, b, 0o600)
}

func managedProcessMatches(pid int, expected, startToken string) bool {
	if pid <= 0 {
		return false
	}
	currentToken := processStartToken(pid)
	if currentToken == "" {
		return false
	}
	if startToken != "" && currentToken != startToken {
		return false
	}
	if expected == "" {
		return startToken != ""
	}
	cmdline := ""
	if b, err := readProcPIDFile(pid, "cmdline"); err == nil {
		cmdline = strings.ReplaceAll(string(b), "\x00", " ")
	} else if out, err := commandOutput(2*time.Second, "ps", "-p", fmt.Sprint(pid), "-o", "command="); err == nil {
		cmdline = out
	}
	for _, field := range strings.Fields(cmdline) {
		if filepath.Base(field) == expected || strings.HasSuffix(field, "/"+expected) {
			return true
		}
	}
	return false
}

func processStartToken(pid int) string {
	if b, err := readProcPIDFile(pid, "stat"); err == nil {
		line := string(b)
		if close := strings.LastIndex(line, ")"); close >= 0 {
			fields := strings.Fields(line[close+1:])
			if len(fields) > 19 {
				return fields[19]
			}
		}
	}
	out, err := commandOutput(2*time.Second, "ps", "-p", fmt.Sprint(pid), "-o", "lstart=")
	if err != nil {
		return ""
	}
	return strings.TrimSpace(out)
}

func readProcPIDFile(pid int, name string) ([]byte, error) {
	if pid <= 0 || name != "cmdline" && name != "stat" {
		return nil, errors.New("invalid proc file request")
	}
	root, err := os.OpenRoot("/proc")
	if err != nil {
		return nil, err
	}
	defer root.Close()
	return root.ReadFile(filepath.Join(strconv.Itoa(pid), name))
}

func parsePID(v string) (int, error) {
	var pid int
	_, err := fmt.Sscanf(v, "%d", &pid)
	if pid <= 0 && err == nil {
		err = errors.New("invalid pid")
	}
	return pid, err
}

func generateRealmConfig(rules []forwardRule) (string, error) {
	var b strings.Builder
	b.WriteString("# Generated by OBoard Agent. Do not edit manually.\n")
	b.WriteString("[network]\n")
	b.WriteString("use_udp = true\n\n")
	for _, rule := range rules {
		if err := core.ValidateSafeHost(rule.TargetAddress); err != nil {
			return "", fmt.Errorf("realm target_address for rule %q: %w", rule.Name, err)
		}
		listenIP := strings.TrimSpace(rule.ListenIP)
		if listenIP == "" {
			listenIP = "0.0.0.0"
		}
		b.WriteString("[[endpoints]]\n")
		b.WriteString(fmt.Sprintf("# id=%d name=%q protocol=%s priority=%d\n", rule.ID, rule.Name, rule.Protocol, rule.Priority))
		b.WriteString(fmt.Sprintf("listen = %q\n", net.JoinHostPort(listenIP, fmt.Sprint(rule.ListenPort))))
		b.WriteString(fmt.Sprintf("remote = %q\n\n", net.JoinHostPort(rule.TargetAddress, fmt.Sprint(rule.TargetPort))))
	}
	return b.String(), nil
}

func (r *Runner) applyNFTForwards(rules []forwardRule, result *forwardApplyResult) error {
	if runtime.GOOS != "linux" {
		if len(rules) == 0 {
			return nil
		}
		return errors.New("nft backend is only supported on Linux")
	}
	if len(rules) == 0 {
		_ = runCommand(r.commandTimeout(), "nft", "delete", "table", "inet", nftTableName)
		return nil
	}
	if result != nil && !linuxIPForwardEnabled() {
		result.Warnings = append(result.Warnings, "Linux ip_forward is disabled; nft DNAT rules may not forward routed traffic until sysctl net.ipv4.ip_forward=1 is enabled")
	}
	config, err := generateNFTConfig(rules)
	if err != nil {
		return err
	}
	path := filepath.Join(r.stateDir(), nftConfigFile)
	if err := os.WriteFile(path, []byte(config), 0o600); err != nil {
		return err
	}
	_ = runCommand(r.commandTimeout(), "nft", "delete", "table", "inet", nftTableName)
	return runCommand(r.commandTimeout(), "nft", "-f", path)
}

func generateNFTConfig(rules []forwardRule) (string, error) {
	var b strings.Builder
	b.WriteString("#!/usr/sbin/nft -f\n")
	b.WriteString("# Generated by OBoard Agent. It owns only table inet oboard_forward.\n")
	b.WriteString("table inet ")
	b.WriteString(nftTableName)
	b.WriteString(" {\n")
	b.WriteString("  chain prerouting {\n")
	b.WriteString("    type nat hook prerouting priority dstnat; policy accept;\n")
	for _, rule := range rules {
		lines, err := nftRuleLines(rule)
		if err != nil {
			return "", err
		}
		for _, line := range lines {
			b.WriteString("    ")
			b.WriteString(line)
			b.WriteByte('\n')
		}
	}
	b.WriteString("  }\n")
	b.WriteString("  chain postrouting {\n")
	b.WriteString("    type nat hook postrouting priority srcnat; policy accept;\n")
	b.WriteString("    masquerade\n")
	b.WriteString("  }\n")
	b.WriteString("}\n")
	return b.String(), nil
}

func nftRuleLines(rule forwardRule) ([]string, error) {
	target, err := netip.ParseAddr(strings.Trim(rule.TargetAddress, "[]"))
	if err != nil {
		return nil, fmt.Errorf("nft backend requires target_address to be an IP address for rule %q: %w", rule.Name, err)
	}
	family := "ip"
	if target.Is6() {
		family = "ip6"
	}
	daddr := ""
	if strings.TrimSpace(rule.ListenIP) != "" {
		listen, err := netip.ParseAddr(strings.Trim(rule.ListenIP, "[]"))
		if err != nil {
			return nil, fmt.Errorf("invalid nft listen_ip for rule %q: %w", rule.Name, err)
		}
		if listen.Is6() != target.Is6() {
			return nil, fmt.Errorf("nft listen_ip and target_address IP family differ for rule %q", rule.Name)
		}
		daddr = fmt.Sprintf("%s daddr %s ", family, listen.String())
	}
	var protocols []string
	switch rule.Protocol {
	case model.ForwardProtocolTCP:
		protocols = []string{"tcp"}
	case model.ForwardProtocolUDP:
		protocols = []string{"udp"}
	case model.ForwardProtocolTCPUDP:
		protocols = []string{"tcp", "udp"}
	default:
		return nil, fmt.Errorf("unsupported forward protocol %q", rule.Protocol)
	}
	out := make([]string, 0, len(protocols))
	for _, proto := range protocols {
		out = append(out, fmt.Sprintf("%s%s dport %d dnat %s to %s", daddr, proto, rule.ListenPort, family, nftDNATTarget(target, rule.TargetPort)))
	}
	return out, nil
}

func nftDNATTarget(addr netip.Addr, port int) string {
	if addr.Is6() {
		return fmt.Sprintf("[%s]:%d", addr.String(), port)
	}
	return fmt.Sprintf("%s:%d", addr.String(), port)
}

func linuxIPForwardEnabled() bool {
	b, err := os.ReadFile("/proc/sys/net/ipv4/ip_forward")
	return err == nil && strings.TrimSpace(string(b)) == "1"
}
