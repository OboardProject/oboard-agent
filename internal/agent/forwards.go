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
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/OboardProject/oboard-agent/internal/core"
	"github.com/OboardProject/oboard-agent/internal/model"
)

const (
	portForwardsCurrent  = "port-forwards.json"
	portForwardsLastGood = "port-forwards.last-good.json"
	// The state file names predate the bundled binary. They are kept so that a
	// host upgrading from a PATH realm still finds its recorded PID here and
	// stops that process before the bundled one takes the same listen ports.
	realmConfigFile  = "realm.toml"
	realmPIDFile     = "realm.pid"
	realmLogFile     = "realm.log"
	realmProcessName = "oboard-realm"
	legacyRealmName  = "realm"
)

type forwardApplyResult struct {
	Version      int64             `json:"version"`
	Unchanged    bool              `json:"unchanged,omitempty"`
	Applied      int               `json:"applied"`
	RealmRules   int               `json:"realm_rules"`
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
	result := forwardApplyResult{Version: plan.Version, Capabilities: r.detectForwardCapabilities(), Backends: map[string]string{}}
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
	originalResolved, err := resolveForwardBackends(current.Rules, r.detectForwardCapabilities())
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
	retainedResolved, err := resolveForwardBackends(retained.Rules, r.detectForwardCapabilities())
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
	resolved, err := resolveForwardBackends(plan.Rules, r.detectForwardCapabilities())
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
	if err := r.applyRealmForwards(rules); err != nil {
		return err
	}
	if result != nil {
		result.Applied = len(rules)
		result.RealmRules = len(rules)
	}
	r.setForwardProbeRules(rules)
	return nil
}

func resolveForwardBackends(rules []model.PortForward, caps map[string]bool) ([]forwardRule, error) {
	out := make([]forwardRule, 0, len(rules))
	for _, rule := range rules {
		backend := rule.Backend
		if backend == "" {
			backend = model.ForwardBackendRealm
		}
		if backend != model.ForwardBackendRealm {
			return nil, fmt.Errorf("unsupported forward backend %q", backend)
		}
		if !caps["realm"] {
			return nil, fmt.Errorf("port forward %q requires the bundled %s binary; run the Agent update from the panel to install it", rule.Name, realmProcessName)
		}
		out = append(out, forwardRule{PortForward: rule, ResolvedBackend: backend})
	}
	return out, nil
}

func (r *Runner) detectForwardCapabilities() map[string]bool {
	return map[string]bool{
		"realm": executableFileExists(r.realmBinary()),
		"linux": runtime.GOOS == "linux",
		"root":  runningAsRoot(),
	}
}

func executableFileExists(path string) bool {
	if strings.TrimSpace(path) == "" {
		return false
	}
	info, err := os.Stat(path)
	if err != nil || !info.Mode().IsRegular() {
		return false
	}
	return info.Mode().Perm()&0o111 != 0
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
		res.ResultJSON = marshalForwardProbeDetails(rule, details)
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
	res.ResultJSON = marshalForwardProbeDetails(rule, details)
	return res
}

func marshalForwardProbeDetails(rule model.PortForward, details map[string]any) string {
	if !rule.UpdatedAt.IsZero() {
		details["forward_updated_at"] = rule.UpdatedAt.UTC().Format(time.RFC3339Nano)
	}
	return marshalProbeDetails(details)
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
	realmPath := r.realmBinary()
	if !executableFileExists(realmPath) {
		return fmt.Errorf("bundled %s binary is not installed; run the Agent update from the panel to install it", realmProcessName)
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
	// #nosec G204 -- realmPath is the bundled binary validated above and configPath is a separate argv entry.
	cmd := exec.Command(realmPath, "-c", configPath)
	cmd.Stdout = logFile
	cmd.Stderr = logFile
	if err := cmd.Start(); err != nil {
		_ = logFile.Close()
		return err
	}
	_ = logFile.Close()
	return writeManagedPIDFile(pidPath, cmd.Process.Pid, realmProcessName)
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
		} else if strings.Contains(base, legacyRealmName) {
			// Only a record written before the command field existed lands here,
			// and back then the process was always a host-provided realm. A
			// bundled oboard-realm always records its own name explicitly.
			expected = legacyRealmName
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
