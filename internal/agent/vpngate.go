package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/OboardProject/oboard-agent/internal/model"
)

const (
	vpngateStateFile         = "vpngate-pools.json"
	vpngateMaxPools          = 64
	vpngateMaxMembers        = 8
	vpngateMaxProbe          = 64
	vpngateReconcileInterval = 15 * time.Second
	vpngateProbeTimeout      = 180 * time.Second
	vpngateStatusTimeout     = 3 * time.Second
	kernelCapabilityVPNGate  = "vpngate_pool_v1"
)

var vpngateTagPattern = regexp.MustCompile(`^vpngate-[1-9][0-9]{0,18}$`)

// errVPNGatePoolNotLoaded means the kernel has no such pool yet, typically
// because the deployment that adds it has not been applied. The persisted
// membership is installed by the reconciler as soon as the pool appears.
var errVPNGatePoolNotLoaded = errors.New("vpngate pool is not loaded by the kernel yet")

type vpngateState struct {
	mu       sync.Mutex
	plans    map[string]model.VPNGatePoolPlan
	wake     chan struct{}
	status   []model.VPNGatePoolStatus
	statusAt time.Time
}

const vpngateStatusFreshness = 90 * time.Second

// cachedVPNGateStatus is the most recent kernel pool health, for the health
// report. It is refreshed by the reconcile loop and never blocks.
func (r *Runner) cachedVPNGateStatus() []model.VPNGatePoolStatus {
	state := r.vpngate()
	state.mu.Lock()
	defer state.mu.Unlock()
	if len(state.status) == 0 || time.Since(state.statusAt) > vpngateStatusFreshness {
		return nil
	}
	return append([]model.VPNGatePoolStatus(nil), state.status...)
}

type persistedVPNGatePools struct {
	Plans []model.VPNGatePoolPlan `json:"plans"`
}

func (r *Runner) vpngatePath() string {
	return r.statePath(vpngateStateFile)
}

func (r *Runner) vpngate() *vpngateState {
	r.vpngateOnce.Do(func() {
		r.vpngateState = &vpngateState{plans: map[string]model.VPNGatePoolPlan{}, wake: make(chan struct{}, 1)}
		raw, err := r.stateReadPath(r.vpngatePath())
		if err != nil {
			return
		}
		var persisted persistedVPNGatePools
		if json.Unmarshal(raw, &persisted) != nil {
			return
		}
		for _, plan := range persisted.Plans {
			if validateVPNGatePlan(plan) == nil {
				r.vpngateState.plans[plan.Tag] = plan
			}
		}
	})
	return r.vpngateState
}

func validateVPNGatePlan(plan model.VPNGatePoolPlan) error {
	if plan.PoolID <= 0 || plan.Tag != fmt.Sprintf("vpngate-%d", plan.PoolID) || !vpngateTagPattern.MatchString(plan.Tag) {
		return errors.New("vpngate plan tag must be vpngate-<pool_id>")
	}
	if plan.Revision <= 0 {
		return errors.New("vpngate plan revision must be positive")
	}
	if strings.TrimSpace(plan.ContentDigest) == "" || len(plan.ContentDigest) > 128 {
		return errors.New("vpngate plan content_digest is required")
	}
	if len(plan.Members) > vpngateMaxMembers {
		return fmt.Errorf("vpngate plan accepts at most %d members", vpngateMaxMembers)
	}
	if plan.HotStandby < 0 || plan.HotStandby > 2 {
		return errors.New("vpngate plan hot_standby must be between 0 and 2")
	}
	return nil
}

func (r *Runner) persistVPNGateLocked(state *vpngateState) error {
	persisted := persistedVPNGatePools{Plans: make([]model.VPNGatePoolPlan, 0, len(state.plans))}
	for _, plan := range state.plans {
		persisted.Plans = append(persisted.Plans, plan)
	}
	sort.Slice(persisted.Plans, func(i, j int) bool { return persisted.Plans[i].Tag < persisted.Plans[j].Tag })
	data, err := json.Marshal(persisted)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(r.stateDir(), 0o700); err != nil {
		return err
	}
	return r.stateWritePath(r.vpngatePath(), data, 0o600)
}

// applyVPNGatePool persists a signed membership and installs it in the
// kernel. The persisted copy survives Agent and kernel restarts; a kernel
// that comes back empty refuses all pool traffic until it is reinstalled.
func (r *Runner) applyVPNGatePool(ctx context.Context, plan model.VPNGatePoolPlan) (map[string]any, error) {
	if err := validateVPNGatePlan(plan); err != nil {
		return nil, err
	}
	state := r.vpngate()
	state.mu.Lock()
	if current, ok := state.plans[plan.Tag]; ok {
		if plan.Revision < current.Revision {
			state.mu.Unlock()
			return nil, fmt.Errorf("vpngate plan revision %d is older than applied revision %d", plan.Revision, current.Revision)
		}
		if plan.Revision == current.Revision && plan.ContentDigest != current.ContentDigest {
			state.mu.Unlock()
			return nil, fmt.Errorf("vpngate plan revision %d conflicts with the applied content", plan.Revision)
		}
	}
	if len(state.plans) >= vpngateMaxPools {
		if _, ok := state.plans[plan.Tag]; !ok {
			state.mu.Unlock()
			return nil, fmt.Errorf("at most %d vpngate pools per server", vpngateMaxPools)
		}
	}
	state.plans[plan.Tag] = plan
	err := r.persistVPNGateLocked(state)
	state.mu.Unlock()
	if err != nil {
		return nil, fmt.Errorf("persist vpngate plan: %w", err)
	}
	status, err := r.installVPNGatePlan(ctx, plan)
	if errors.Is(err, errVPNGatePoolNotLoaded) {
		return map[string]any{"message": "vpngate membership stored; waiting for the kernel to load the pool", "installed": false, "revision": plan.Revision}, nil
	}
	if err != nil {
		return nil, err
	}
	return map[string]any{"message": "vpngate membership installed", "installed": true, "revision": plan.Revision, "status": status}, nil
}

func (r *Runner) vpngateClient(timeout time.Duration) *http.Client {
	if r.coreClient != nil {
		// Share the transport, but keep operation deadlines independent of
		// the short timeout used by ordinary kernel requests.
		client := *r.coreClient
		client.Timeout = timeout
		return &client
	}
	dialer := &net.Dialer{Timeout: 3 * time.Second}
	socket := r.coreAPISocketPath()
	return &http.Client{Timeout: timeout, Transport: &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return dialer.DialContext(ctx, "unix", socket)
		},
		DisableKeepAlives:  true,
		DisableCompression: true,
	}}
}

func (r *Runner) installVPNGatePlan(ctx context.Context, plan model.VPNGatePoolPlan) (*model.VPNGatePoolStatus, error) {
	body, err := json.Marshal(map[string]any{
		"tag":            plan.Tag,
		"revision":       plan.Revision,
		"content_digest": plan.ContentDigest,
		"hot_standby":    plan.HotStandby,
		"members":        plan.Members,
	})
	if err != nil {
		return nil, err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://oboard-sb/outbounds/vpngate/members", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	request.Header.Set("Content-Type", "application/json")
	response, err := r.vpngateClient(10 * time.Second).Do(request)
	if err != nil {
		return nil, fmt.Errorf("install vpngate membership: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode == http.StatusNotFound {
		return nil, errVPNGatePoolNotLoaded
	}
	if response.StatusCode != http.StatusOK {
		message, _ := io.ReadAll(io.LimitReader(response.Body, 512))
		return nil, fmt.Errorf("kernel rejected vpngate membership (%d): %s", response.StatusCode, strings.TrimSpace(string(message)))
	}
	var payload struct {
		Status model.VPNGatePoolStatus `json:"status"`
	}
	if err := json.NewDecoder(io.LimitReader(response.Body, 64<<10)).Decode(&payload); err != nil {
		return nil, err
	}
	return &payload.Status, nil
}

// readVPNGateStatus returns the kernel's pool health, or nil when the kernel
// has no pool support or is unreachable.
func (r *Runner) readVPNGateStatus(ctx context.Context) ([]model.VPNGatePoolStatus, error) {
	ctx, cancel := context.WithTimeout(ctx, vpngateStatusTimeout)
	defer cancel()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://oboard-sb/outbounds/vpngate/status", nil)
	if err != nil {
		return nil, err
	}
	response, err := r.vpngateClient(vpngateStatusTimeout).Do(request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("vpngate status returned %d", response.StatusCode)
	}
	var payload struct {
		Pools []model.VPNGatePoolStatus `json:"pools"`
	}
	if err := json.NewDecoder(io.LimitReader(response.Body, 256<<10)).Decode(&payload); err != nil {
		return nil, err
	}
	if len(payload.Pools) > vpngateMaxPools {
		payload.Pools = payload.Pools[:vpngateMaxPools]
	}
	return payload.Pools, nil
}

// reconcileVPNGate reinstalls persisted memberships the kernel does not hold,
// for example after a kernel restart or a deployment that added the pool.
func (r *Runner) reconcileVPNGate(ctx context.Context) {
	state := r.vpngate()
	state.mu.Lock()
	plans := make([]model.VPNGatePoolPlan, 0, len(state.plans))
	for _, plan := range state.plans {
		plans = append(plans, plan)
	}
	state.mu.Unlock()
	if len(plans) == 0 && !r.kernelAdvertises(kernelCapabilityVPNGate) {
		return
	}
	pools, err := r.readVPNGateStatus(ctx)
	if err != nil {
		return
	}
	state.mu.Lock()
	state.status = pools
	state.statusAt = time.Now()
	state.mu.Unlock()
	loaded := map[string]model.VPNGatePoolStatus{}
	for _, pool := range pools {
		loaded[pool.Tag] = pool
	}
	for _, plan := range plans {
		current, ok := loaded[plan.Tag]
		if !ok {
			continue
		}
		if current.Revision == plan.Revision && current.ContentDigest == plan.ContentDigest {
			continue
		}
		if current.Revision > plan.Revision {
			continue
		}
		_, _ = r.installVPNGatePlan(ctx, plan)
	}
}

func (r *Runner) wakeVPNGate() {
	select {
	case r.vpngate().wake <- struct{}{}:
	default:
	}
}

func (r *Runner) startVPNGateLoop(ctx context.Context) {
	state := r.vpngate()
	go func() {
		ticker := time.NewTicker(vpngateReconcileInterval)
		defer ticker.Stop()
		for {
			r.reconcileVPNGate(ctx)
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
			case <-state.wake:
			}
		}
	}()
}

// probeVPNGate measures candidates through the kernel with throwaway
// sessions. Results are bounded and secret-free.
func (r *Runner) probeVPNGate(ctx context.Context, plan model.VPNGateProbePlan) (model.VPNGateProbeReport, error) {
	report := model.VPNGateProbeReport{PoolID: plan.PoolID, RequestID: plan.RequestID}
	if plan.PoolID <= 0 || plan.Tag != fmt.Sprintf("vpngate-%d", plan.PoolID) {
		return report, errors.New("vpngate probe tag must be vpngate-<pool_id>")
	}
	if len(plan.Candidates) == 0 || len(plan.Candidates) > vpngateMaxProbe {
		return report, fmt.Errorf("vpngate probe needs 1 to %d candidates", vpngateMaxProbe)
	}
	body, err := json.Marshal(map[string]any{"tag": plan.Tag, "candidates": plan.Candidates})
	if err != nil {
		return report, err
	}
	ctx, cancel := context.WithTimeout(ctx, vpngateProbeTimeout)
	defer cancel()
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://oboard-sb/outbounds/vpngate/probe", bytes.NewReader(body))
	if err != nil {
		return report, err
	}
	request.Header.Set("Content-Type", "application/json")
	response, err := r.vpngateClient(vpngateProbeTimeout).Do(request)
	if err != nil {
		return report, fmt.Errorf("vpngate probe: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode == http.StatusNotFound {
		return report, errVPNGatePoolNotLoaded
	}
	if response.StatusCode != http.StatusOK {
		message, _ := io.ReadAll(io.LimitReader(response.Body, 512))
		return report, fmt.Errorf("kernel rejected vpngate probe (%d): %s", response.StatusCode, strings.TrimSpace(string(message)))
	}
	var payload struct {
		Results []model.VPNGateProbeResult `json:"results"`
	}
	if err := json.NewDecoder(io.LimitReader(response.Body, 512<<10)).Decode(&payload); err != nil {
		return report, err
	}
	if len(payload.Results) > len(plan.Candidates) {
		payload.Results = payload.Results[:len(plan.Candidates)]
	}
	for i := range payload.Results {
		payload.Results[i].Error = boundedExternalEgressProbeError(payload.Results[i].Error)
		if len(payload.Results[i].RTTMS) > 8 {
			payload.Results[i].RTTMS = payload.Results[i].RTTMS[:8]
		}
	}
	report.Results = payload.Results
	return report, nil
}

func (r *Runner) kernelAdvertises(capability string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, item := range r.lastKernelCapabilities {
		if item == capability {
			return true
		}
	}
	return false
}
