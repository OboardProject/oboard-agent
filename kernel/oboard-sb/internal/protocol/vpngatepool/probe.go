// SPDX-License-Identifier: GPL-3.0-or-later

package vpngatepool

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/OboardProject/oboard-agent/kernel/oboard-sb/internal/protocol/openvpn"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

const (
	MaxProbeCandidates  = 64
	probeConcurrency    = 4
	probeCandidateLimit = 25 * time.Second
	probeBatchLimit     = 150 * time.Second
	probeRTTSamples     = 3
	probeBodyLimit      = 256
)

var egressSources = []string{
	"https://api.ip.sb/ip",
	"https://icanhazip.com",
}

// ProbeCandidate is one server to measure.
type ProbeCandidate struct {
	ProbeID string `json:"probe_id"`
	openvpn.Spec
}

// ProbeResult is the bounded outcome of one candidate measurement.
type ProbeResult struct {
	ProbeID     string  `json:"probe_id"`
	Status      string  `json:"status"`
	Stage       string  `json:"stage,omitempty"`
	Error       string  `json:"error,omitempty"`
	HandshakeMS int64   `json:"handshake_ms,omitempty"`
	RTTMS       []int64 `json:"rtt_ms,omitempty"`
	TTFBMS      int64   `json:"ttfb_ms,omitempty"`
	EgressIP    string  `json:"egress_ip,omitempty"`
}

// Probe measures candidates with throwaway sessions over this pool's
// underlay. It never touches the pool's members or live traffic.
func (p *Pool) Probe(ctx context.Context, candidates []ProbeCandidate) ([]ProbeResult, error) {
	return probeCandidates(ctx, p.connect, candidates)
}

func probeCandidates(ctx context.Context, connect connectFunc, candidates []ProbeCandidate) ([]ProbeResult, error) {
	if len(candidates) == 0 {
		return nil, errors.New("no probe candidates")
	}
	if len(candidates) > MaxProbeCandidates {
		return nil, fmt.Errorf("at most %d probe candidates per batch", MaxProbeCandidates)
	}
	results := make([]ProbeResult, len(candidates))
	seen := map[string]bool{}
	batchCtx, cancel := context.WithTimeout(ctx, probeBatchLimit)
	defer cancel()
	sem := make(chan struct{}, probeConcurrency)
	var wg sync.WaitGroup
	for i := range candidates {
		candidate := candidates[i]
		results[i] = ProbeResult{ProbeID: candidate.ProbeID, Status: "failed"}
		if !memberIDPattern.MatchString(candidate.ProbeID) || seen[candidate.ProbeID] {
			results[i].Stage, results[i].Error = "validate", "invalid or duplicate probe_id"
			continue
		}
		seen[candidate.ProbeID] = true
		if err := candidate.Spec.Normalize(); err != nil {
			results[i].Stage, results[i].Error = "validate", boundError(err.Error())
			continue
		}
		wg.Add(1)
		go func(i int, candidate ProbeCandidate) {
			defer wg.Done()
			select {
			case sem <- struct{}{}:
				defer func() { <-sem }()
			case <-batchCtx.Done():
				results[i].Stage, results[i].Error = "queue", "probe batch timed out"
				return
			}
			candidateCtx, cancel := context.WithTimeout(batchCtx, probeCandidateLimit)
			defer cancel()
			results[i] = probeOne(candidateCtx, connect, candidate)
		}(i, candidate)
	}
	wg.Wait()
	return results, nil
}

func probeOne(ctx context.Context, connect connectFunc, candidate ProbeCandidate) ProbeResult {
	result := ProbeResult{ProbeID: candidate.ProbeID, Status: "failed"}
	sess, err := connect(ctx, candidate.Spec)
	if err != nil {
		result.Stage, result.Error = "handshake", boundError(err.Error())
		return result
	}
	defer sess.Close()
	result.HandshakeMS = sess.HandshakeDuration().Milliseconds()
	for i := 0; i < probeRTTSamples; i++ {
		rtt, err := checkSession(ctx, sess)
		if err != nil {
			result.Stage, result.Error = "tcp_connect", boundError(err.Error())
			return result
		}
		result.RTTMS = append(result.RTTMS, rtt.Milliseconds())
	}
	started := time.Now()
	egress, err := egressIP(ctx, sess)
	if err != nil {
		result.Stage, result.Error = "egress", boundError(err.Error())
		return result
	}
	result.TTFBMS = time.Since(started).Milliseconds()
	result.EgressIP = egress
	result.Status = "succeeded"
	return result
}

func egressIP(ctx context.Context, sess session) (string, error) {
	client := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			Proxy:             nil,
			DisableKeepAlives: true,
			DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
				return sess.DialContext(ctx, N.NetworkTCP, M.ParseSocksaddr(address))
			},
		},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	var lastErr error
	for _, source := range egressSources {
		request, err := http.NewRequestWithContext(ctx, http.MethodGet, source, nil)
		if err != nil {
			return "", err
		}
		response, err := client.Do(request)
		if err != nil {
			lastErr = err
			continue
		}
		body, err := io.ReadAll(io.LimitReader(response.Body, probeBodyLimit))
		_ = response.Body.Close()
		if err != nil || response.StatusCode != http.StatusOK {
			lastErr = fmt.Errorf("egress source returned %d", response.StatusCode)
			continue
		}
		addr, err := netip.ParseAddr(strings.TrimSpace(string(body)))
		if err != nil {
			lastErr = errors.New("egress source returned an invalid address")
			continue
		}
		return addr.Unmap().String(), nil
	}
	return "", lastErr
}
