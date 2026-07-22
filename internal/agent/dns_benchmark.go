package agent

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/OboardProject/oboard-agent/internal/core"
	"github.com/OboardProject/oboard-agent/internal/model"
	quic "github.com/sagernet/quic-go"
	"golang.org/x/net/dns/dnsmessage"
)

type dnsBenchmarkLocalState struct {
	LastRun map[string]time.Time               `json:"last_run"`
	Policy  *model.DNSBenchmarkPlan            `json:"policy,omitempty"`
	Best    map[string]model.DNSBenchmarkGroup `json:"best,omitempty"`
}

type dnsBenchmarkItem = model.DNSBenchmarkItem

func (r *Runner) runDNSBenchmarkTask(ctx context.Context, plan model.DNSBenchmarkPlan, fromTask bool) (map[string]any, error) {
	state, err := r.loadDNSBenchmarkState()
	if err != nil {
		return map[string]any{"server_id": plan.ServerID}, err
	}
	if plan.Mode == model.DNSAutoTestNever {
		state.Policy = nil
		state.LastRun = map[string]time.Time{}
		state.Best = map[string]model.DNSBenchmarkGroup{}
		if err := r.saveDNSBenchmarkState(state); err != nil {
			return map[string]any{"server_id": plan.ServerID}, err
		}
		return map[string]any{"skipped": true, "reason": "periodic dns test disabled", "server_id": plan.ServerID}, nil
	}
	if plan.PolicyRevision == 0 || plan.EncryptedListID == 0 || plan.BootstrapListID == 0 || len(plan.EncryptedCandidates) == 0 || len(plan.BootstrapCandidates) == 0 {
		return map[string]any{"skipped": true, "reason": "empty dns benchmark plan"}, nil
	}
	if err := validateDNSBenchmarkPlan(plan); err != nil {
		return map[string]any{"server_id": plan.ServerID}, err
	}

	key := dnsBenchmarkPlanKey(plan)
	if plan.Mode != model.DNSAutoTestPeriodic {
		state.Policy = nil
	}
	if fromTask && plan.Mode == model.DNSAutoTestFirstApply {
		if _, ok := state.LastRun[key]; ok {
			if err := r.saveDNSBenchmarkState(state); err != nil {
				return map[string]any{"server_id": plan.ServerID}, err
			}
			return map[string]any{"skipped": true, "reason": "first_apply already completed", "server_id": plan.ServerID}, nil
		}
	}
	if plan.Mode == model.DNSAutoTestPeriodic {
		if plan.IntervalSeconds < 300 {
			plan.IntervalSeconds = 3600
		}
		state.Policy = &plan
	}

	runCtx, cancel := context.WithTimeout(ctx, 45*time.Second)
	defer cancel()
	semaphore := make(chan struct{}, 4)
	bootstrapItems := benchmarkDNSCandidates(runCtx, plan.BootstrapCandidates, 2*time.Second, semaphore, nil)
	bootstrapBest := bestDNSBenchmarks(bootstrapItems, 2)

	var bootstrapPrimary *model.DNSCandidate
	if len(bootstrapBest) > 0 {
		for i := range plan.BootstrapCandidates {
			if plan.BootstrapCandidates[i].Tag == bootstrapBest[0].Tag {
				candidate := plan.BootstrapCandidates[i]
				bootstrapPrimary = &candidate
				break
			}
		}
	}
	var encryptedItems []dnsBenchmarkItem
	if bootstrapPrimary == nil {
		encryptedItems = failedDNSBenchmarkItems(plan.EncryptedCandidates, "bootstrap dns has no usable candidate", 2000)
	} else {
		encryptedItems = benchmarkDNSCandidates(runCtx, plan.EncryptedCandidates, 2*time.Second, semaphore, bootstrapPrimary)
	}
	encryptedBest := bestDNSBenchmarks(encryptedItems, 2)

	result := model.DNSBenchmarkResult{
		ReportID:              newDNSBenchmarkReportID(),
		RequestID:             plan.RequestID,
		ServerID:              plan.ServerID,
		PolicyRevision:        plan.PolicyRevision,
		EncryptedListID:       plan.EncryptedListID,
		EncryptedListRevision: plan.EncryptedListRevision,
		BootstrapListID:       plan.BootstrapListID,
		BootstrapListRevision: plan.BootstrapListRevision,
		Encrypted:             model.DNSBenchmarkGroup{Items: encryptedItems, BestTags: benchmarkTags(encryptedBest)},
		Bootstrap:             model.DNSBenchmarkGroup{Items: bootstrapItems, BestTags: benchmarkTags(bootstrapBest)},
	}
	if len(encryptedBest) == 0 || len(bootstrapBest) == 0 {
		result.Status = "failed"
		result.Error = "both encrypted and bootstrap dns groups require at least one usable candidate"
	} else {
		result.Status = "succeeded"
	}

	if state.Best == nil {
		state.Best = map[string]model.DNSBenchmarkGroup{}
	}
	if result.Status == "succeeded" {
		state.Best[key+":encrypted"] = result.Encrypted
		state.Best[key+":bootstrap"] = result.Bootstrap
		state.LastRun[key] = time.Now().UTC()
	} else if plan.Mode == model.DNSAutoTestPeriodic {
		state.LastRun[key] = time.Now().UTC()
	}
	stateErr := r.saveDNSBenchmarkState(state)
	postErr := r.postControllerJSON(ctx, "/api/v1/agent/dns-benchmarks", result, nil, true)
	response := map[string]any{
		"report_id":  result.ReportID,
		"request_id": result.RequestID,
		"status":     result.Status,
		"encrypted":  result.Encrypted,
		"bootstrap":  result.Bootstrap,
	}
	if postErr != nil {
		return response, postErr
	}
	if stateErr != nil {
		return response, stateErr
	}
	if result.Error != "" {
		return response, errors.New(result.Error)
	}
	return response, nil
}

func (r *Runner) maybeRunPeriodicDNSBenchmark(ctx context.Context) error {
	state, err := r.loadDNSBenchmarkState()
	if err != nil || state.Policy == nil || state.Policy.Mode != model.DNSAutoTestPeriodic {
		return err
	}
	interval := time.Duration(state.Policy.IntervalSeconds) * time.Second
	if interval < 5*time.Minute {
		interval = time.Hour
	}
	last := state.LastRun[dnsBenchmarkPlanKey(*state.Policy)]
	if !last.IsZero() && time.Since(last) < interval {
		return nil
	}
	_, err = r.runDNSBenchmarkTask(ctx, *state.Policy, false)
	return err
}

func dnsBenchmarkPlanKey(plan model.DNSBenchmarkPlan) string {
	return fmt.Sprintf("%d:%d:%d:%d:%d:%d", plan.ServerID, plan.PolicyRevision, plan.EncryptedListID, plan.EncryptedListRevision, plan.BootstrapListID, plan.BootstrapListRevision)
}

func validateDNSBenchmarkPlan(plan model.DNSBenchmarkPlan) error {
	if err := core.ValidateDNSCandidates(plan.EncryptedCandidates); err != nil {
		return fmt.Errorf("encrypted candidates: %w", err)
	}
	if err := core.ValidateDNSCandidates(plan.BootstrapCandidates); err != nil {
		return fmt.Errorf("bootstrap candidates: %w", err)
	}
	for i, candidate := range plan.EncryptedCandidates {
		switch candidate.Transport {
		case model.DNSTransportDoH, model.DNSTransportDoT, model.DNSTransportDoQ:
		default:
			return fmt.Errorf("encrypted candidate[%d] has invalid transport", i)
		}
	}
	for i, candidate := range plan.BootstrapCandidates {
		if candidate.Transport != model.DNSTransportUDP && candidate.Transport != model.DNSTransportTCP {
			return fmt.Errorf("bootstrap candidate[%d] has invalid transport", i)
		}
		if net.ParseIP(strings.Trim(candidate.Server, "[]")) == nil {
			return fmt.Errorf("bootstrap candidate[%d] must use an IP literal", i)
		}
	}
	return nil
}

func benchmarkDNSCandidates(ctx context.Context, candidates []model.DNSCandidate, timeout time.Duration, semaphore chan struct{}, bootstrap *model.DNSCandidate) []dnsBenchmarkItem {
	if timeout <= 0 {
		timeout = 2 * time.Second
	}
	out := make([]dnsBenchmarkItem, len(candidates))
	var wg sync.WaitGroup
	for i := range candidates {
		i := i
		candidate := candidates[i]
		wg.Add(1)
		go func() {
			defer wg.Done()
			select {
			case semaphore <- struct{}{}:
				defer func() { <-semaphore }()
			case <-ctx.Done():
				out[i] = dnsBenchmarkItem{Tag: candidate.Tag, LatencyMS: int64(timeout / time.Millisecond), Error: ctx.Err().Error()}
				return
			}
			candidateCtx, cancel := context.WithTimeout(ctx, timeout)
			defer cancel()
			started := time.Now()
			err := probeDNSCandidate(candidateCtx, candidate, timeout, bootstrap)
			item := dnsBenchmarkItem{Tag: candidate.Tag, LatencyMS: time.Since(started).Milliseconds()}
			if item.Tag == "" {
				item.Tag = candidate.Server
			}
			if err != nil {
				item.Error = err.Error()
				item.LatencyMS = int64(timeout / time.Millisecond)
			}
			out[i] = item
		}()
	}
	wg.Wait()
	sort.SliceStable(out, func(i, j int) bool {
		if (out[i].Error == "") != (out[j].Error == "") {
			return out[i].Error == ""
		}
		return out[i].LatencyMS < out[j].LatencyMS
	})
	return out
}

func failedDNSBenchmarkItems(candidates []model.DNSCandidate, message string, latency int64) []dnsBenchmarkItem {
	out := make([]dnsBenchmarkItem, 0, len(candidates))
	for _, candidate := range candidates {
		out = append(out, dnsBenchmarkItem{Tag: candidate.Tag, LatencyMS: latency, Error: message})
	}
	return out
}

func bestDNSBenchmark(items []dnsBenchmarkItem) dnsBenchmarkItem {
	best := bestDNSBenchmarks(items, 1)
	if len(best) > 0 {
		return best[0]
	}
	if len(items) > 0 {
		return items[0]
	}
	return dnsBenchmarkItem{}
}

func bestDNSBenchmarks(items []dnsBenchmarkItem, limit int) []dnsBenchmarkItem {
	out := make([]dnsBenchmarkItem, 0, limit)
	for _, item := range items {
		if item.Error != "" {
			continue
		}
		out = append(out, item)
		if len(out) == limit {
			break
		}
	}
	return out
}

func benchmarkTags(items []dnsBenchmarkItem) []string {
	out := make([]string, 0, len(items))
	for _, item := range items {
		out = append(out, item.Tag)
	}
	return out
}

func probeDNSCandidate(ctx context.Context, candidate model.DNSCandidate, timeout time.Duration, bootstrap *model.DNSCandidate) error {
	target := candidate.Server
	if bootstrap != nil && net.ParseIP(strings.Trim(target, "[]")) == nil {
		ip, err := resolveDNSBenchmarkHost(ctx, *bootstrap, target, timeout)
		if err != nil {
			return fmt.Errorf("bootstrap resolve %s: %w", target, err)
		}
		target = ip
	}
	return probeDNSCandidateAt(ctx, candidate, target, timeout)
}

func resolveDNSBenchmarkHost(ctx context.Context, bootstrap model.DNSCandidate, host string, timeout time.Duration) (string, error) {
	port := bootstrap.Port
	if port == 0 {
		port = 53
	}
	address := net.JoinHostPort(bootstrap.Server, fmt.Sprint(port))
	for _, recordType := range []dnsmessage.Type{dnsmessage.TypeA, dnsmessage.TypeAAAA} {
		queryID := uint16(time.Now().UnixNano())
		query, err := buildDNSLookupQuery(queryID, host, recordType)
		if err != nil {
			return "", err
		}
		response, err := exchangeBootstrapDNS(ctx, string(bootstrap.Transport), address, query, timeout)
		if err != nil {
			return "", err
		}
		ip, err := firstDNSResponseIP(response, queryID)
		if err == nil && ip != "" {
			return ip, nil
		}
		if err != nil && !errors.Is(err, errDNSNoAddress) {
			return "", err
		}
	}
	return "", errDNSNoAddress
}

var errDNSNoAddress = errors.New("dns response has no IP address")

func buildDNSLookupQuery(id uint16, host string, recordType dnsmessage.Type) ([]byte, error) {
	name, err := dnsmessage.NewName(strings.TrimSuffix(host, ".") + ".")
	if err != nil {
		return nil, err
	}
	builder := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: id, RecursionDesired: true})
	if err := builder.StartQuestions(); err != nil {
		return nil, err
	}
	if err := builder.Question(dnsmessage.Question{Name: name, Type: recordType, Class: dnsmessage.ClassINET}); err != nil {
		return nil, err
	}
	return builder.Finish()
}

func exchangeBootstrapDNS(ctx context.Context, network, address string, query []byte, timeout time.Duration) ([]byte, error) {
	dialer := &net.Dialer{Timeout: timeout}
	conn, err := dialer.DialContext(ctx, network, address)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()
	_ = conn.SetDeadline(time.Now().Add(timeout))
	if network == "tcp" {
		return exchangeDNSStream(conn, query)
	}
	if _, err := conn.Write(query); err != nil {
		return nil, err
	}
	response := make([]byte, 4096)
	n, err := conn.Read(response)
	if err != nil {
		return nil, err
	}
	return response[:n], nil
}

func firstDNSResponseIP(response []byte, id uint16) (string, error) {
	var parser dnsmessage.Parser
	header, err := parser.Start(response)
	if err != nil {
		return "", err
	}
	if !header.Response || header.ID != id {
		return "", errors.New("invalid dns lookup response")
	}
	if err := parser.SkipAllQuestions(); err != nil {
		return "", err
	}
	for {
		header, err := parser.AnswerHeader()
		if errors.Is(err, dnsmessage.ErrSectionDone) {
			return "", errDNSNoAddress
		}
		if err != nil {
			return "", err
		}
		switch header.Type {
		case dnsmessage.TypeA:
			resource, err := parser.AResource()
			if err != nil {
				return "", err
			}
			return net.IP(resource.A[:]).String(), nil
		case dnsmessage.TypeAAAA:
			resource, err := parser.AAAAResource()
			if err != nil {
				return "", err
			}
			return net.IP(resource.AAAA[:]).String(), nil
		default:
			if err := parser.SkipAnswer(); err != nil {
				return "", err
			}
		}
	}
}

func probeDNSCandidateAt(ctx context.Context, candidate model.DNSCandidate, target string, timeout time.Duration) error {
	port := candidate.Port
	if port == 0 {
		switch candidate.Transport {
		case model.DNSTransportDoT, model.DNSTransportDoQ:
			port = 853
		case model.DNSTransportDoH:
			port = 443
		default:
			port = 53
		}
	}
	address := net.JoinHostPort(target, fmt.Sprint(port))
	queryID := uint16(time.Now().UnixNano())
	query, err := buildDNSProbeQuery(queryID)
	if err != nil {
		return err
	}
	dialer := &net.Dialer{Timeout: timeout}
	switch candidate.Transport {
	case model.DNSTransportUDP, model.DNSTransportTCP:
		conn, err := dialer.DialContext(ctx, string(candidate.Transport), address)
		if err != nil {
			return err
		}
		defer conn.Close()
		stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
		defer stop()
		_ = conn.SetDeadline(time.Now().Add(timeout))
		var response []byte
		if candidate.Transport == model.DNSTransportUDP {
			if _, err := conn.Write(query); err != nil {
				return err
			}
			packet := make([]byte, 4096)
			n, err := conn.Read(packet)
			if err != nil {
				return err
			}
			response = packet[:n]
		} else {
			response, err = exchangeDNSStream(conn, query)
			if err != nil {
				return err
			}
		}
		return validateDNSProbeResponse(response, queryID)
	case model.DNSTransportDoT:
		name := candidate.TLSName
		if name == "" {
			name = candidate.Server
		}
		raw, err := dialer.DialContext(ctx, "tcp", address)
		if err != nil {
			return err
		}
		defer raw.Close()
		stop := context.AfterFunc(ctx, func() { _ = raw.Close() })
		defer stop()
		conn := tls.Client(raw, &tls.Config{ServerName: name, MinVersion: tls.VersionTLS12})
		_ = conn.SetDeadline(time.Now().Add(timeout))
		if err := conn.HandshakeContext(ctx); err != nil {
			return err
		}
		response, err := exchangeDNSStream(conn, query)
		if err != nil {
			return err
		}
		return validateDNSProbeResponse(response, queryID)
	case model.DNSTransportDoH:
		path := candidate.Path
		if path == "" {
			path = "/dns-query"
		}
		request, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://"+address+path, bytes.NewReader(query))
		if err != nil {
			return err
		}
		request.Header.Set("Content-Type", "application/dns-message")
		request.Header.Set("Accept", "application/dns-message")
		request.Host = candidate.Server
		tlsName := candidate.TLSName
		if tlsName == "" {
			tlsName = candidate.Server
		}
		transport := &http.Transport{Proxy: nil, TLSHandshakeTimeout: timeout, ResponseHeaderTimeout: timeout, DisableCompression: true, TLSClientConfig: &tls.Config{ServerName: tlsName, MinVersion: tls.VersionTLS12}}
		defer transport.CloseIdleConnections()
		client := &http.Client{Timeout: timeout, Transport: transport}
		response, err := client.Do(request)
		if err != nil {
			return err
		}
		defer response.Body.Close()
		if response.StatusCode != http.StatusOK {
			return fmt.Errorf("http status %d", response.StatusCode)
		}
		packet, err := io.ReadAll(io.LimitReader(response.Body, 4097))
		if err != nil {
			return err
		}
		if len(packet) > 4096 {
			return errors.New("dns response is too large")
		}
		return validateDNSProbeResponse(packet, queryID)
	case model.DNSTransportDoQ:
		name := candidate.TLSName
		if name == "" {
			name = candidate.Server
		}
		quicCtx, cancel := context.WithTimeout(ctx, timeout)
		defer cancel()
		conn, err := quic.DialAddr(quicCtx, address, &tls.Config{ServerName: name, NextProtos: []string{"doq"}, MinVersion: tls.VersionTLS13}, &quic.Config{HandshakeIdleTimeout: timeout, MaxIdleTimeout: timeout})
		if err != nil {
			return err
		}
		defer conn.CloseWithError(0, "dns benchmark complete")
		stream, err := conn.OpenStreamSync(quicCtx)
		if err != nil {
			return err
		}
		defer stream.Close()
		_ = stream.SetDeadline(time.Now().Add(timeout))
		doqQuery, err := buildDNSProbeQuery(0)
		if err != nil {
			return err
		}
		response, err := exchangeDNSStream(stream, doqQuery)
		if err != nil {
			return err
		}
		return validateDNSProbeResponse(response, 0)
	default:
		return fmt.Errorf("unsupported dns transport %q", candidate.Transport)
	}
}

func buildDNSProbeQuery(id uint16) ([]byte, error) {
	builder := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: id, RecursionDesired: true})
	if err := builder.StartQuestions(); err != nil {
		return nil, err
	}
	if err := builder.Question(dnsmessage.Question{Name: dnsmessage.MustNewName("example.com."), Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET}); err != nil {
		return nil, err
	}
	return builder.Finish()
}

func exchangeDNSStream(stream io.ReadWriter, query []byte) ([]byte, error) {
	if len(query) > 65535 {
		return nil, errors.New("dns query is too large")
	}
	packet := make([]byte, 2+len(query))
	binary.BigEndian.PutUint16(packet, uint16(len(query)))
	copy(packet[2:], query)
	if _, err := stream.Write(packet); err != nil {
		return nil, err
	}
	var length [2]byte
	if _, err := io.ReadFull(stream, length[:]); err != nil {
		return nil, err
	}
	size := int(binary.BigEndian.Uint16(length[:]))
	if size == 0 || size > 4096 {
		return nil, errors.New("dns response has invalid size")
	}
	response := make([]byte, size)
	_, err := io.ReadFull(stream, response)
	return response, err
}

func validateDNSProbeResponse(response []byte, id uint16) error {
	var parser dnsmessage.Parser
	header, err := parser.Start(response)
	if err != nil {
		return fmt.Errorf("parse dns response: %w", err)
	}
	if !header.Response {
		return errors.New("dns response flag is missing")
	}
	if header.ID != id {
		return errors.New("dns response id does not match query")
	}
	return nil
}

func newDNSBenchmarkReportID() string {
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err == nil {
		return hex.EncodeToString(raw[:])
	}
	return fmt.Sprintf("dns-%d", time.Now().UnixNano())
}

func (r *Runner) loadDNSBenchmarkState() (dnsBenchmarkLocalState, error) {
	state := dnsBenchmarkLocalState{LastRun: map[string]time.Time{}, Best: map[string]model.DNSBenchmarkGroup{}}
	data, err := os.ReadFile(r.dnsBenchmarkStatePath())
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return state, nil
		}
		return state, err
	}
	if err := json.Unmarshal(data, &state); err != nil {
		return dnsBenchmarkLocalState{LastRun: map[string]time.Time{}, Best: map[string]model.DNSBenchmarkGroup{}}, nil
	}
	if state.LastRun == nil {
		state.LastRun = map[string]time.Time{}
	}
	if state.Best == nil {
		state.Best = map[string]model.DNSBenchmarkGroup{}
	}
	return state, nil
}

func (r *Runner) saveDNSBenchmarkState(state dnsBenchmarkLocalState) error {
	if err := os.MkdirAll(r.stateDir(), 0o700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return err
	}
	return atomicWriteFile(r.dnsBenchmarkStatePath(), data, 0o600)
}

func (r *Runner) dnsBenchmarkStatePath() string {
	return filepath.Join(r.stateDir(), "dns-benchmark.json")
}
