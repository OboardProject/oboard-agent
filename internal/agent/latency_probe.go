package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"math"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/OboardProject/oboard-agent/internal/model"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
)

const (
	latencyProbeMaxTargets     = 256
	latencyProbeMaxConcurrency = 16
	latencyProbeBatchTimeout   = 90 * time.Second
	latencyProbeStateFile      = "latency-probe.json"
	latencyProbeMaxPending     = 2048
	latencyProbeRetention      = 35 * 24 * time.Hour
)

type latencyProbeSamplesFunc func(context.Context, string, int, int, time.Duration, time.Duration) ([]int64, []string)

type latencyProbeLocalState struct {
	Plan      model.LatencyProbeTargetsPlan    `json:"plan"`
	LastRunAt time.Time                        `json:"last_run_at"`
	Pending   []model.LatencyProbeResultReport `json:"pending"`
}

var latencyProbeSequence atomic.Uint32

func (r *Runner) runLatencyProbeTask(ctx context.Context, plan model.LatencyProbeTargetsPlan) (model.LatencyProbeResultReport, error) {
	probe := tcpProbeSamplesContext
	if plan.Mode == model.LatencyProbeModeICMP {
		probe = icmpProbeSamplesContext
	}
	return r.runLatencyProbeTaskWithProbe(ctx, plan, probe)
}

func (r *Runner) runLatencyProbeTaskWithProbe(ctx context.Context, plan model.LatencyProbeTargetsPlan, probe latencyProbeSamplesFunc) (model.LatencyProbeResultReport, error) {
	now := func() time.Time {
		if r != nil && r.clock != nil {
			return r.clock.Now().UTC()
		}
		return time.Now().UTC()
	}
	if len(plan.Targets) == 0 {
		return model.LatencyProbeResultReport{ResourceVersion: plan.ResourceVersion, CheckedAt: now(), Items: []model.LatencyProbeResult{}}, errors.New("延迟测试没有可用目标")
	}
	if len(plan.Targets) > latencyProbeMaxTargets {
		return model.LatencyProbeResultReport{}, fmt.Errorf("延迟测试目标不能超过 %d 个", latencyProbeMaxTargets)
	}
	samples := plan.SampleCount
	if samples < 1 || samples > 10 {
		samples = 3
	}
	interval := time.Duration(plan.IntervalMS) * time.Millisecond
	if interval < 25*time.Millisecond || interval > 5*time.Second {
		interval = 150 * time.Millisecond
	}
	timeout := time.Duration(plan.TimeoutMS) * time.Millisecond
	if timeout < 100*time.Millisecond || timeout > 10*time.Second {
		timeout = 3 * time.Second
	}
	batchCtx, cancel := context.WithTimeout(ctx, latencyProbeBatchTimeout)
	defer cancel()
	items := make([]model.LatencyProbeResult, len(plan.Targets))
	sem := make(chan struct{}, latencyProbeMaxConcurrency)
	var wg sync.WaitGroup
	for i, target := range plan.Targets {
		i, target := i, target
		port := target.Port
		if plan.Mode == model.LatencyProbeModeICMP {
			port = 0
		}
		items[i] = model.LatencyProbeResult{ProbeID: target.ProbeID, Kind: target.Kind, Mode: string(plan.Mode), Province: target.Province, Carrier: target.Carrier, Host: target.Host, IP: target.IP, Port: port, SampleCount: samples, CheckedAt: now()}
		if err := validateLatencyProbeTarget(target, plan.Mode); err != nil {
			items[i].Error = err.Error()
			continue
		}
		if target.ProbeID == "" {
			items[i].Error = "目标标识无效"
			continue
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			select {
			case sem <- struct{}{}:
				defer func() { <-sem }()
			case <-batchCtx.Done():
				items[i].Error = "测试等待超时"
				return
			}
			latencies, failures := probe(batchCtx, target.Host, target.Port, samples, interval, timeout)
			applyLatencyStats(&items[i], latencies, samples)
			if len(failures) > 0 {
				items[i].Error = boundedLatencyProbeError(failures[0])
			}
			items[i].Available = items[i].SuccessCount > 0
			items[i].CheckedAt = now()
		}()
	}
	wg.Wait()
	failed := 0
	for i := range items {
		if !items[i].Available {
			failed++
			if items[i].Error == "" {
				items[i].Error = "目标不可达"
			}
		}
	}
	checkedAt := now()
	return model.LatencyProbeResultReport{ReportID: newLatencyProbeReportID(r.Config().AgentID, checkedAt), ResourceVersion: plan.ResourceVersion, CheckedAt: checkedAt, Items: items}, func() error {
		if failed > 0 {
			return fmt.Errorf("%d 个延迟测试目标失败", failed)
		}
		return nil
	}()
}

func validateLatencyProbeTarget(target model.LatencyProbeTarget, mode model.LatencyProbeMode) error {
	if strings.TrimSpace(target.ProbeID) == "" {
		return errors.New("目标标识无效")
	}
	host := strings.TrimSpace(target.Host)
	switch target.Kind {
	case "public":
		if host != "cp.cloudflare.com" && host != "www.12306.cn" && host != "www.gstatic.com" {
			return errors.New("公网延迟目标无效")
		}
	case "regional":
		addr, err := netip.ParseAddr(host)
		if err != nil || !validLatencyProbeIPv4(addr) || strings.TrimSpace(target.IP) != addr.String() || strings.TrimSpace(target.Province) == "" || strings.TrimSpace(target.Carrier) == "" {
			return errors.New("地区目标必须是公网 IPv4 地址")
		}
	default:
		return errors.New("延迟目标类型无效")
	}
	if mode != model.LatencyProbeModeTCP && mode != model.LatencyProbeModeICMP {
		return errors.New("延迟测试方式无效")
	}
	if mode == model.LatencyProbeModeTCP && (target.Port < 1 || target.Port > 65535) {
		return errors.New("TCP 延迟目标端口无效")
	}
	return nil
}

func validLatencyProbeIPv4(addr netip.Addr) bool {
	return addr.IsValid() && addr.Is4() && addr.IsGlobalUnicast() && !addr.IsPrivate() && !addr.IsLoopback() && !addr.IsLinkLocalUnicast() && !addr.IsLinkLocalMulticast() && !addr.IsMulticast() && !addr.IsUnspecified()
}

func icmpProbeSamplesContext(ctx context.Context, host string, _ int, count int, interval, timeout time.Duration) ([]int64, []string) {
	target, err := resolveLatencyProbeIPv4(ctx, host)
	if err != nil {
		return nil, []string{"目标必须是公网 IPv4 地址"}
	}
	conn, err := icmp.ListenPacket("ip4:icmp", "0.0.0.0")
	if err != nil {
		return nil, []string{"当前环境不允许执行 ICMP 延迟测试"}
	}
	defer conn.Close()
	id := int((uint32(os.Getpid()) + latencyProbeSequence.Add(1)) & 0xffff)
	latencies := make([]int64, 0, count)
	failures := make([]string, 0, count)
	for i := 0; i < count; i++ {
		if ctx.Err() != nil {
			failures = append(failures, "测试已取消")
			break
		}
		sequence := int(latencyProbeSequence.Add(1) & 0xffff)
		message := icmp.Message{Type: ipv4.ICMPTypeEcho, Code: 0, Body: &icmp.Echo{ID: id, Seq: sequence, Data: []byte("oboard-latency")}}
		payload, marshalErr := message.Marshal(nil)
		if marshalErr != nil {
			failures = append(failures, "无法创建 ICMP 测试请求")
			continue
		}
		started := time.Now()
		deadline := started.Add(timeout)
		if contextDeadline, ok := ctx.Deadline(); ok && contextDeadline.Before(deadline) {
			deadline = contextDeadline
		}
		if err := conn.SetDeadline(deadline); err != nil {
			failures = append(failures, "无法设置 ICMP 测试超时")
			continue
		}
		if _, err := conn.WriteTo(payload, &net.IPAddr{IP: net.IP(target.AsSlice())}); err != nil {
			failures = append(failures, "无法发送 ICMP 测试请求")
			continue
		}
		buffer := make([]byte, 1500)
		matched := false
		for !matched {
			n, peer, readErr := conn.ReadFrom(buffer)
			if readErr != nil {
				if ctx.Err() != nil {
					failures = append(failures, "测试已取消")
				} else {
					failures = append(failures, "目标未响应")
				}
				break
			}
			if !icmpPeerMatches(peer, net.IP(target.AsSlice())) {
				continue
			}
			reply, parseErr := icmp.ParseMessage(1, buffer[:n])
			if parseErr != nil || reply.Type != ipv4.ICMPTypeEchoReply {
				continue
			}
			echo, ok := reply.Body.(*icmp.Echo)
			if !ok || echo.ID != id || echo.Seq != sequence {
				continue
			}
			latencies = append(latencies, time.Since(started).Milliseconds())
			matched = true
		}
		if i+1 < count {
			timer := time.NewTimer(interval)
			select {
			case <-timer.C:
			case <-ctx.Done():
				if !timer.Stop() {
					select {
					case <-timer.C:
					default:
					}
				}
				failures = append(failures, "测试已取消")
				return latencies, failures
			}
		}
	}
	return latencies, failures
}

func tcpProbeSamplesContext(ctx context.Context, host string, port, count int, interval, timeout time.Duration) ([]int64, []string) {
	if port < 1 || port > 65535 {
		return nil, []string{"TCP 延迟目标端口无效"}
	}
	if _, err := resolveLatencyProbeIPv4(ctx, host); err != nil {
		return nil, []string{"目标必须解析到公网 IPv4 地址"}
	}
	latencies := make([]int64, 0, count)
	failures := make([]string, 0, count)
	dialer := net.Dialer{Timeout: timeout}
	address := net.JoinHostPort(host, fmt.Sprintf("%d", port))
	for index := 0; index < count; index++ {
		started := time.Now()
		conn, err := dialer.DialContext(ctx, "tcp4", address)
		if err != nil {
			if ctx.Err() != nil {
				failures = append(failures, "测试已取消")
			} else {
				failures = append(failures, "目标未响应")
			}
		} else {
			latencies = append(latencies, time.Since(started).Milliseconds())
			_ = conn.Close()
		}
		if index+1 < count {
			timer := time.NewTimer(interval)
			select {
			case <-timer.C:
			case <-ctx.Done():
				if !timer.Stop() {
					select {
					case <-timer.C:
					default:
					}
				}
				return latencies, append(failures, "测试已取消")
			}
		}
	}
	return latencies, failures
}

func resolveLatencyProbeIPv4(ctx context.Context, host string) (netip.Addr, error) {
	host = strings.TrimSpace(host)
	if addr, err := netip.ParseAddr(host); err == nil {
		if validLatencyProbeIPv4(addr) {
			return addr, nil
		}
		return netip.Addr{}, errors.New("not a public IPv4 address")
	}
	addresses, err := net.DefaultResolver.LookupNetIP(ctx, "ip4", host)
	if err != nil {
		return netip.Addr{}, err
	}
	for _, addr := range addresses {
		if validLatencyProbeIPv4(addr) {
			return addr, nil
		}
	}
	return netip.Addr{}, errors.New("hostname has no public IPv4 address")
}

func newLatencyProbeReportID(agentID string, checkedAt time.Time) string {
	return fmt.Sprintf("%s-latency-%d-%d", strings.TrimSpace(agentID), checkedAt.UnixNano(), latencyProbeSequence.Add(1))
}

func (r *Runner) latencyProbeStatePath() string {
	return filepath.Join(r.stateDir(), latencyProbeStateFile)
}

func (r *Runner) loadLatencyProbeStateLocked() {
	if r.latencyProbeStateLoaded {
		return
	}
	r.latencyProbeStateLoaded = true
	data, err := os.ReadFile(r.latencyProbeStatePath())
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			log.Printf("读取延迟测试本地状态失败: %v", err)
		}
		return
	}
	var state latencyProbeLocalState
	if err := json.Unmarshal(data, &state); err != nil {
		log.Printf("延迟测试本地状态无效: %v", err)
		return
	}
	r.latencyProbeState = state
	r.pruneLatencyProbeStateLocked(time.Now().UTC())
}

func (r *Runner) persistLatencyProbeStateLocked() error {
	if err := os.MkdirAll(r.stateDir(), 0o700); err != nil {
		return err
	}
	data, err := json.Marshal(r.latencyProbeState)
	if err != nil {
		return err
	}
	return atomicWriteFile(r.latencyProbeStatePath(), data, 0o600)
}

func (r *Runner) pruneLatencyProbeStateLocked(now time.Time) {
	cutoff := now.Add(-latencyProbeRetention)
	pending := r.latencyProbeState.Pending[:0]
	for _, report := range r.latencyProbeState.Pending {
		if report.CheckedAt.Before(cutoff) {
			continue
		}
		pending = append(pending, report)
	}
	if len(pending) > latencyProbeMaxPending {
		pending = pending[len(pending)-latencyProbeMaxPending:]
	}
	r.latencyProbeState.Pending = pending
}

func (r *Runner) setLatencyProbePlan(plan model.LatencyProbeTargetsPlan) error {
	if plan.Version <= 0 || strings.TrimSpace(plan.ResourceVersion) == "" {
		return errors.New("延迟测试计划版本无效")
	}
	if plan.IntervalSeconds < 30 || plan.IntervalSeconds > 86400 {
		return errors.New("延迟测试间隔无效")
	}
	if plan.Mode != model.LatencyProbeModeTCP && plan.Mode != model.LatencyProbeModeICMP {
		return errors.New("延迟测试方式无效")
	}
	if len(plan.Targets) == 0 || len(plan.Targets) > latencyProbeMaxTargets {
		return errors.New("延迟测试目标数量无效")
	}
	for _, target := range plan.Targets {
		if err := validateLatencyProbeTarget(target, plan.Mode); err != nil {
			return err
		}
	}
	r.latencyProbeMu.Lock()
	defer r.latencyProbeMu.Unlock()
	r.loadLatencyProbeStateLocked()
	current, _ := json.Marshal(r.latencyProbeState.Plan)
	next, _ := json.Marshal(plan)
	if r.latencyProbeState.Plan.Version > plan.Version {
		return errors.New("延迟测试计划版本早于当前版本")
	}
	if r.latencyProbeState.Plan.Version == plan.Version && string(current) != string(next) {
		return errors.New("延迟测试计划版本对应的内容不一致")
	}
	if string(current) == string(next) {
		return nil
	}
	previous := r.latencyProbeState
	r.latencyProbeState.Plan = plan
	r.latencyProbeState.LastRunAt = time.Time{}
	if err := r.persistLatencyProbeStateLocked(); err != nil {
		r.latencyProbeState = previous
		return err
	}
	return nil
}

func (r *Runner) startLatencyProbeLoop(ctx context.Context) {
	go func() {
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case now := <-ticker.C:
				r.runLatencyProbeIfDue(ctx, now.UTC())
			}
		}
	}()
}

func (r *Runner) runLatencyProbeIfDue(ctx context.Context, now time.Time) {
	r.latencyProbeMu.Lock()
	r.loadLatencyProbeStateLocked()
	plan := r.latencyProbeState.Plan
	if !plan.Enabled || len(plan.Targets) == 0 || (!r.latencyProbeState.LastRunAt.IsZero() && now.Sub(r.latencyProbeState.LastRunAt) < time.Duration(plan.IntervalSeconds)*time.Second) {
		r.latencyProbeMu.Unlock()
		return
	}
	previousRunAt := r.latencyProbeState.LastRunAt
	r.latencyProbeState.LastRunAt = now
	if err := r.persistLatencyProbeStateLocked(); err != nil {
		r.latencyProbeState.LastRunAt = previousRunAt
		r.latencyProbeMu.Unlock()
		log.Printf("保存延迟测试执行时间失败: %v", err)
		return
	}
	r.latencyProbeMu.Unlock()

	report, _ := r.runLatencyProbeTask(ctx, plan)
	if len(report.Items) == 0 || report.ReportID == "" {
		return
	}
	if err := r.queueLatencyProbeReport(report, now); err != nil {
		log.Printf("保存延迟测试待补报结果失败: %v", err)
	}
}

func (r *Runner) queueLatencyProbeReport(report model.LatencyProbeResultReport, now time.Time) error {
	r.latencyProbeMu.Lock()
	defer r.latencyProbeMu.Unlock()
	r.loadLatencyProbeStateLocked()
	previous := r.latencyProbeState
	previous.Pending = append([]model.LatencyProbeResultReport(nil), r.latencyProbeState.Pending...)
	r.latencyProbeState.Pending = append(r.latencyProbeState.Pending, report)
	r.pruneLatencyProbeStateLocked(now)
	if err := r.persistLatencyProbeStateLocked(); err != nil {
		r.latencyProbeState = previous
		return err
	}
	return nil
}

func (r *Runner) nextPendingLatencyProbeReport() (model.LatencyProbeResultReport, bool) {
	r.latencyProbeMu.Lock()
	defer r.latencyProbeMu.Unlock()
	r.loadLatencyProbeStateLocked()
	if len(r.latencyProbeState.Pending) == 0 {
		return model.LatencyProbeResultReport{}, false
	}
	return r.latencyProbeState.Pending[0], true
}

func (r *Runner) ackLatencyProbeReport(reportID string) error {
	r.latencyProbeMu.Lock()
	defer r.latencyProbeMu.Unlock()
	r.loadLatencyProbeStateLocked()
	previous := append([]model.LatencyProbeResultReport(nil), r.latencyProbeState.Pending...)
	pending := r.latencyProbeState.Pending[:0]
	for _, report := range r.latencyProbeState.Pending {
		if report.ReportID != reportID {
			pending = append(pending, report)
		}
	}
	r.latencyProbeState.Pending = pending
	if err := r.persistLatencyProbeStateLocked(); err != nil {
		r.latencyProbeState.Pending = previous
		return err
	}
	return nil
}

func icmpPeerMatches(peer net.Addr, target net.IP) bool {
	switch value := peer.(type) {
	case *net.IPAddr:
		return value.IP.Equal(target)
	case *net.UDPAddr:
		return value.IP.Equal(target)
	default:
		return strings.TrimSpace(peer.String()) == target.String()
	}
}

func applyLatencyStats(result *model.LatencyProbeResult, latencies []int64, total int) {
	result.SampleCount = total
	result.SuccessCount = len(latencies)
	if len(latencies) == 0 {
		return
	}
	ordered := append([]int64(nil), latencies...)
	sort.Slice(ordered, func(i, j int) bool { return ordered[i] < ordered[j] })
	var sum int64
	for _, value := range ordered {
		sum += value
	}
	result.LatencyMS = sum / int64(len(ordered))
	result.MinLatencyMS = ordered[0]
	p95 := int(math.Ceil(float64(len(ordered))*0.95)) - 1
	if p95 < 0 {
		p95 = 0
	}
	if p95 >= len(ordered) {
		p95 = len(ordered) - 1
	}
	result.P95LatencyMS = ordered[p95]
	if len(latencies) > 1 {
		var delta int64
		for i := 1; i < len(latencies); i++ {
			d := latencies[i] - latencies[i-1]
			if d < 0 {
				d = -d
			}
			delta += d
		}
		result.JitterMS = delta / int64(len(latencies)-1)
	}
}

func boundedLatencyProbeError(message string) string {
	message = strings.TrimSpace(message)
	if len(message) > 240 {
		message = message[:240]
	}
	return message
}
