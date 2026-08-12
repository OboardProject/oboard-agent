package agent

import (
	"context"
	"errors"
	"fmt"
	"math"
	"net"
	"net/netip"
	"os"
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
)

type latencyProbeSamplesFunc func(context.Context, string, int, time.Duration, time.Duration) ([]int64, []string)

var latencyProbeSequence atomic.Uint32

func (r *Runner) runLatencyProbeTask(ctx context.Context, plan model.LatencyProbeTargetsPlan) (model.LatencyProbeResultReport, error) {
	return r.runLatencyProbeTaskWithProbe(ctx, plan, icmpProbeSamplesContext)
}

func (r *Runner) runLatencyProbeTaskWithProbe(ctx context.Context, plan model.LatencyProbeTargetsPlan, probe latencyProbeSamplesFunc) (model.LatencyProbeResultReport, error) {
	if len(plan.Targets) == 0 {
		return model.LatencyProbeResultReport{ResourceVersion: plan.ResourceVersion, CheckedAt: time.Now().UTC(), Items: []model.LatencyProbeResult{}}, errors.New("区域延迟测试没有可用目标")
	}
	if len(plan.Targets) > latencyProbeMaxTargets {
		return model.LatencyProbeResultReport{}, fmt.Errorf("区域延迟测试目标不能超过 %d 个", latencyProbeMaxTargets)
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
		items[i] = model.LatencyProbeResult{ProbeID: target.ProbeID, Province: target.Province, Carrier: target.Carrier, IP: target.IP, SampleCount: samples, CheckedAt: time.Now().UTC()}
		if target.ProbeID == "" {
			items[i].Error = "目标标识无效"
			continue
		}
		addr, err := netip.ParseAddr(strings.TrimSpace(target.IP))
		if err != nil || !validLatencyProbeIPv4(addr) {
			items[i].Error = "目标必须是公网 IPv4 地址"
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
			latencies, failures := probe(batchCtx, addr.String(), samples, interval, timeout)
			applyLatencyStats(&items[i], latencies, samples)
			if len(failures) > 0 {
				items[i].Error = boundedLatencyProbeError(failures[0])
			}
			items[i].Available = items[i].SuccessCount > 0
			items[i].CheckedAt = time.Now().UTC()
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
	checkedAt := time.Now().UTC()
	return model.LatencyProbeResultReport{ResourceVersion: plan.ResourceVersion, CheckedAt: checkedAt, Items: items}, func() error {
		if failed > 0 {
			return fmt.Errorf("%d 个区域延迟测试目标失败", failed)
		}
		return nil
	}()
}

func validLatencyProbeIPv4(addr netip.Addr) bool {
	return addr.IsValid() && addr.Is4() && addr.IsGlobalUnicast() && !addr.IsPrivate() && !addr.IsLoopback() && !addr.IsLinkLocalUnicast() && !addr.IsLinkLocalMulticast() && !addr.IsMulticast() && !addr.IsUnspecified()
}

func icmpProbeSamplesContext(ctx context.Context, host string, count int, interval, timeout time.Duration) ([]int64, []string) {
	target := net.ParseIP(host)
	if target == nil || target.To4() == nil {
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
		if _, err := conn.WriteTo(payload, &net.IPAddr{IP: target}); err != nil {
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
			if !icmpPeerMatches(peer, target) {
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
