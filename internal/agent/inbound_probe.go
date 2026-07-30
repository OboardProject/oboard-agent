package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/OboardProject/oboard-agent/internal/model"
)

const (
	defaultProbeSamples  = 5
	defaultProbeInterval = 300 * time.Millisecond
	defaultProbeTimeout  = 3 * time.Second
)

func (r *Runner) runInboundProbeTask(ctx context.Context, plan model.InboundProbePlan) ([]model.InboundProbeResult, error) {
	samples := clampProbeInt(plan.SampleCount, defaultProbeSamples, 1, 10)
	interval := time.Duration(clampProbeInt(plan.IntervalMS, int(defaultProbeInterval/time.Millisecond), 50, 5000)) * time.Millisecond
	timeout := time.Duration(clampProbeInt(plan.TimeoutMS, int(defaultProbeTimeout/time.Millisecond), 250, 10000)) * time.Millisecond
	results := make([]model.InboundProbeResult, 0, len(plan.EntryTargets))
	var firstErr error
	for _, target := range plan.EntryTargets {
		targetSamples := clampProbeInt(target.SampleCount, samples, 1, 10)
		result := probeLocalInbound(target, plan.Version, targetSamples, interval, timeout)
		results = append(results, result)
		if err := r.reportInboundProbe(ctx, result); err != nil && firstErr == nil {
			firstErr = err
		}
		if !result.Available && firstErr == nil {
			firstErr = errors.New(result.Error)
		}
	}
	return results, firstErr
}

func probeLocalInbound(target model.InboundProbeTarget, version int64, sampleCount int, interval, timeout time.Duration) model.InboundProbeResult {
	transport := strings.ToLower(strings.TrimSpace(target.Transport))
	if transport == "" {
		transport = inboundProbeTransport(target.Protocol)
	}
	host := localProbeHost(target.ListenIP)
	result := model.InboundProbeResult{
		InboundID: target.InboundID, ConfigVersion: version, Mode: "agent_listener",
		Transport: transport, Endpoint: net.JoinHostPort(host, fmt.Sprint(target.Port)),
		Confirmed: true, ResultJSON: "{}",
	}
	details := map[string]any{"name": target.Name, "protocol": target.Protocol, "listen_ip": target.ListenIP}

	if transport == "udp" {
		ok, err := udpPortBound(target.ListenIP, target.Port)
		result.Available = ok
		result.SampleCount = 1
		if ok {
			result.SuccessCount = 1
		} else if err != nil {
			result.Error = err.Error()
		} else {
			result.Error = "UDP 端口未监听"
		}
		details["udp_listener"] = ok
		result.ResultJSON = marshalProbeDetails(details)
		return result
	}

	latencies, failures := tcpProbeSamples(host, target.Port, sampleCount, interval, timeout)
	applyProbeStats(&result, latencies, sampleCount)
	result.Available = result.SuccessCount >= requiredProbeSuccesses(sampleCount)
	if len(failures) > 0 {
		details["failures"] = failures
	}
	if transport == "tcp_udp" {
		udpOK, udpErr := udpPortBound(target.ListenIP, target.Port)
		details["udp_listener"] = udpOK
		if udpErr != nil {
			details["udp_error"] = udpErr.Error()
		}
		result.Available = result.Available && udpOK
		if !udpOK && result.Error == "" {
			result.Error = "UDP 端口未监听"
		}
	}
	if !result.Available && result.Error == "" {
		result.Error = fmt.Sprintf("本机端口探测仅成功 %d/%d 次", result.SuccessCount, sampleCount)
	}
	details["latencies_ms"] = latencies
	result.ResultJSON = marshalProbeDetails(details)
	return result
}

func tcpProbeSamples(host string, port, count int, interval, timeout time.Duration) ([]int64, []string) {
	latencies := make([]int64, 0, count)
	failures := make([]string, 0)
	address := net.JoinHostPort(strings.Trim(host, "[]"), fmt.Sprint(port))
	for i := 0; i < count; i++ {
		started := time.Now()
		conn, err := net.DialTimeout("tcp", address, timeout)
		elapsed := time.Since(started).Milliseconds()
		if err != nil {
			failures = append(failures, err.Error())
		} else {
			latencies = append(latencies, elapsed)
			_ = conn.Close()
		}
		if i+1 < count {
			time.Sleep(interval)
		}
	}
	return latencies, failures
}

func applyProbeStats(result *model.InboundProbeResult, latencies []int64, total int) {
	result.SampleCount = total
	result.SuccessCount = len(latencies)
	if len(latencies) == 0 {
		return
	}
	var sum int64
	for _, value := range latencies {
		sum += value
	}
	result.LatencyMS = sum / int64(len(latencies))
	ordered := append([]int64(nil), latencies...)
	sort.Slice(ordered, func(i, j int) bool { return ordered[i] < ordered[j] })
	result.MinLatencyMS = ordered[0]
	p95Index := int(math.Ceil(float64(len(ordered))*0.95)) - 1
	if p95Index < 0 {
		p95Index = 0
	}
	result.P95LatencyMS = ordered[p95Index]
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

func udpPortBound(listenIP string, port int) (bool, error) {
	host := strings.TrimSpace(listenIP)
	if host == "" {
		host = "0.0.0.0"
	}
	ip := net.ParseIP(strings.Trim(host, "[]"))
	network := "udp4"
	if ip != nil && ip.To4() == nil {
		network = "udp6"
	}
	conn, err := net.ListenUDP(network, &net.UDPAddr{IP: ip, Port: port})
	if err != nil {
		if errors.Is(err, syscall.EADDRINUSE) || strings.Contains(strings.ToLower(err.Error()), "address already in use") {
			return true, nil
		}
		return false, err
	}
	_ = conn.Close()
	return false, nil
}

func localProbeHost(listenIP string) string {
	switch strings.TrimSpace(listenIP) {
	case "", "0.0.0.0":
		return "127.0.0.1"
	case "::", "[::]":
		return "::1"
	default:
		return strings.Trim(strings.TrimSpace(listenIP), "[]")
	}
}

func inboundProbeTransport(protocol model.Protocol) string {
	switch protocol {
	case model.ProtocolHY2:
		return "udp"
	case model.ProtocolSS:
		return "tcp_udp"
	default:
		return "tcp"
	}
}

func requiredProbeSuccesses(total int) int {
	return total/2 + 1
}

func clampProbeInt(value, fallback, minimum, maximum int) int {
	if value == 0 {
		value = fallback
	}
	if value < minimum {
		return minimum
	}
	if value > maximum {
		return maximum
	}
	return value
}

func marshalProbeDetails(value any) string {
	b, err := json.Marshal(value)
	if err != nil {
		return "{}"
	}
	return string(b)
}

func (r *Runner) reportInboundProbe(ctx context.Context, result model.InboundProbeResult) error {
	return r.postControllerJSON(ctx, "/api/v1/agent/inbound-probes", result, nil, true)
}
