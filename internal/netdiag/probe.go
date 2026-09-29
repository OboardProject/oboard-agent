package netdiag

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"math"
	"net/netip"
	"time"

	"github.com/OboardProject/oboard-agent/internal/model"
)

var errReceiveTimeout = errors.New("receive timeout")

// probeTransport sends TTL-limited probes and receives ICMP replies on a raw
// ICMP socket. Implementations never run external programs.
type probeTransport interface {
	SendEcho(dst netip.Addr, id, seq, ttl, size int) error
	// SendUDP sends one datagram from a fresh ephemeral port and returns it.
	SendUDP(dst netip.Addr, port, ttl int) (int, error)
	Receive(deadline time.Time) (reply, time.Time, error)
	Close() error
}

type transportFactory func(v6 bool) (probeTransport, error)

// tcpProbeOutcome is one TTL-limited TCP connection attempt.
type tcpProbeOutcome struct {
	reached bool
	from    netip.Addr
	rtt     time.Duration
	timeout bool
}

// tcpTracer performs one TCP trace probe, using the transport to observe the
// ICMP time-exceeded answer that names the router at that TTL.
type tcpTracer func(ctx context.Context, transport probeTransport, dst netip.Addr, port, ttl int, timeout time.Duration) (tcpProbeOutcome, error)

func randomID() int {
	var buf [2]byte
	_, _ = rand.Read(buf[:])
	return int(binary.BigEndian.Uint16(buf[:]))
}

func sleepContext(ctx context.Context, d time.Duration) error {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func invalid(message string) error { return fail(model.NetworkDiagnosticCodeInvalidInput, message) }

// ValidatePing enforces the shared bounds independently of the Controller.
func ValidatePing(p model.NetworkPingTaskPayload) error {
	switch {
	case !validFamily(p.IPFamily):
		return invalid("ip_family must be auto, ipv4 or ipv6")
	case p.Count < 1 || p.Count > model.PingMaxCount:
		return invalid("count is out of range")
	case p.IntervalMS < model.PingMinIntervalMS || p.IntervalMS > model.PingMaxIntervalMS:
		return invalid("interval_ms is out of range")
	case p.TimeoutMS < model.PingMinTimeoutMS || p.TimeoutMS > model.PingMaxTimeoutMS:
		return invalid("timeout_ms is out of range")
	case p.PacketSize < 0 || p.PacketSize > model.PingMaxPacketSize:
		return invalid("packet_size is out of range")
	case p.Count*p.IntervalMS+p.TimeoutMS > model.NetworkDiagnosticMaxDurationMS:
		return invalid("ping would exceed the diagnostic time budget")
	}
	return nil
}

// Ping sends ICMP echo requests and matches replies by identifier, sequence
// and source address.
func Ping(ctx context.Context, resolver Resolver, open transportFactory, p model.NetworkPingTaskPayload) (model.NetworkPingResult, error) {
	result := model.NetworkPingResult{OperationID: p.OperationID, Target: p.Target, Samples: []model.NetworkPingSample{}}
	if err := ValidatePing(p); err != nil {
		return result, err
	}
	ip, err := ResolveTarget(ctx, resolver, p.Target, p.IPFamily)
	if err != nil {
		return result, err
	}
	result.ResolvedIP, result.IPFamily = ip.String(), familyName(ip)
	transport, err := open(ip.Is6())
	if err != nil {
		return result, err
	}
	defer transport.Close()
	id := randomID()
	var rtts []float64
	for seq := 1; seq <= p.Count; seq++ {
		if ctx.Err() != nil {
			break
		}
		sample := model.NetworkPingSample{Seq: seq, Timeout: true}
		sent := time.Now()
		if err := transport.SendEcho(ip, id, seq, 64, p.PacketSize); err != nil {
			return result, fail(model.NetworkDiagnosticCodeFailed, "cannot send ICMP echo")
		}
		result.Sent++
		deadline := sent.Add(time.Duration(p.TimeoutMS) * time.Millisecond)
		for {
			got, at, err := transport.Receive(deadline)
			if err != nil {
				break
			}
			if got.kind == replyEcho && got.from == ip && got.id == id && got.seq == seq {
				rtt := roundMS(at.Sub(sent))
				sample.RTTMS, sample.Timeout = rtt, false
				rtts = append(rtts, rtt)
				result.Received++
				break
			}
		}
		result.Samples = append(result.Samples, sample)
		if seq < p.Count {
			if sleepContext(ctx, time.Duration(p.IntervalMS)*time.Millisecond) != nil {
				break
			}
		}
	}
	if result.Sent > 0 {
		result.LossPercent = math.Round(float64(result.Sent-result.Received)/float64(result.Sent)*1000) / 10
	}
	if len(rtts) > 0 {
		minRTT, maxRTT, sum := math.MaxFloat64, 0.0, 0.0
		for _, rtt := range rtts {
			minRTT, maxRTT, sum = math.Min(minRTT, rtt), math.Max(maxRTT, rtt), sum+rtt
		}
		result.MinRTTMS, result.MaxRTTMS, result.AvgRTTMS = minRTT, maxRTT, math.Round(sum/float64(len(rtts))*1000)/1000
	}
	return result, nil
}

func roundMS(d time.Duration) float64 {
	return math.Round(float64(d)/float64(time.Millisecond)*1000) / 1000
}

// ValidateTrace enforces the shared bounds independently of the Controller.
func ValidateTrace(p model.NetworkTraceTaskPayload) error {
	switch {
	case !validFamily(p.IPFamily):
		return invalid("ip_family must be auto, ipv4 or ipv6")
	case p.Mode != model.TraceModeICMP && p.Mode != model.TraceModeUDP && p.Mode != model.TraceModeTCP:
		return invalid("mode must be icmp, udp or tcp")
	case p.Mode == model.TraceModeICMP && p.Port != 0:
		return invalid("port is only valid for udp and tcp traces")
	case p.Mode != model.TraceModeICMP && (p.Port < 1 || p.Port > 65535):
		return invalid("port is out of range")
	case p.MaxHops < 1 || p.MaxHops > model.TraceMaxHops:
		return invalid("max_hops is out of range")
	case p.QueriesPerHop < 1 || p.QueriesPerHop > model.TraceMaxQueriesPerHop:
		return invalid("queries_per_hop is out of range")
	case p.PerHopTimeoutMS < model.TraceMinHopTimeoutMS || p.PerHopTimeoutMS > model.TraceMaxHopTimeoutMS:
		return invalid("per_hop_timeout_ms is out of range")
	}
	return nil
}

// Trace walks the path with increasing TTL. It stops at the target, at
// max_hops, or when the total trace budget is spent (truncated=true).
func Trace(ctx context.Context, resolver Resolver, open transportFactory, tcp tcpTracer, p model.NetworkTraceTaskPayload) (model.NetworkTraceResult, error) {
	started := time.Now()
	result := model.NetworkTraceResult{OperationID: p.OperationID, Target: p.Target, Mode: p.Mode, Port: p.Port, StartedAt: started.UTC(), Hops: []model.NetworkTraceHop{}}
	if err := ValidateTrace(p); err != nil {
		return result, err
	}
	ip, err := ResolveTarget(ctx, resolver, p.Target, p.IPFamily)
	if err != nil {
		return result, err
	}
	result.ResolvedIP, result.IPFamily = ip.String(), familyName(ip)
	if p.Mode == model.TraceModeTCP && tcp == nil {
		return result, ErrUnsupported
	}
	transport, err := open(ip.Is6())
	if err != nil {
		return result, err
	}
	defer transport.Close()
	budget := started.Add(time.Duration(model.TraceMaxDurationMS) * time.Millisecond)
	if deadline, ok := ctx.Deadline(); ok && deadline.Before(budget) {
		budget = deadline
	}
	perHop := time.Duration(p.PerHopTimeoutMS) * time.Millisecond
	id := randomID()
hops:
	for ttl := 1; ttl <= p.MaxHops; ttl++ {
		hop := model.NetworkTraceHop{Hop: ttl, Addresses: []string{}, Probes: []model.NetworkTraceProbe{}}
		reached := false
		for query := 0; query < p.QueriesPerHop; query++ {
			if ctx.Err() != nil || time.Now().Add(perHop).After(budget) {
				result.Truncated = true
				if len(hop.Probes) > 0 {
					result.Hops = append(result.Hops, finishHop(hop))
				}
				break hops
			}
			probe, hit, err := traceProbe(ctx, transport, tcp, p, ip, id, ttl, query, perHop)
			if err != nil {
				return result, err
			}
			hop.Probes = append(hop.Probes, probe)
			reached = reached || hit
		}
		result.Hops = append(result.Hops, finishHop(hop))
		if reached {
			result.Reached = true
			break
		}
	}
	result.DurationMS = time.Since(started).Milliseconds()
	return result, nil
}

func finishHop(hop model.NetworkTraceHop) model.NetworkTraceHop {
	seen := map[string]bool{}
	for _, probe := range hop.Probes {
		if probe.Address != "" && !seen[probe.Address] && len(hop.Addresses) < model.TraceMaxQueriesPerHop {
			seen[probe.Address] = true
			hop.Addresses = append(hop.Addresses, probe.Address)
		}
	}
	return hop
}

func traceProbe(ctx context.Context, transport probeTransport, tcp tcpTracer, p model.NetworkTraceTaskPayload, ip netip.Addr, id, ttl, query int, timeout time.Duration) (model.NetworkTraceProbe, bool, error) {
	timedOut := model.NetworkTraceProbe{Timeout: true}
	sent := time.Now()
	deadline := sent.Add(timeout)
	switch p.Mode {
	case model.TraceModeTCP:
		outcome, err := tcp(ctx, transport, ip, p.Port, ttl, timeout)
		if err != nil {
			return timedOut, false, err
		}
		if outcome.timeout || !outcome.from.IsValid() {
			return timedOut, false, nil
		}
		return model.NetworkTraceProbe{Address: outcome.from.String(), RTTMS: roundMS(outcome.rtt)}, outcome.reached, nil
	case model.TraceModeUDP:
		srcPort, err := transport.SendUDP(ip, p.Port, ttl)
		if err != nil {
			return timedOut, false, fail(model.NetworkDiagnosticCodeFailed, "cannot send UDP probe")
		}
		for {
			got, at, err := transport.Receive(deadline)
			if err != nil {
				return timedOut, false, nil
			}
			if got.proto != protocolUDP || got.srcPort != srcPort || got.dstPort != p.Port || got.innerDst != ip {
				continue
			}
			reached := got.kind == replyUnreachable && got.from == ip
			if got.kind == replyTimeExceeded || reached {
				return model.NetworkTraceProbe{Address: got.from.String(), RTTMS: roundMS(at.Sub(sent))}, reached, nil
			}
		}
	default:
		seq := (ttl << 2) | query
		if err := transport.SendEcho(ip, id, seq, ttl, 32); err != nil {
			return timedOut, false, fail(model.NetworkDiagnosticCodeFailed, "cannot send ICMP probe")
		}
		for {
			got, at, err := transport.Receive(deadline)
			if err != nil {
				return timedOut, false, nil
			}
			if got.id != id || got.seq != seq {
				continue
			}
			switch {
			case got.kind == replyEcho && got.from == ip:
				return model.NetworkTraceProbe{Address: got.from.String(), RTTMS: roundMS(at.Sub(sent))}, true, nil
			case got.kind == replyTimeExceeded && got.innerDst == ip:
				return model.NetworkTraceProbe{Address: got.from.String(), RTTMS: roundMS(at.Sub(sent))}, false, nil
			case got.kind == replyUnreachable && got.innerDst == ip:
				return model.NetworkTraceProbe{Address: got.from.String(), RTTMS: roundMS(at.Sub(sent))}, got.from == ip, nil
			}
		}
	}
}
