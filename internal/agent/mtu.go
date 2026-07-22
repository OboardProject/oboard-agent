package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os/exec"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/OboardProject/oboard-agent/internal/core"
	"github.com/OboardProject/oboard-agent/internal/model"
)

func (r *Runner) runMTUDetectionTask(ctx context.Context, plan model.MTUDetectionPlan) (map[string]any, error) {
	plan = normalizeMTUPlan(plan)
	result := model.MTUDetectionResult{ServerID: plan.ServerID, Mode: plan.Mode, TargetHost: plan.TargetHost, TargetPort: plan.TargetPort}
	methods := make([]model.MTUDetectionMethod, 0, 5)

	iface, localIP, err := egressInterface(ctx, plan.TargetHost, plan.TargetPort, plan.InterfaceName, time.Duration(plan.TimeoutMS)*time.Millisecond)
	if err != nil {
		methods = append(methods, model.MTUDetectionMethod{Name: "egress_interface", Available: false, Error: err.Error()})
	} else {
		result.InterfaceName = iface.Name
		result.CurrentMTU = iface.MTU
		methods = append(methods, model.MTUDetectionMethod{Name: "egress_interface", Available: true, MTU: iface.MTU, Detail: "local_ip=" + localIP})
	}

	if route := routeMTU(plan.TargetHost, time.Duration(plan.TimeoutMS)*time.Millisecond); route.Available || route.Error != "" {
		methods = append(methods, route)
		if result.InterfaceName == "" && strings.HasPrefix(route.Detail, "dev=") {
			result.InterfaceName = strings.TrimPrefix(route.Detail, "dev=")
		}
	}

	if trace := tracepathMTU(plan.TargetHost, time.Duration(plan.TimeoutMS)*time.Millisecond); trace.Available || trace.Error != "" {
		methods = append(methods, trace)
	}

	if ping := pingDFMTU(plan.TargetHost, plan.MinMTU, maxProbeMTU(plan, result.CurrentMTU), plan.SampleCount, time.Duration(plan.TimeoutMS)*time.Millisecond); ping.Available || ping.Error != "" {
		methods = append(methods, ping)
	}

	tcp := tcpConnectMTU(ctx, plan.TargetHost, plan.TargetPort, time.Duration(plan.TimeoutMS)*time.Millisecond)
	methods = append(methods, tcp)

	pathMTU := choosePathMTU(methods)
	result.PathMTU = pathMTU
	result.RecommendedMTU = recommendMTU(result.CurrentMTU, pathMTU, plan.OverheadBytes, plan.MinMTU, plan.MaxMTU)
	if plan.DesiredMTU > 0 {
		result.RecommendedMTU = clampMTU(plan.DesiredMTU, plan.MinMTU, plan.MaxMTU)
	}
	result.Confidence = mtuConfidence(methods, result.CurrentMTU, result.PathMTU)
	result.Methods = methods

	if plan.Mode == model.MTUModeApply {
		applied, applyErr := applyInterfaceMTU(result.InterfaceName, result.RecommendedMTU, r.commandTimeout())
		if applyErr != nil {
			result.Error = applyErr.Error()
		} else {
			result.AppliedMTU = applied
		}
	}

	resultJSON, err := json.Marshal(map[string]any{"version": plan.Version, "overhead_bytes": plan.OverheadBytes, "desired_mtu": plan.DesiredMTU, "methods": methods})
	if err != nil {
		return nil, err
	}
	result.ResultJSON = string(resultJSON)
	out := map[string]any{
		"server_id":       result.ServerID,
		"mode":            result.Mode,
		"target_host":     result.TargetHost,
		"target_port":     result.TargetPort,
		"interface_name":  result.InterfaceName,
		"current_mtu":     result.CurrentMTU,
		"path_mtu":        result.PathMTU,
		"recommended_mtu": result.RecommendedMTU,
		"applied_mtu":     result.AppliedMTU,
		"confidence":      result.Confidence,
		"error":           result.Error,
		"methods":         methods,
	}
	if reportErr := r.postControllerJSON(ctx, "/api/v1/agent/mtu-detections", result, nil, true); reportErr != nil {
		out["report_error"] = reportErr.Error()
		if result.Error == "" || plan.Mode != model.MTUModeApply {
			return out, reportErr
		}
	}
	if result.Error != "" && plan.Mode == model.MTUModeApply {
		return out, errors.New(result.Error)
	}
	return out, nil
}

func normalizeMTUPlan(plan model.MTUDetectionPlan) model.MTUDetectionPlan {
	if plan.Mode == "" || plan.Mode == model.MTUModeDisabled {
		plan.Mode = model.MTUModeDetect
	}
	if strings.TrimSpace(plan.TargetHost) == "" {
		plan.TargetHost = "1.1.1.1"
	}
	if plan.TargetPort <= 0 {
		plan.TargetPort = 443
	}
	if plan.SampleCount <= 0 || plan.SampleCount > 5 {
		plan.SampleCount = 3
	}
	if plan.TimeoutMS <= 0 || plan.TimeoutMS > 5000 {
		plan.TimeoutMS = 1200
	}
	if plan.MinMTU <= 0 {
		plan.MinMTU = 1280
	}
	if plan.MaxMTU <= 0 || plan.MaxMTU > 9000 {
		plan.MaxMTU = 9000
	}
	if plan.OverheadBytes < 0 {
		plan.OverheadBytes = 0
	}
	return plan
}

func egressInterface(ctx context.Context, host string, port int, preferred string, timeout time.Duration) (*net.Interface, string, error) {
	if preferred != "" {
		iface, err := net.InterfaceByName(preferred)
		if err != nil {
			return nil, "", err
		}
		return iface, "", nil
	}
	addr := net.JoinHostPort(host, strconv.Itoa(port))
	d := net.Dialer{Timeout: timeout}
	conn, err := d.DialContext(ctx, "udp", addr)
	if err != nil {
		return nil, "", err
	}
	defer conn.Close()
	local, ok := conn.LocalAddr().(*net.UDPAddr)
	if !ok || local.IP == nil {
		return nil, "", errors.New("unable to determine local UDP address")
	}
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, "", err
	}
	for i := range ifaces {
		addrs, _ := ifaces[i].Addrs()
		for _, a := range addrs {
			if ipNet, ok := a.(*net.IPNet); ok && ipNet.IP.Equal(local.IP) {
				return &ifaces[i], local.IP.String(), nil
			}
		}
	}
	return nil, local.IP.String(), errors.New("egress interface not found for local_ip=" + local.IP.String())
}

func routeMTU(host string, timeout time.Duration) model.MTUDetectionMethod {
	switch runtime.GOOS {
	case "linux":
		if _, err := exec.LookPath("ip"); err != nil {
			return model.MTUDetectionMethod{Name: "route", Available: false, Error: "ip command not found"}
		}
		out, err := commandOutput(timeout, "ip", "route", "get", host)
		if err != nil {
			return model.MTUDetectionMethod{Name: "route", Available: false, Error: strings.TrimSpace(err.Error() + ": " + out)}
		}
		mtu := firstRegexpInt(`\bmtu\s+(\d+)`, out)
		dev := firstRegexpString(`\bdev\s+(\S+)`, out)
		return model.MTUDetectionMethod{Name: "route", Available: mtu > 0 || dev != "", MTU: mtu, Detail: "dev=" + dev}
	case "darwin":
		if _, err := exec.LookPath("route"); err != nil {
			return model.MTUDetectionMethod{Name: "route", Available: false, Error: "route command not found"}
		}
		out, err := commandOutput(timeout, "route", "-n", "get", host)
		if err != nil {
			return model.MTUDetectionMethod{Name: "route", Available: false, Error: strings.TrimSpace(err.Error() + ": " + out)}
		}
		dev := firstRegexpString(`interface:\s*(\S+)`, out)
		mtu := 0
		if dev != "" {
			if iface, err := net.InterfaceByName(dev); err == nil {
				mtu = iface.MTU
			}
		}
		return model.MTUDetectionMethod{Name: "route", Available: dev != "", MTU: mtu, Detail: "dev=" + dev}
	default:
		return model.MTUDetectionMethod{Name: "route", Available: false, Error: runtime.GOOS + " route mtu detection unsupported"}
	}
}

func tracepathMTU(host string, timeout time.Duration) model.MTUDetectionMethod {
	if runtime.GOOS != "linux" {
		return model.MTUDetectionMethod{Name: "tracepath", Available: false, Error: runtime.GOOS + " tracepath unsupported"}
	}
	if _, err := exec.LookPath("tracepath"); err != nil {
		return model.MTUDetectionMethod{Name: "tracepath", Available: false, Error: "tracepath command not found"}
	}
	out, err := commandOutput(timeout, "tracepath", "-n", "-m", "5", host)
	mtu := firstRegexpInt(`pmtu\s+(\d+)`, out)
	if err != nil && mtu == 0 {
		return model.MTUDetectionMethod{Name: "tracepath", Available: false, Error: strings.TrimSpace(err.Error() + ": " + out)}
	}
	return model.MTUDetectionMethod{Name: "tracepath", Available: mtu > 0, MTU: mtu, Detail: "pmtu"}
}

func pingDFMTU(host string, minMTU, maxMTU, samples int, timeout time.Duration) model.MTUDetectionMethod {
	if err := core.ValidateSafeHost(host); err != nil {
		return model.MTUDetectionMethod{Name: "ping_df", Available: false, Error: err.Error()}
	}
	ping, err := exec.LookPath("ping")
	if err != nil {
		return model.MTUDetectionMethod{Name: "ping_df", Available: false, Error: "ping command not found"}
	}
	if maxMTU <= 0 {
		maxMTU = 1500
	}
	if minMTU <= 0 || minMTU > maxMTU {
		minMTU = 576
	}
	overhead := 28
	if strings.Contains(host, ":") {
		overhead = 48
	}
	lo := minMTU
	hi := maxMTU
	best := 0
	start := time.Now()
	var lastErr error
	for lo <= hi {
		mid := (lo + hi) / 2
		payload := mid - overhead
		if payload < 0 {
			payload = mid
		}
		if pingDFOnce(ping, host, payload, timeout) {
			best = mid
			lo = mid + 1
		} else {
			lastErr = fmt.Errorf("mtu %d failed", mid)
			hi = mid - 1
		}
	}
	if best == 0 {
		msg := "all df ping probes failed"
		if lastErr != nil {
			msg = lastErr.Error()
		}
		return model.MTUDetectionMethod{Name: "ping_df", Available: false, LatencyMS: time.Since(start).Milliseconds(), Error: msg}
	}
	// Confirm the selected size a small number of times to avoid one lucky sample.
	ok := 0
	for i := 0; i < samples; i++ {
		if pingDFOnce(ping, host, best-overhead, timeout) {
			ok++
		}
	}
	if ok == 0 {
		return model.MTUDetectionMethod{Name: "ping_df", Available: false, MTU: best, LatencyMS: time.Since(start).Milliseconds(), Error: "confirmation samples failed"}
	}
	return model.MTUDetectionMethod{Name: "ping_df", Available: true, MTU: best, LatencyMS: time.Since(start).Milliseconds() / int64(max(1, ok)), Detail: fmt.Sprintf("samples=%d/%d", ok, samples)}
}

func pingDFOnce(ping, host string, payload int, timeout time.Duration) bool {
	if payload < 0 {
		payload = 0
	}
	var args []string
	switch runtime.GOOS {
	case "linux":
		args = []string{"-c", "1", "-W", "1", "-M", "do", "-s", strconv.Itoa(payload), host}
	case "darwin":
		args = []string{"-c", "1", "-t", "2", "-D", "-s", strconv.Itoa(payload), host}
	case "windows":
		args = []string{"-n", "1", "-w", strconv.Itoa(int(timeout / time.Millisecond)), "-f", "-l", strconv.Itoa(payload), host}
	default:
		return false
	}
	_, err := commandOutput(timeout, ping, args...)
	return err == nil
}

func tcpConnectMTU(ctx context.Context, host string, port int, timeout time.Duration) model.MTUDetectionMethod {
	if err := core.ValidateSafeHost(host); err != nil {
		return model.MTUDetectionMethod{Name: "tcp_connect", Available: false, Error: err.Error()}
	}
	start := time.Now()
	d := net.Dialer{Timeout: timeout}
	conn, err := d.DialContext(ctx, "tcp", net.JoinHostPort(host, strconv.Itoa(port)))
	if err != nil {
		return model.MTUDetectionMethod{Name: "tcp_connect", Available: false, LatencyMS: time.Since(start).Milliseconds(), Error: err.Error()}
	}
	_ = conn.Close()
	return model.MTUDetectionMethod{Name: "tcp_connect", Available: true, LatencyMS: time.Since(start).Milliseconds(), Detail: "connectivity check only"}
}

func choosePathMTU(methods []model.MTUDetectionMethod) int {
	values := []int{}
	for _, m := range methods {
		if !m.Available || m.MTU <= 0 {
			continue
		}
		switch m.Name {
		case "ping_df", "tracepath", "route":
			values = append(values, m.MTU)
		}
	}
	if len(values) == 0 {
		return 0
	}
	sort.Ints(values)
	return values[0]
}

func recommendMTU(current, path, overhead, minMTU, maxMTU int) int {
	candidates := []int{}
	if current > 0 {
		candidates = append(candidates, current)
	}
	if path > 0 {
		candidates = append(candidates, path)
	}
	if len(candidates) == 0 {
		return 0
	}
	sort.Ints(candidates)
	recommended := candidates[0] - overhead
	return clampMTU(recommended, minMTU, maxMTU)
}

func clampMTU(v, minMTU, maxMTU int) int {
	if v == 0 {
		return 0
	}
	if minMTU <= 0 {
		minMTU = 1280
	}
	if maxMTU <= 0 {
		maxMTU = 9000
	}
	if v < minMTU {
		return minMTU
	}
	if v > maxMTU {
		return maxMTU
	}
	return v
}

func mtuConfidence(methods []model.MTUDetectionMethod, current, path int) string {
	mtuSignals := 0
	for _, m := range methods {
		if m.Available && m.MTU > 0 {
			mtuSignals++
		}
	}
	if current > 0 && path > 0 && abs(current-path) <= 40 && mtuSignals >= 2 {
		return "high"
	}
	if path > 0 || mtuSignals >= 2 {
		return "medium"
	}
	if current > 0 {
		return "low"
	}
	return "unknown"
}

func applyInterfaceMTU(iface string, mtu int, timeout time.Duration) (int, error) {
	if err := core.ValidateNetworkInterfaceName(iface); err != nil {
		return 0, err
	}

	if strings.TrimSpace(iface) == "" {
		return 0, errors.New("interface_name is empty; refusing to apply MTU")
	}
	if mtu < 576 || mtu > 9000 {
		return 0, fmt.Errorf("recommended MTU %d outside safe range 576..9000", mtu)
	}
	switch runtime.GOOS {
	case "linux":
		if _, err := exec.LookPath("ip"); err != nil {
			return 0, errors.New("ip command not found")
		}
		return mtu, runCommand(timeout, "ip", "link", "set", "dev", iface, "mtu", strconv.Itoa(mtu))
	case "darwin":
		if _, err := exec.LookPath("ifconfig"); err != nil {
			return 0, errors.New("ifconfig command not found")
		}
		return mtu, runCommand(timeout, "ifconfig", iface, "mtu", strconv.Itoa(mtu))
	case "windows":
		if _, err := exec.LookPath("netsh"); err != nil {
			return 0, errors.New("netsh command not found")
		}
		return mtu, runCommand(timeout, "netsh", "interface", "ipv4", "set", "subinterface", iface, "mtu="+strconv.Itoa(mtu), "store=active")
	default:
		return 0, fmt.Errorf("%s MTU apply unsupported", runtime.GOOS)
	}
}

func maxProbeMTU(plan model.MTUDetectionPlan, current int) int {
	if current > 0 && current < plan.MaxMTU {
		return current
	}
	if plan.MaxMTU > 0 {
		return plan.MaxMTU
	}
	return 1500
}

func firstRegexpInt(pattern, text string) int {
	match := regexp.MustCompile(pattern).FindStringSubmatch(text)
	if len(match) < 2 {
		return 0
	}
	v, _ := strconv.Atoi(match[1])
	return v
}

func firstRegexpString(pattern, text string) string {
	match := regexp.MustCompile(pattern).FindStringSubmatch(text)
	if len(match) < 2 {
		return ""
	}
	return strings.TrimSpace(match[1])
}

func abs(v int) int {
	if v < 0 {
		return -v
	}
	return v
}
