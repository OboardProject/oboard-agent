package agent

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"

	"github.com/OboardProject/oboard-agent/internal/core"
	"github.com/OboardProject/oboard-agent/internal/model"
)

const (
	ntpPacketSize              = 48
	ntpUnixEpochDelta          = 2208988800
	controllerTimeMaxAge       = 2 * time.Minute
	controllerNTPConflictLimit = 5 * time.Second
)

type timeReference struct {
	Offset      time.Duration
	Reference   time.Time
	LocalAnchor time.Time
	Source      string
}

type ntpSample struct {
	offset time.Duration
	source string
	err    error
}

var queryNTPSource = queryNTP

func (r *Runner) runTimeCheckTask(ctx context.Context, plan model.TimeCheckPlan) (model.TimeCheckResult, error) {
	plan.CorrectionMode = normalizeTimeCorrectionMode(plan.CorrectionMode)
	if plan.CorrectionMode == "" {
		plan.CorrectionMode = normalizeTimeCorrectionMode(r.Config().TimeCorrectionMode)
	}
	if plan.ThresholdSeconds <= 0 || plan.ThresholdSeconds > 3600 {
		plan.ThresholdSeconds = 30
	}
	if len(plan.NTPServers) == 0 {
		plan.NTPServers = defaultTimeServers()
	}
	normalizedServers, err := normalizeNTPServers(plan.NTPServers)
	if err != nil {
		return model.TimeCheckResult{Status: "unavailable", CorrectionMode: plan.CorrectionMode, CheckedAt: r.clock.Now().UTC(), Error: err.Error()}, err
	}
	plan.NTPServers = normalizedServers
	if err := r.persistTimeCorrectionMode(plan.CorrectionMode); err != nil {
		return model.TimeCheckResult{Status: "unavailable", CorrectionMode: plan.CorrectionMode, CheckedAt: r.clock.Now().UTC(), Error: err.Error()}, err
	}

	reference, err := r.resolveTimeReference(ctx, plan.NTPServers)
	if err != nil {
		if plan.CorrectionMode == model.TimeCorrectionOff {
			if clearErr := r.clock.Apply(false, time.Time{}, "", time.Now().UTC()); clearErr != nil {
				return model.TimeCheckResult{Status: "unavailable", CorrectionMode: plan.CorrectionMode, CheckedAt: time.Now().UTC(), Error: clearErr.Error()}, clearErr
			}
			_ = r.configureCoreClock(ctx)
		}
		state := r.clock.Snapshot()
		result := model.TimeCheckResult{Status: "unavailable", CorrectionMode: plan.CorrectionMode, Source: state.Source, CheckedAt: r.clock.Now().UTC(), LogicalTimeActive: state.Enabled, Error: err.Error()}
		if state.Enabled {
			result.EffectiveOffsetMS = 0
		}
		return result, err
	}
	threshold := time.Duration(plan.ThresholdSeconds) * time.Second
	rawOffset := reference.Offset
	result := model.TimeCheckResult{
		Status:            "ok",
		CorrectionMode:    plan.CorrectionMode,
		RawOffsetMS:       rawOffset.Milliseconds(),
		EffectiveOffsetMS: rawOffset.Milliseconds(),
		Source:            reference.Source,
		CheckedAt:         reference.Reference.UTC(),
	}

	if plan.CorrectionMode == model.TimeCorrectionOff {
		if err := r.clock.Apply(false, time.Time{}, reference.Source, reference.Reference); err != nil {
			result.Error = err.Error()
			return result, err
		}
		if absDuration(rawOffset) >= threshold {
			result.Status = "skewed"
		}
		if err := r.configureCoreClock(ctx); err != nil {
			result.Error = "内核时间状态同步失败: " + err.Error()
		}
		return result, nil
	}

	if absDuration(rawOffset) < threshold {
		if err := r.clock.Apply(false, time.Time{}, reference.Source, reference.Reference); err != nil {
			result.Error = err.Error()
			return result, err
		}
		if err := r.configureCoreClock(ctx); err != nil {
			result.Error = "内核时间状态同步失败: " + err.Error()
		}
		return result, nil
	}

	if plan.CorrectionMode == model.TimeCorrectionAuto {
		result.SystemSyncAttempted = true
		cmdName, args, commandErr := r.timeSyncCommand(plan.NTPServers)
		if commandErr == nil && cmdName != "none" {
			commandErr = runCommand(r.commandTimeout(), cmdName, args...)
		}
		if commandErr == nil && cmdName == "none" {
			commandErr = errors.New("time_sync_command is none")
		}
		if commandErr == nil {
			resampleCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
			resampled, sampleErr := r.resolveTimeReference(resampleCtx, plan.NTPServers)
			cancel()
			if sampleErr == nil && absDuration(resampled.Offset) < threshold {
				result.Status = "corrected"
				result.SystemSyncSucceeded = true
				result.EffectiveOffsetMS = resampled.Offset.Milliseconds()
				result.Source = resampled.Source
				result.CheckedAt = resampled.Reference.UTC()
				if err := r.clock.Apply(false, time.Time{}, resampled.Source, resampled.Reference); err != nil {
					result.Error = err.Error()
					return result, err
				}
				if err := r.configureCoreClock(ctx); err != nil {
					result.Error = "内核时间状态同步失败: " + err.Error()
				}
				return result, nil
			}
			if sampleErr != nil {
				commandErr = sampleErr
			} else {
				commandErr = fmt.Errorf("系统校时后仍偏差 %.1f 秒", resampled.Offset.Seconds())
			}
		}
		result.SystemSyncError = commandErr.Error()
	}

	referenceNow := reference.Reference.Add(time.Since(reference.LocalAnchor))
	if err := r.clock.Apply(true, referenceNow, reference.Source, referenceNow); err != nil {
		result.Error = err.Error()
		return result, err
	}
	result.Status = "corrected"
	result.EffectiveOffsetMS = 0
	result.LogicalTimeActive = true
	result.UnsupportedTimePaths = r.unsupportedLogicalTimePaths()
	if err := r.configureCoreClock(ctx); err != nil {
		result.Error = "内核时间状态同步失败: " + err.Error()
	}
	return result, nil
}

func normalizeTimeCorrectionMode(mode model.TimeCorrectionMode) model.TimeCorrectionMode {
	switch model.TimeCorrectionMode(strings.ToLower(strings.TrimSpace(string(mode)))) {
	case model.TimeCorrectionAuto:
		return model.TimeCorrectionAuto
	case model.TimeCorrectionNTP:
		return model.TimeCorrectionNTP
	case model.TimeCorrectionOff:
		return model.TimeCorrectionOff
	default:
		return ""
	}
}

func (r *Runner) persistTimeCorrectionMode(mode model.TimeCorrectionMode) error {
	cfg := r.Config()
	if cfg.TimeCorrectionMode == mode {
		return nil
	}
	cfg.TimeCorrectionMode = mode
	if strings.TrimSpace(cfg.ConfigPath) != "" {
		if err := SaveConfig(cfg.ConfigPath, cfg); err != nil {
			return err
		}
	}
	r.storeConfig(cfg)
	return nil
}

func (r *Runner) resolveTimeReference(ctx context.Context, servers []string) (timeReference, error) {
	reference, ntpErr := queryNTPMedian(ctx, servers)
	controller, controllerOK := r.controllerReferenceNow()
	if ntpErr == nil {
		if controllerOK {
			ntpNow := reference.Reference.Add(time.Since(reference.LocalAnchor))
			if absDuration(ntpNow.Sub(controller)) > controllerNTPConflictLimit {
				return timeReference{}, fmt.Errorf("NTP 与 Controller 时间相差超过 %s，拒绝应用时间补偿", controllerNTPConflictLimit)
			}
		}
		return reference, nil
	}
	if controllerOK {
		local := time.Now()
		return timeReference{Offset: controller.Sub(local), Reference: controller, LocalAnchor: local, Source: "controller"}, nil
	}
	return timeReference{}, ntpErr
}

func queryNTPMedian(ctx context.Context, servers []string) (timeReference, error) {
	queryCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	results := make(chan ntpSample, len(servers))
	for _, server := range servers {
		server := server
		go func() {
			offset, err := queryNTPSource(queryCtx, server)
			results <- ntpSample{offset: offset, source: server, err: err}
		}()
	}
	samples := make([]ntpSample, 0, len(servers))
	errorsByServer := make([]string, 0, len(servers))
	for range servers {
		select {
		case sample := <-results:
			if sample.err != nil {
				errorsByServer = append(errorsByServer, sample.source+": "+sample.err.Error())
			} else {
				samples = append(samples, sample)
			}
		case <-queryCtx.Done():
			errorsByServer = append(errorsByServer, queryCtx.Err().Error())
		}
	}
	if len(samples) < 2 {
		return timeReference{}, fmt.Errorf("至少需要两个 NTP 源返回结果: %s", strings.Join(errorsByServer, "; "))
	}
	sort.Slice(samples, func(i, j int) bool { return samples[i].offset < samples[j].offset })
	offset := samples[len(samples)/2].offset
	if len(samples)%2 == 0 {
		offset = samples[len(samples)/2-1].offset/2 + samples[len(samples)/2].offset/2
	}
	local := time.Now()
	sources := make([]string, 0, len(samples))
	for _, sample := range samples {
		sources = append(sources, sample.source)
	}
	return timeReference{Offset: offset, Reference: local.Add(offset), LocalAnchor: local, Source: "ntp:" + strings.Join(sources, ",")}, nil
}

func queryNTP(ctx context.Context, server string) (time.Duration, error) {
	dialer := net.Dialer{Timeout: 4 * time.Second}
	conn, err := dialer.DialContext(ctx, "udp", net.JoinHostPort(server, "123"))
	if err != nil {
		return 0, err
	}
	defer conn.Close()
	deadline, ok := ctx.Deadline()
	if ok {
		_ = conn.SetDeadline(deadline)
	}
	request := make([]byte, ntpPacketSize)
	request[0] = 0x23
	t1 := time.Now()
	transmit, err := encodeNTPTimestamp(t1)
	if err != nil {
		return 0, err
	}
	binary.BigEndian.PutUint64(request[40:48], transmit)
	if _, err := conn.Write(request); err != nil {
		return 0, err
	}
	response := make([]byte, ntpPacketSize)
	if _, err := conn.Read(response); err != nil {
		return 0, err
	}
	t4 := time.Now()
	if response[0]&0x7 != 4 || response[1] == 0 || response[1] > 15 {
		return 0, errors.New("invalid NTP server response")
	}
	if binary.BigEndian.Uint64(response[24:32]) != transmit {
		return 0, errors.New("NTP originate timestamp mismatch")
	}
	t2 := decodeNTPTimestamp(binary.BigEndian.Uint64(response[32:40]))
	t3 := decodeNTPTimestamp(binary.BigEndian.Uint64(response[40:48]))
	if t2.IsZero() || t3.IsZero() {
		return 0, errors.New("NTP response timestamp is missing")
	}
	return (t2.Sub(t1) + t3.Sub(t4)) / 2, nil
}

func encodeNTPTimestamp(value time.Time) (uint64, error) {
	seconds := value.Unix() + ntpUnixEpochDelta
	if seconds < 0 || seconds > int64(^uint32(0)) {
		return 0, errors.New("local time is outside the supported NTP era")
	}
	fraction := (uint64(value.Nanosecond()) << 32) / 1_000_000_000
	return uint64(seconds)<<32 | fraction, nil
}

func decodeNTPTimestamp(value uint64) time.Time {
	seconds := int64(uint32(value>>32)) - ntpUnixEpochDelta
	fraction := uint32(value)
	nanoseconds := int64(uint64(fraction) * 1_000_000_000 >> 32)
	return time.Unix(seconds, nanoseconds).UTC()
}

func validateNTPServers(servers []string) error {
	_, err := normalizeNTPServers(servers)
	return err
}

func normalizeNTPServers(servers []string) ([]string, error) {
	if len(servers) != 3 {
		return nil, errors.New("time check requires exactly three NTP servers")
	}
	seen := map[string]bool{}
	normalized := make([]string, 0, len(servers))
	for _, server := range servers {
		server = strings.ToLower(strings.TrimSpace(server))
		if strings.HasPrefix(server, "[") {
			if !strings.HasSuffix(server, "]") {
				return nil, fmt.Errorf("invalid NTP server %q", server)
			}
			server = strings.TrimSuffix(strings.TrimPrefix(server, "["), "]")
			if net.ParseIP(server) == nil {
				return nil, fmt.Errorf("invalid NTP server %q", server)
			}
		}
		if seen[server] || core.ValidateSafeHost(server) != nil {
			return nil, fmt.Errorf("invalid or duplicate NTP server %q", server)
		}
		seen[server] = true
		normalized = append(normalized, server)
	}
	return normalized, nil
}

func (r *Runner) configureCoreClock(ctx context.Context) error {
	state := r.clock.Snapshot()
	body, err := json.Marshal(map[string]any{
		"enabled":        state.Enabled,
		"reference_time": state.ReferenceTime,
		"source":         state.Source,
		"checked_at":     state.CheckedAt,
	})
	if err != nil {
		return err
	}
	client := r.coreClient
	if client == nil {
		client = unixHTTPClient(coreAPISocket)
	}
	requestCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(requestCtx, http.MethodPost, "http://oboard-sb/clock/config", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	res, err := client.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	if res.StatusCode >= 300 {
		return fmt.Errorf("core clock config status %d", res.StatusCode)
	}
	return nil
}

func (r *Runner) unsupportedLogicalTimePaths() []string {
	data, err := os.ReadFile(filepath.Join(r.stateDir(), "sing-box.json"))
	if err != nil {
		return nil
	}
	var config struct {
		Outbounds []struct {
			Type string `json:"type"`
			TLS  *struct {
				Reality any `json:"reality"`
			} `json:"tls"`
		} `json:"outbounds"`
	}
	if json.Unmarshal(data, &config) != nil {
		return nil
	}
	seen := map[string]bool{}
	for _, outbound := range config.Outbounds {
		if outbound.Type == "mieru" {
			seen["mieru_outbound"] = true
		}
		if outbound.TLS != nil && outbound.TLS.Reality != nil {
			seen["reality_outbound"] = true
		}
	}
	paths := make([]string, 0, len(seen))
	for path := range seen {
		paths = append(paths, path)
	}
	sort.Strings(paths)
	return paths
}

func (r *Runner) timeSyncCommand(servers []string) (string, []string, error) {
	command := strings.TrimSpace(r.Config().TimeSyncCommand)
	switch command {
	case "", "auto":
		return autoTimeSyncCommand(servers)
	case "none":
		return "none", nil, nil
	case "chrony":
		return "chronyc", []string{"-a", "makestep"}, nil
	case "systemd-timesyncd":
		return "timedatectl", []string{"set-ntp", "true"}, nil
	default:
		return "", nil, errors.New("time_sync_command is not an allowed managed preset")
	}
}

func autoTimeSyncCommand(servers []string) (string, []string, error) {
	server := "pool.ntp.org"
	if len(servers) > 0 && strings.TrimSpace(servers[0]) != "" {
		server = strings.TrimSpace(servers[0])
	}
	switch runtime.GOOS {
	case "linux":
		if _, err := exec.LookPath("chronyc"); err == nil {
			return "chronyc", []string{"-a", "makestep"}, nil
		}
		if _, err := exec.LookPath("ntpdate"); err == nil {
			return "ntpdate", []string{"-u", server}, nil
		}
		if _, err := exec.LookPath("sntp"); err == nil {
			return "sntp", []string{"-sS", server}, nil
		}
		if _, err := exec.LookPath("timedatectl"); err == nil {
			return "timedatectl", []string{"set-ntp", "true"}, nil
		}
	case "darwin":
		if _, err := exec.LookPath("sntp"); err == nil {
			return "sntp", []string{"-sS", server}, nil
		}
	case "windows":
		return "w32tm", []string{"/resync"}, nil
	}
	return "", nil, errors.New("no supported time sync command found; set time_sync_command to an allowed preset or none")
}

func defaultTimeServers() []string {
	return []string{"time.cloudflare.com", "time.google.com", "pool.ntp.org"}
}

func absDuration(value time.Duration) time.Duration {
	if value < 0 {
		return -value
	}
	return value
}
