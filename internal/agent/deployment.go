package agent

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/OboardProject/oboard-agent/internal/model"
)

type deploymentStepResult struct {
	Key        string `json:"key"`
	Label      string `json:"label"`
	Status     string `json:"status"`
	Message    string `json:"message,omitempty"`
	Error      string `json:"error,omitempty"`
	DurationMS int64  `json:"duration_ms"`
	Result     any    `json:"result,omitempty"`
}

func (r *Runner) executeDeploymentTask(payload model.DeploymentTaskPayload) (string, string) {
	r.deploymentMu.Lock()
	defer r.deploymentMu.Unlock()
	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		return "failed", jsonResult("encode deployment version state: " + err.Error())
	}
	replay, err := r.checkAppliedVersion(model.AgentTaskTypeApplyDeployment, payload.Version, payloadBytes)
	if err != nil {
		return "failed", jsonMap(map[string]any{"message": "deployment rejected", "version": payload.Version, "error": err.Error()})
	}
	if replay {
		return r.deploymentReplayResponse(payload)
	}
	ctx := context.Background()
	steps := make([]deploymentStepResult, 0, 12+len(payload.WARPRequests))
	criticalFailures := 0
	warnings := 0

	add := func(key, label string, critical bool, started time.Time, result any, err error, skipped bool, message string) {
		step := deploymentStepResult{Key: key, Label: label, Status: "succeeded", Message: message, DurationMS: time.Since(started).Milliseconds(), Result: result}
		if skipped {
			step.Status = "skipped"
		} else if err != nil {
			step.Error = err.Error()
			if critical {
				step.Status = "failed"
				criticalFailures++
			} else {
				step.Status = "warning"
				warnings++
			}
		}
		steps = append(steps, step)
	}

	controllerConfig := payload.Config.Config
	started := time.Now()
	resolvedConfig, assetsChanged, assetErr := r.syncManagedAssets(ctx, payload.Config.Assets, payload.Config.Config)
	add("managed_assets", "同步受管资产", true, started, map[string]any{"requested": len(payload.Config.Assets), "changed": assetsChanged}, assetErr, len(payload.Config.Assets) == 0 && assetErr == nil, "受管资产已就绪")
	if assetErr != nil {
		return deploymentTaskResponse(payload.Version, steps, criticalFailures, warnings)
	}
	payload.Config.Config = resolvedConfig
	if assetsChanged {
		payload.ConfigChanged = true
	}

	warpReports := make(map[int64]model.WARPConfigReport, len(payload.WARPRequests))
	warpBindings := map[int64]warpRegistrationBinding{}
	if len(payload.WARPRequests) > 0 {
		warpBindings, err = deriveWARPRegistrationBindings(payload.Config.Config)
		if err != nil {
			add("warp_config", "准备 WARP 出口", true, time.Now(), nil, err, false, "WARP 出口绑定已检查")
			return deploymentTaskResponse(payload.Version, steps, criticalFailures, warnings)
		}
	}
	for _, plan := range payload.WARPRequests {
		started := time.Now()
		report := r.requestWARPConfig(ctx, plan, warpBindings[plan.ProfileID])
		var err error
		if report.Status != model.WARPStatusReady {
			err = fmt.Errorf("%s", report.Error)
			if report.Error == "" {
				err = fmt.Errorf("WARP 配置申请失败")
			}
		}
		add(fmt.Sprintf("warp_%d", plan.ProfileID), "准备 WARP", true, started, reportToMap(report), err, false, "WARP 配置已准备")
		if err != nil {
			return deploymentTaskResponse(payload.Version, steps, criticalFailures, warnings)
		}
		warpReports[plan.ProfileID] = report
	}
	if len(payload.WARPRequests) > 0 {
		payload.Config.Config, err = resolveDeploymentWARPConfig(payload.Config.Config, payload.WARPRequests, warpReports)
		if err != nil {
			add("warp_config", "写入 WARP 出口", true, time.Now(), nil, err, false, "WARP 出口已写入")
			return deploymentTaskResponse(payload.Version, steps, criticalFailures, warnings)
		}
		controllerConfig, err = resolveDeploymentWARPConfig(controllerConfig, payload.WARPRequests, warpReports)
		if err != nil {
			add("warp_config", "写入 WARP 出口", true, time.Now(), nil, err, false, "WARP 出口已写入")
			return deploymentTaskResponse(payload.Version, steps, criticalFailures, warnings)
		}
	}
	effectiveConfigSHA256, hashErr := canonicalConfigSHA256(controllerConfig)
	if hashErr != nil && strings.TrimSpace(controllerConfig) != "" {
		add("config_digest", "校验配置摘要", true, time.Now(), nil, hashErr, false, "配置摘要已生成")
		return deploymentTaskResponse(payload.Version, steps, criticalFailures, warnings)
	}

	if payload.TimeCheck != nil {
		started := time.Now()
		result, err := r.runTimeCheckTask(ctx, *payload.TimeCheck)
		add("time_check", "检测时间", false, started, result, err, false, "系统时间已检查")
	}

	started = time.Now()
	var (
		result    any
		configErr error
		unchanged bool
	)
	if strings.TrimSpace(payload.Config.Config) == "" {
		result = map[string]any{"reason": "config_not_in_payload"}
		unchanged = !payload.ConfigChanged
		if payload.ConfigChanged {
			configErr = errors.New("deployment marked core config changed but did not include a config")
		}
	} else {
		applyResult, err := r.applyCoreConfigUnlocked(payload.Version, payload.Config.Config)
		applyResult["effective_config_sha256"] = effectiveConfigSHA256
		result, configErr = applyResult, err
		unchanged, _ = applyResult["unchanged"].(bool)
	}
	add("config", "应用核心配置", true, started, result, configErr, unchanged, "核心配置已应用")
	if configErr != nil {
		return deploymentTaskResponse(payload.Version, steps, criticalFailures, warnings)
	}
	cleanupStarted := time.Now()
	cleanupErr := r.cleanupManagedAssets(payload.Config.Assets)
	add("managed_asset_cleanup", "清理受管资产", true, cleanupStarted, nil, cleanupErr, false, "未引用资产已清理")
	if cleanupErr != nil {
		return deploymentTaskResponse(payload.Version, steps, criticalFailures, warnings)
	}

	started = time.Now()
	forwardResult, forwardErr := r.applyPortForwards(payload.PortForwards)
	add("port_forwards", "应用端口转发", true, started, forwardResult, forwardErr, forwardResult.Unchanged, "端口转发已应用")
	if forwardErr != nil {
		return deploymentTaskResponse(payload.Version, steps, criticalFailures, warnings)
	}

	if payload.InboundProbe != nil {
		started = time.Now()
		result, err := r.runInboundProbeTask(ctx, *payload.InboundProbe)
		add("inbound_probe", "检查入口监听", false, started, result, err, false, "入口监听已检查")
	}

	if payload.PortForwardProbe != nil {
		started = time.Now()
		result, err := r.runForwardProbeTask(ctx, payload.PortForwardProbe.Rules, "deployment")
		add("port_forward_probe", "检查端口转发", false, started, result, err, false, "端口转发已检查")
	}

	started = time.Now()
	tunnelResult, tunnelErr := r.applyTunnels(payload.Tunnels)
	add("tunnels", "应用隧道", true, started, tunnelResult, tunnelErr, tunnelResult.Unchanged, "隧道已应用")
	if tunnelErr != nil {
		return deploymentTaskResponse(payload.Version, steps, criticalFailures, warnings)
	}

	started = time.Now()
	sshInboundResult, sshInboundErr := r.applySSHInbounds(payload.SSHInbounds)
	add("ssh_inbounds", "应用 SSH 入站", true, started, sshInboundResult, sshInboundErr, sshInboundResult.Unchanged, "受限 SSH 入站已应用")
	if sshInboundErr != nil {
		return deploymentTaskResponse(payload.Version, steps, criticalFailures, warnings)
	}

	if payload.DNSBenchmark != nil {
		started = time.Now()
		result, err := r.runDNSBenchmarkTask(ctx, *payload.DNSBenchmark, true)
		skipped, _ := result["skipped"].(bool)
		add("dns_benchmark", "检测 DNS", false, started, result, err, skipped, "DNS 检测已完成")
	}

	if payload.MTUDetection != nil {
		started = time.Now()
		result, err := r.runMTUDetectionTask(ctx, *payload.MTUDetection)
		add("mtu_detection", "检测 MTU", false, started, result, err, false, "MTU 检测已完成")
	}

	if criticalFailures == 0 {
		if err := r.persistAppliedVersion(model.AgentTaskTypeApplyDeployment, payload.Version, payloadBytes); err != nil {
			add("version_state", "记录部署版本", true, time.Now(), nil, err, false, "部署版本已记录")
		}
	}
	if criticalFailures == 0 && payload.ExternalEgressProbe != nil {
		started = time.Now()
		result, err := r.runExternalEgressProbeTask(ctx, *payload.ExternalEgressProbe)
		add("external_egress_probe", "识别第三方出口地区", false, started, result, err, false, "第三方出口地区已检查")
	}

	return deploymentTaskResponse(payload.Version, steps, criticalFailures, warnings)
}

func deploymentTaskResponse(version int64, steps []deploymentStepResult, criticalFailures, warnings int) (string, string) {
	succeeded, skipped := 0, 0
	for _, step := range steps {
		switch step.Status {
		case "succeeded":
			succeeded++
		case "skipped":
			skipped++
		}
	}
	message := "部署已完成"
	status := "succeeded"
	if criticalFailures > 0 {
		message = fmt.Sprintf("部署失败：%d 个关键步骤未完成", criticalFailures)
		status = "failed"
	} else if warnings > 0 {
		message = fmt.Sprintf("部署已完成，%d 个检查项需要关注", warnings)
	}
	return status, jsonMap(map[string]any{
		"message": message, "version": version,
		"summary": map[string]int{
			"total": len(steps), "succeeded": succeeded, "skipped": skipped,
			"warnings": warnings, "failed": criticalFailures,
		},
		"steps": steps,
	})
}

func resolveDeploymentWARPConfig(config string, plans []model.WARPRequestPlan, reports map[int64]model.WARPConfigReport) (string, error) {
	if len(plans) == 0 {
		return config, nil
	}
	if strings.TrimSpace(config) == "" {
		return "", errors.New("WARP deployment requires a core config")
	}
	var root map[string]any
	if err := json.Unmarshal([]byte(config), &root); err != nil {
		return "", fmt.Errorf("decode core config for WARP: %w", err)
	}
	endpoints, _ := root["endpoints"].([]any)
	for _, plan := range plans {
		tag := strings.TrimSpace(plan.OutboundTag)
		if tag == "" {
			return "", fmt.Errorf("WARP profile %d is missing outbound_tag", plan.ProfileID)
		}
		report, ok := reports[plan.ProfileID]
		if !ok || report.Status != model.WARPStatusReady || strings.TrimSpace(report.ConfigJSON) == "" {
			return "", fmt.Errorf("WARP profile %d is not ready", plan.ProfileID)
		}
		var endpoint map[string]any
		if err := json.Unmarshal([]byte(report.ConfigJSON), &endpoint); err != nil {
			return "", fmt.Errorf("decode WARP profile %d: %w", plan.ProfileID, err)
		}
		if !strings.EqualFold(strings.TrimSpace(fmt.Sprint(endpoint["type"])), "wireguard") {
			return "", fmt.Errorf("WARP profile %d is not a WireGuard endpoint", plan.ProfileID)
		}
		normalizeWARPDomainResolver(endpoint, plan)
		baseFound := false
		for index, raw := range endpoints {
			placeholder, ok := raw.(map[string]any)
			if !ok {
				continue
			}
			placeholderTag := strings.TrimSpace(fmt.Sprint(placeholder["tag"]))
			placeholderProfileID := int64FromAny(placeholder["_oboard_warp_pending"])
			if placeholderTag == tag {
				baseFound = true
				if placeholderProfileID != plan.ProfileID {
					return "", fmt.Errorf("WARP outbound tag %q already exists", tag)
				}
			}
			if placeholderProfileID != plan.ProfileID {
				continue
			}
			resolvedEndpoint := make(map[string]any, len(endpoint)+3)
			for key, value := range endpoint {
				resolvedEndpoint[key] = value
			}
			resolvedEndpoint["tag"] = placeholderTag
			if value, exists := placeholder["domain_resolver"]; exists {
				resolvedEndpoint["domain_resolver"] = value
			}
			if value, exists := placeholder["bind_interface"]; exists {
				delete(resolvedEndpoint, "detour")
				resolvedEndpoint["bind_interface"] = value
			} else if value, exists := placeholder["detour"]; exists {
				delete(resolvedEndpoint, "bind_interface")
				resolvedEndpoint["detour"] = value
			}
			endpoints[index] = resolvedEndpoint
		}
		if !baseFound {
			endpoint["tag"] = tag
			endpoints = append(endpoints, endpoint)
		}
	}
	root["endpoints"] = endpoints
	out, err := json.MarshalIndent(root, "", "  ")
	if err != nil {
		return "", err
	}
	return string(out), nil
}

func canonicalConfigSHA256(config string) (string, error) {
	if strings.TrimSpace(config) == "" {
		return "", nil
	}
	var value any
	if err := json.Unmarshal([]byte(config), &value); err != nil {
		return "", err
	}
	canonical, err := json.Marshal(value)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%x", sha256.Sum256(canonical)), nil
}

func int64FromAny(value any) int64 {
	switch number := value.(type) {
	case float64:
		return int64(number)
	case int64:
		return number
	case int:
		return int64(number)
	default:
		return 0
	}
}

func (r *Runner) deploymentReplayResponse(payload model.DeploymentTaskPayload) (string, string) {
	reports := make(map[int64]model.WARPConfigReport, len(payload.WARPRequests))
	steps := make([]deploymentStepResult, 0, len(payload.WARPRequests)+3)
	for _, plan := range payload.WARPRequests {
		report, err := r.loadPersistedWARPConfig(plan)
		if err != nil {
			steps = append(steps, deploymentStepResult{Key: fmt.Sprintf("warp_%d", plan.ProfileID), Label: "准备 WARP", Status: "failed", Error: "已应用版本缺少本地 WARP 状态"})
			return deploymentTaskResponse(payload.Version, steps, 1, 0)
		}
		reports[plan.ProfileID] = report
		steps = append(steps, deploymentStepResult{Key: fmt.Sprintf("warp_%d", plan.ProfileID), Label: "准备 WARP", Status: "succeeded", Message: "WARP 配置已恢复", Result: reportToMap(report)})
	}
	resolved, err := resolveDeploymentWARPConfig(payload.Config.Config, payload.WARPRequests, reports)
	if err != nil {
		steps = append(steps, deploymentStepResult{Key: "config", Label: "应用核心配置", Status: "failed", Error: err.Error()})
		return deploymentTaskResponse(payload.Version, steps, 1, 0)
	}
	digest, err := canonicalConfigSHA256(resolved)
	if err != nil {
		steps = append(steps, deploymentStepResult{Key: "config", Label: "应用核心配置", Status: "failed", Error: err.Error()})
		return deploymentTaskResponse(payload.Version, steps, 1, 0)
	}
	steps = append(steps, deploymentStepResult{Key: "config", Label: "应用核心配置", Status: "skipped", Message: "部署版本已应用", Result: map[string]any{"idempotent_replay": true, "effective_config_sha256": digest}})
	sshResult, err := r.applySSHInbounds(payload.SSHInbounds)
	if err != nil {
		steps = append(steps, deploymentStepResult{Key: "ssh_inbounds", Label: "应用 SSH 入站", Status: "failed", Error: err.Error()})
		return deploymentTaskResponse(payload.Version, steps, 1, 0)
	}
	steps = append(steps, deploymentStepResult{Key: "ssh_inbounds", Label: "应用 SSH 入站", Status: "skipped", Message: "受限 SSH 入站已应用", Result: sshResult})
	warnings := 0
	if payload.ExternalEgressProbe != nil {
		result, probeErr := r.runExternalEgressProbeTask(context.Background(), *payload.ExternalEgressProbe)
		step := deploymentStepResult{Key: "external_egress_probe", Label: "识别第三方出口地区", Status: "succeeded", Message: "第三方出口地区已检查", Result: result}
		if probeErr != nil {
			step.Status = "warning"
			step.Error = probeErr.Error()
			warnings++
		}
		steps = append(steps, step)
	}
	return deploymentTaskResponse(payload.Version, steps, 0, warnings)
}
