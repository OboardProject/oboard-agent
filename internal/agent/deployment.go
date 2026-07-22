package agent

import (
	"context"
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
		return "succeeded", jsonMap(map[string]any{"message": "部署已应用", "version": payload.Version, "idempotent_replay": true})
	}
	ctx := context.Background()
	steps := make([]deploymentStepResult, 0, 11+len(payload.WARPRequests))
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

	for _, plan := range payload.WARPRequests {
		started := time.Now()
		report := r.requestWARPConfig(ctx, plan)
		var err error
		if report.Status != model.WARPStatusReady {
			err = fmt.Errorf("%s", report.Error)
			if report.Error == "" {
				err = fmt.Errorf("WARP 配置申请失败")
			}
		}
		add(fmt.Sprintf("warp_%d", plan.ProfileID), "准备 WARP", false, started, reportToMap(report), err, false, "WARP 配置已准备")
	}

	if payload.TimeSync != nil {
		started := time.Now()
		result, err := r.runTimeSyncTask(ctx, *payload.TimeSync)
		skipped, _ := result["skipped"].(bool)
		add("time_sync", "同步时间", false, started, result, err, skipped, "系统时间已检查")
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
