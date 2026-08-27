package agent

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/OboardProject/oboard-agent/internal/model"
)

const (
	remoteExecDefaultTimeout = 30 * time.Second
	remoteExecMaxTimeout     = 300 * time.Second
	remoteExecGrace          = 2 * time.Second
	remoteExecDefaultOutput  = 1 << 20
	remoteExecMaxOutput      = 4 << 20
	remoteExecMaxArgv        = 64
	remoteExecMaxArgBytes    = 4096
	remoteExecMaxArgvTotal   = 32 << 10
	remoteExecMaxShell       = 32 << 10
	remoteExecMaxCwd         = 4096
)

type remoteExecRun struct {
	cancel context.CancelFunc
	cmd    *exec.Cmd
}

func (r *Runner) executeRemoteExecTask(task model.AgentTask) (string, string) {
	var payload model.RemoteExecTaskPayload
	if err := json.Unmarshal([]byte(task.PayloadJSON), &payload); err != nil {
		return "failed", jsonResult(err.Error())
	}
	if err := r.validateRemoteExecPayload(payload); err != nil {
		return "failed", jsonMap(map[string]any{"error": err.Error(), "code": "invalid_input"})
	}
	if !r.localGateAllows(localGateFeatureForExec(payload.Origin, payload.Command.Mode)) {
		return "failed", jsonMap(map[string]any{"error": "agent local security policy denied remote exec", "code": "agent_local_gate_denied"})
	}
	digest := remoteExecPayloadDigest(payload)
	record, err := r.remoteExecJournal().Begin(payload.RequestID, digest)
	if err != nil {
		code := "request_id_conflict"
		if errors.Is(err, errRemoteExecRunning) {
			code = "already_running"
		}
		return "failed", jsonMap(map[string]any{"error": err.Error(), "code": code})
	}
	if record != nil && record.State == remoteExecStateCompleted {
		return "succeeded", string(record.ResultJSON)
	}
	result, runErr := r.runRemoteExec(payload)
	status := "succeeded"
	if runErr != nil && result.Error == "" {
		result.Error = runErr.Error()
		status = "failed"
	}
	if result.Error != "" && status == "succeeded" {
		status = "failed"
	}
	encoded, _ := json.Marshal(result)
	_ = r.remoteExecJournal().Complete(payload.RequestID, digest, encoded)
	if status == "failed" {
		return "failed", string(encoded)
	}
	return "succeeded", string(encoded)
}

func (r *Runner) validateRemoteExecPayload(payload model.RemoteExecTaskPayload) error {
	if strings.TrimSpace(payload.RequestID) == "" {
		return errors.New("request_id is required")
	}
	if len(payload.RequestID) > 128 {
		return errors.New("request_id exceeds limit")
	}
	if payload.ServerID != r.Config().ServerID && r.Config().ServerID != 0 {
		return fmt.Errorf("payload server_id %d does not match enrolled server", payload.ServerID)
	}
	if !payload.ExpiresAt.IsZero() && time.Now().After(payload.ExpiresAt) {
		return errors.New("remote exec payload expired")
	}
	cwd := strings.TrimSpace(payload.Command.Cwd)
	if cwd == "" {
		cwd = "/"
	}
	if len(cwd) > remoteExecMaxCwd {
		return errors.New("cwd exceeds limit")
	}
	if !filepath.IsAbs(cwd) {
		return errors.New("cwd must be an absolute path")
	}
	if strings.Contains(cwd, "..") {
		return errors.New("cwd must not contain dot-dot segments")
	}
	cleaned := filepath.Clean(cwd)
	if cleaned != cwd {
		return errors.New("cwd must be a cleaned absolute path")
	}
	switch payload.Command.Mode {
	case model.RemoteExecModeArgv:
		if len(payload.Command.Argv) == 0 || len(payload.Command.Argv) > remoteExecMaxArgv {
			return errors.New("argv count out of range")
		}
		total := 0
		for _, arg := range payload.Command.Argv {
			if len(arg) == 0 {
				return errors.New("argv item is empty")
			}
			if len(arg) > remoteExecMaxArgBytes {
				return errors.New("argv item exceeds limit")
			}
			if strings.Contains(arg, "\x00") {
				return errors.New("argv item contains null byte")
			}
			total += len(arg)
		}
		if total > remoteExecMaxArgvTotal {
			return errors.New("argv total exceeds limit")
		}
	case model.RemoteExecModeShell:
		shell := strings.TrimSpace(payload.Command.Shell)
		if shell == "" || len(shell) > remoteExecMaxShell {
			return errors.New("shell command exceeds limit")
		}
		if strings.Contains(shell, "\x00") {
			return errors.New("shell command contains null byte")
		}
	default:
		return errors.New("unsupported remote exec mode")
	}
	return nil
}

func (r *Runner) runRemoteExec(payload model.RemoteExecTaskPayload) (model.RemoteExecResult, error) {
	timeout := time.Duration(payload.Limits.TimeoutSeconds) * time.Second
	if timeout <= 0 {
		timeout = remoteExecDefaultTimeout
	}
	if timeout > remoteExecMaxTimeout {
		timeout = remoteExecMaxTimeout
	}
	stdoutLimit := payload.Limits.StdoutBytes
	if stdoutLimit <= 0 {
		stdoutLimit = remoteExecDefaultOutput
	}
	if stdoutLimit > remoteExecMaxOutput {
		stdoutLimit = remoteExecMaxOutput
	}
	stderrLimit := payload.Limits.StderrBytes
	if stderrLimit <= 0 {
		stderrLimit = remoteExecDefaultOutput
	}
	if stderrLimit > remoteExecMaxOutput {
		stderrLimit = remoteExecMaxOutput
	}
	cwd := strings.TrimSpace(payload.Command.Cwd)
	if cwd == "" {
		cwd = "/"
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	var cmd *exec.Cmd
	switch payload.Command.Mode {
	case model.RemoteExecModeShell:
		cmd = exec.CommandContext(ctx, "/bin/sh", "-c", payload.Command.Shell)
	default:
		cmd = exec.CommandContext(ctx, payload.Command.Argv[0], payload.Command.Argv[1:]...)
	}
	cmd.Dir = cwd
	cmd.Env = remoteExecEnv()
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	var stdout, stderr limitedBuffer
	stdout.limit = stdoutLimit
	stderr.limit = stderrLimit
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	started := time.Now()
	r.trackRemoteExec(payload.RequestID, &remoteExecRun{cancel: cancel, cmd: cmd})
	defer r.untrackRemoteExec(payload.RequestID)
	err := cmd.Run()
	result := model.RemoteExecResult{
		DurationMS:      time.Since(started).Milliseconds(),
		StdoutBytes:     stdout.n,
		StderrBytes:     stderr.n,
		StdoutSHA256:    remoteExecDigestHex(stdout.buf.Bytes()),
		StderrSHA256:    remoteExecDigestHex(stderr.buf.Bytes()),
		StdoutTruncated: stdout.truncated,
		StderrTruncated: stderr.truncated,
		Stdout:          stdout.buf.String(),
		Stderr:          stderr.buf.String(),
	}
	if cmd.ProcessState != nil {
		result.ExitCode = cmd.ProcessState.ExitCode()
	}
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		killProcessGroup(cmd)
		result.Error = "remote_exec_timeout"
		return result, ctx.Err()
	}
	if errors.Is(ctx.Err(), context.Canceled) {
		killProcessGroup(cmd)
		result.Cancelled = true
		result.Error = "remote_exec_cancelled"
		return result, ctx.Err()
	}
	_ = err
	return result, nil
}

func remoteExecEnv() []string {
	path := os.Getenv("PATH")
	if path == "" {
		path = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
	}
	return []string{
		"PATH=" + path,
		"HOME=/root",
		"USER=root",
		"LOGNAME=root",
		"LANG=C.UTF-8",
		"LC_ALL=C.UTF-8",
	}
}

func killProcessGroup(cmd *exec.Cmd) {
	if cmd == nil || cmd.Process == nil {
		return
	}
	pgid := cmd.Process.Pid
	_ = syscall.Kill(-pgid, syscall.SIGTERM)
	done := make(chan struct{})
	go func() {
		_, _ = cmd.Process.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(remoteExecGrace):
		_ = syscall.Kill(-pgid, syscall.SIGKILL)
		_, _ = cmd.Process.Wait()
	}
}

func (r *Runner) trackRemoteExec(requestID string, run *remoteExecRun) {
	r.remoteExecMu.Lock()
	if r.remoteExecRuns == nil {
		r.remoteExecRuns = map[string]*remoteExecRun{}
	}
	r.remoteExecRuns[requestID] = run
	r.remoteExecMu.Unlock()
}

func (r *Runner) untrackRemoteExec(requestID string) {
	r.remoteExecMu.Lock()
	delete(r.remoteExecRuns, requestID)
	r.remoteExecMu.Unlock()
}

func (r *Runner) cancelRemoteExec(requestID string) string {
	r.remoteExecMu.Lock()
	run := r.remoteExecRuns[requestID]
	r.remoteExecMu.Unlock()
	if run == nil {
		return "already_finished"
	}
	run.cancel()
	killProcessGroup(run.cmd)
	return "cancelling"
}

func remoteExecPayloadDigest(payload model.RemoteExecTaskPayload) string {
	raw, _ := json.Marshal(payload)
	return remoteExecDigestHex(raw)
}

func remoteExecDigestHex(value []byte) string {
	sum := sha256.Sum256(value)
	return hex.EncodeToString(sum[:])
}

type limitedBuffer struct {
	buf       bytes.Buffer
	n         int
	limit     int
	truncated bool
}

func (b *limitedBuffer) Write(p []byte) (int, error) {
	remain := b.limit - b.n
	if remain <= 0 {
		b.truncated = true
		return len(p), nil
	}
	if len(p) > remain {
		b.truncated = true
		_, _ = b.buf.Write(p[:remain])
		b.n += remain
		return len(p), nil
	}
	n, err := b.buf.Write(p)
	b.n += n
	return n, err
}

func (r *Runner) executeRemoteOperationTask(task model.AgentTask) (string, string) {
	var payload model.RemoteOperationTaskPayload
	if err := json.Unmarshal([]byte(task.PayloadJSON), &payload); err != nil {
		return "failed", jsonResult(err.Error())
	}
	if !r.localGateAllows("mcp_remote_operations") {
		return "failed", jsonMap(map[string]any{"error": "agent local security policy denied remote operations", "code": "agent_local_gate_denied"})
	}
	result, err := r.runRemoteOperation(payload)
	if err != nil {
		result["error"] = err.Error()
		return "failed", jsonMap(result)
	}
	return "succeeded", jsonMap(result)
}

func (r *Runner) runRemoteOperation(payload model.RemoteOperationTaskPayload) (map[string]any, error) {
	switch payload.Kind {
	case model.RemoteOperationSystemInfo:
		health := r.Probe(true)
		return map[string]any{
			"os": health.OS, "distro_id": health.DistroID, "distro_version": health.DistroVersion,
			"distro_name": health.DistroName, "arch": health.Arch, "kernel": health.Kernel,
			"cpu": health.CPU, "memory_used_bytes": health.MemoryUsedBytes, "memory_total_bytes": health.MemoryTotalBytes,
			"cpu_usage_percent": health.CPUUsagePercent, "process_count": health.ProcessCount,
			"agent_version": health.AgentVersion, "uptime_hint": health.Kernel,
		}, nil
	case model.RemoteOperationNetworkInfo:
		ifaces, err := listNetworkInterfaces()
		if err != nil {
			return map[string]any{}, err
		}
		return map[string]any{"interfaces": ifaces}, nil
	case model.RemoteOperationDiskUsage:
		health := r.Probe(false)
		return map[string]any{"disk_used_bytes": health.DiskBytes, "disk_total_bytes": health.DiskTotalBytes}, nil
	case model.RemoteOperationListeners:
		return r.captureCommandOutput("ss", "-lntp")
	case model.RemoteOperationServiceStatus:
		service := strings.TrimSpace(payload.Service)
		if service == "" || service == "all" {
			agent, _ := r.captureCommandOutput("systemctl", "is-active", "oboard-agent")
			core, _ := r.captureCommandOutput("systemctl", "is-active", "oboard-sb")
			return map[string]any{"oboard-agent": agent, "oboard-sb": core}, nil
		}
		if service != "oboard-agent" && service != "oboard-sb" {
			return nil, errors.New("service is not an OBoard managed unit")
		}
		return r.captureCommandOutput("systemctl", "is-active", service)
	case model.RemoteOperationServiceRestart:
		service := strings.TrimSpace(payload.Service)
		if service != "oboard-agent" && service != "oboard-sb" {
			return nil, errors.New("service is not an OBoard managed unit")
		}
		return r.captureCommandOutput("systemctl", "restart", service)
	case model.RemoteOperationLogs:
		lines := payload.Lines
		if lines <= 0 {
			lines = 80
		}
		return r.collectLogsPayload(map[string]any{"services": "agent", "lines": lines})
	case model.RemoteOperationDiagnostics:
		return r.runNetworkDiagnostics(`{}`), nil
	default:
		return nil, errors.New("unsupported remote operation")
	}
}

func (r *Runner) collectLogsPayload(req map[string]any) (map[string]any, error) {
	raw, _ := json.Marshal(req)
	status, result := r.executeAgentTask(model.AgentTask{Type: model.AgentTaskTypeCollectLogs, PayloadJSON: string(raw)})
	var payload map[string]any
	_ = json.Unmarshal([]byte(result), &payload)
	if payload == nil {
		payload = map[string]any{}
	}
	if status != "succeeded" {
		return payload, errors.New("collect logs failed")
	}
	return payload, nil
}

func (r *Runner) captureCommandOutput(name string, args ...string) (map[string]any, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Env = remoteExecEnv()
	out, err := cmd.Output()
	result := map[string]any{"stdout": strings.TrimSpace(string(out))}
	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			result["stderr"] = strings.TrimSpace(string(ee.Stderr))
			result["exit_code"] = ee.ExitCode()
		}
		return result, err
	}
	result["exit_code"] = 0
	return result, nil
}

func (r *Runner) remoteExecJournal() *remoteExecJournal {
	r.remoteExecMu.Lock()
	defer r.remoteExecMu.Unlock()
	if r.remoteExecLog == nil {
		dir := filepath.Join(r.Config().StateDir, "remote-exec")
		r.remoteExecLog = newRemoteExecJournal(dir)
	}
	return r.remoteExecLog
}
