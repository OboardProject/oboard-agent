package agent

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/OboardProject/oboard-agent/internal/model"
	"golang.org/x/net/proxy"
)

// This helper exercises production apply/version code in a separate process.
// The parent owns the real kernel so an Agent exit does not stop the data plane.
func TestProcessFaultHelper(t *testing.T) {
	mode := os.Getenv("OBOARD_FAULT_HELPER")
	if mode == "" {
		return
	}
	state := os.Getenv("OBOARD_FAULT_STATE")
	data, err := os.ReadFile(filepath.Join(state, "request.json"))
	if err != nil {
		t.Fatal(err)
	}
	var request struct {
		Version int64
		Config  string
	}
	if err := json.Unmarshal(data, &request); err != nil {
		t.Fatal(err)
	}
	r := New(Config{StateDir: state, CoreBinary: os.Getenv("OBOARD_PROCESS_KERNEL"), CoreSocket: filepath.Join(state, "k.sock"), ResourceProfile: "large", RestartCommand: "none", ReloadCommand: "none", TimeSyncCommand: "none"})
	r.coreRestartCommand = func() error {
		client := &http.Client{Timeout: 10 * time.Second}
		resp, err := client.Post(os.Getenv("OBOARD_FAULT_SUPERVISOR"), "application/json", nil)
		if err != nil {
			return fmt.Errorf("supervisor restart unavailable")
		}
		defer resp.Body.Close()
		if resp.StatusCode != 200 {
			return fmt.Errorf("supervisor restart rejected")
		}
		return nil
	}
	if mode == "before-version" {
		result, err := r.applyCoreConfigUnlocked(request.Version, request.Config, false)
		if err != nil || result["runtime_verified"] != true {
			t.Fatalf("apply before version barrier failed: %v", err)
		}
		os.Exit(73)
	}
	if mode == "partial-deployment" {
		status, raw := r.executeDeploymentTask(model.DeploymentTaskPayload{Version: request.Version, Config: model.ApplyCoreConfigTaskPayload{Config: request.Config}, ConfigChanged: true, PortForwards: model.PortForwardPlan{Version: request.Version, Rules: []model.PortForward{{ID: 1, Enabled: true, Backend: "invalid-fault-backend", Protocol: "tcp", ListenIP: "127.0.0.1", ListenPort: 1, TargetAddress: "127.0.0.1", TargetPort: 1}}}})
		var result struct {
			Steps []deploymentStepResult `json:"steps"`
		}
		if err := json.Unmarshal([]byte(raw), &result); err != nil {
			t.Fatal(err)
		}
		coreOK, forwardFailed := false, false
		for _, step := range result.Steps {
			if step.Key == "config" && step.Status == "succeeded" {
				coreOK = true
			}
			if step.Key == "port_forwards" && step.Status == "failed" {
				forwardFailed = true
			}
		}
		if status != "failed" || !coreOK || !forwardFailed {
			t.Fatalf("expected core success then forward failure: status=%s core=%v forward=%v", status, coreOK, forwardFailed)
		}
		return
	}
	result, err := r.applyCoreConfigTask(request.Version, model.ApplyCoreConfigTaskPayload{Config: request.Config})
	if err != nil {
		t.Fatalf("configuration apply failed: %v", err)
	}
	if mode == "lost-result" {
		os.Exit(73)
	}
	data, err = json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(state, "result.json"), data, 0600); err != nil {
		t.Fatal(err)
	}
}

type faultKernel struct {
	mu            sync.Mutex
	command       *exec.Cmd
	binary, state string
}

func (k *faultKernel) stop() {
	if k.command != nil {
		_ = k.command.Process.Kill()
		_ = k.command.Wait()
		k.command = nil
	}
}
func (k *faultKernel) restart() error {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.stop()
	_ = os.Remove(filepath.Join(k.state, "k.sock"))
	k.command = exec.Command(k.binary, "-config", filepath.Join(k.state, "sing-box.json"), "-api", "unix:"+filepath.Join(k.state, "k.sock"))
	if err := k.command.Start(); err != nil {
		k.command = nil
		return err
	}
	client := unixHTTPClient(filepath.Join(k.state, "k.sock"))
	client.Timeout = 200 * time.Millisecond
	defer client.CloseIdleConnections()
	deadline := time.Now().Add(8 * time.Second)
	for time.Now().Before(deadline) {
		resp, err := client.Get("http://unix/runtime/status")
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode == 200 {
				return nil
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
	return fmt.Errorf("kernel readiness deadline exceeded")
}

func TestRealKernelProcessFaults(t *testing.T) {
	binary := os.Getenv("OBOARD_PROCESS_KERNEL")
	if binary == "" {
		t.Skip("opt-in: scripts/verify-process-faults.sh requires a real kernel binary")
	}
	bytes, err := os.ReadFile(binary)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("kernel_sha256=%x", sha256.Sum256(bytes))
	state, err := os.MkdirTemp("", "pf-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(state) })
	// Darwin Unix socket paths are limited to 104 bytes, including the terminator.
	if len(filepath.Join(state, "k.sock")) >= 104 {
		t.Fatal("set GOTMPDIR/TMPDIR to a short task-owned directory")
	}
	k := &faultKernel{binary: binary, state: state}
	t.Cleanup(func() { k.mu.Lock(); defer k.mu.Unlock(); k.stop() })
	supervisor := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			w.WriteHeader(405)
			return
		}
		if k.restart() != nil {
			w.WriteHeader(500)
			return
		}
		w.WriteHeader(200)
	}))
	defer supervisor.Close()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	listener.Close()
	config := func(label string) string {
		return fmt.Sprintf(`{"log":{"level":"error"},"inbounds":[{"type":"socks","tag":"%s","listen":"127.0.0.1","listen_port":%d}],"outbounds":[{"type":"direct","tag":"direct"}]}`, label, port)
	}
	run := func(t *testing.T, mode string, version int64, cfg string) map[string]any {
		t.Helper()
		data, _ := json.Marshal(map[string]any{"Version": version, "Config": cfg})
		if err := os.WriteFile(filepath.Join(state, "request.json"), data, 0600); err != nil {
			t.Fatal(err)
		}
		_ = os.Remove(filepath.Join(state, "result.json"))
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		command := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestProcessFaultHelper$", "-test.v")
		command.Env = append(os.Environ(), "OBOARD_FAULT_HELPER="+mode, "OBOARD_FAULT_STATE="+state, "OBOARD_FAULT_SUPERVISOR="+supervisor.URL, "OBOARD_DISABLE_PUBLIC_IP_DETECT=1")
		output, err := command.CombinedOutput()
		if mode == "lost-result" || mode == "before-version" {
			exit, ok := err.(*exec.ExitError)
			if !ok || exit.ExitCode() != 73 {
				t.Fatalf("barrier exit missing: %v %s", err, output)
			}
		} else if err != nil {
			t.Fatalf("helper failed: %v %s", err, output)
		}
		data, err = os.ReadFile(filepath.Join(state, "result.json"))
		if err != nil {
			return nil
		}
		var result map[string]any
		if err = json.Unmarshal(data, &result); err != nil {
			t.Fatal(err)
		}
		return result
	}
	check := func(t *testing.T, cfg string) int {
		t.Helper()
		r := New(Config{StateDir: state, CoreBinary: binary, CoreSocket: filepath.Join(state, "k.sock"), ResourceProfile: "large"})
		check := r.checkCoreRuntimeConfig(context.Background(), []byte(cfg))
		if !check.verified() || check.drift() {
			t.Fatalf("runtime not converged: verification=%s", check.Verification)
		}
		client := unixHTTPClient(filepath.Join(state, "k.sock"))
		defer client.CloseIdleConnections()
		resp, err := client.Get("http://unix/runtime/status")
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		var status struct {
			PID int `json:"pid"`
		}
		if err = json.NewDecoder(resp.Body).Decode(&status); err != nil || status.PID <= 0 {
			t.Fatal("missing runtime PID")
		}
		target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, "real-data-plane") }))
		defer target.Close()
		dialer, err := proxy.SOCKS5("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)), nil, &net.Dialer{Timeout: time.Second})
		if err != nil {
			t.Fatal(err)
		}
		transport := &http.Transport{Dial: dialer.Dial}
		defer transport.CloseIdleConnections()
		hc := &http.Client{Transport: transport, Timeout: 2 * time.Second}
		response, err := hc.Get(target.URL)
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
		body, _ := io.ReadAll(io.LimitReader(response.Body, 64))
		if string(body) != "real-data-plane" {
			t.Fatal("SOCKS path did not complete target work")
		}
		t.Logf("runtime_pid=%d operational_digest=%s", status.PID, check.LoadedDigest)
		return status.PID
	}
	t.Run("B_lost_result_replay", func(t *testing.T) {
		run(t, "lost-result", 10, config("v10"))
		pid := check(t, config("v10"))
		result := run(t, "apply", 10, config("v10"))
		if result["idempotent_replay"] != true {
			t.Fatal("replay not confirmed")
		}
		if check(t, config("v10")) != pid {
			t.Fatal("replay restarted converged kernel")
		}
	})
	t.Run("C_new_before_old", func(t *testing.T) {
		run(t, "apply", 12, config("v12"))
		pid := check(t, config("v12"))
		result := run(t, "apply", 11, config("v11"))
		if result["superseded"] != true {
			t.Fatal("old task not superseded")
		}
		if check(t, config("v12")) != pid {
			t.Fatal("old task changed running process")
		}
	})
	t.Run("D_partial_deployment", func(t *testing.T) {
		run(t, "apply", 12, config("v12"))
		check(t, config("v12"))
		before, err := os.ReadFile(filepath.Join(state, appliedVersionStateFile))
		if err != nil {
			t.Fatal(err)
		}
		run(t, "partial-deployment", 13, config("v13"))
		check(t, config("v13"))
		after, err := os.ReadFile(filepath.Join(state, appliedVersionStateFile))
		if err != nil || string(before) != string(after) {
			t.Fatal("failed deployment advanced version state")
		}
		run(t, "apply", 14, config("v14"))
		check(t, config("v14"))
	})
	t.Run("E_exit_before_version_persist", func(t *testing.T) {
		run(t, "apply", 14, config("v14"))
		check(t, config("v14"))
		before, err := os.ReadFile(filepath.Join(state, appliedVersionStateFile))
		if err != nil {
			t.Fatal(err)
		}
		run(t, "before-version", 15, config("v15"))
		after, err := os.ReadFile(filepath.Join(state, appliedVersionStateFile))
		if err != nil || string(before) != string(after) {
			t.Fatal("exit barrier unexpectedly persisted version state")
		}
		pid := check(t, config("v15"))
		result := run(t, "apply", 15, config("v15"))
		if result["idempotent_replay"] == true {
			t.Fatal("unpersisted version claimed replay")
		}
		if check(t, config("v15")) != pid {
			t.Fatal("recovery unnecessarily restarted correct kernel")
		}
		if run(t, "apply", 15, config("v15"))["idempotent_replay"] != true {
			t.Fatal("recovery did not persist version")
		}
	})
}

func TestRealKernelBuildReplacement(t *testing.T) {
	oldBinary, newBinary := os.Getenv("OBOARD_PROCESS_KERNEL"), os.Getenv("OBOARD_PROCESS_KERNEL_NEXT")
	if oldBinary == "" || newBinary == "" {
		t.Skip("opt-in: verify-process-faults.sh --build requires two distinct real kernel builds")
	}
	oldBuild, err := readCoreBuildIdentity(oldBinary, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	newBuild, err := readCoreBuildIdentity(newBinary, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if oldBuild.empty() || newBuild.empty() || oldBuild.same(newBuild) {
		t.Fatal("two distinct nonempty real kernel build identities required")
	}
	state, err := os.MkdirTemp("", "pf-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(state) })
	if len(filepath.Join(state, "k.sock")) >= 104 {
		t.Fatal("temporary socket path too long")
	}
	installed := filepath.Join(state, "oboard-sb")
	replace := func(source string) {
		t.Helper()
		data, err := os.ReadFile(source)
		if err != nil {
			t.Fatal(err)
		}
		t.Logf("binary_sha256=%x", sha256.Sum256(data))
		next := installed + ".next"
		if err = os.WriteFile(next, data, 0700); err != nil {
			t.Fatal(err)
		}
		if err = os.Rename(next, installed); err != nil {
			t.Fatal(err)
		}
	}
	replace(oldBinary)
	cfg := []byte(`{"log":{"level":"error"}}`)
	if err = os.WriteFile(filepath.Join(state, "sing-box.json"), cfg, 0600); err != nil {
		t.Fatal(err)
	}
	k := &faultKernel{binary: installed, state: state}
	t.Cleanup(func() { k.mu.Lock(); defer k.mu.Unlock(); k.stop() })
	if err = k.restart(); err != nil {
		t.Fatal(err)
	}
	r := New(Config{StateDir: state, CoreBinary: installed, CoreSocket: filepath.Join(state, "k.sock"), ResourceProfile: "large"})
	before := r.checkCoreRuntimeConfig(context.Background(), cfg)
	if !before.verified() || before.BuildState != coreBuildStateCurrent {
		t.Fatal("initial running build not verified")
	}
	replace(newBinary)
	// A fresh Agent must inspect the running process, not trust replacement bytes.
	r = New(Config{StateDir: state, CoreBinary: installed, CoreSocket: filepath.Join(state, "k.sock"), ResourceProfile: "large"})
	stale := r.checkCoreRuntimeConfig(context.Background(), cfg)
	if !stale.binaryDrift() || stale.PID != before.PID || !stale.RunningBuild.same(oldBuild) || !stale.InstalledBuild.same(newBuild) {
		t.Fatal("disk replacement incorrectly reported as running new build")
	}
	if err = k.restart(); err != nil {
		t.Fatal(err)
	}
	after := r.checkCoreRuntimeConfig(context.Background(), cfg)
	if after.BuildState != coreBuildStateCurrent || !after.RunningBuild.same(newBuild) || after.PID == before.PID {
		t.Fatal("restart did not confirm new running build")
	}
}

// This tests the real kernel Unix authorization API and TCP data plane. It does
// not simulate a Controller WebSocket reconnect or claim Agent transport coverage.
func TestRealKernelAuthorizationFaults(t *testing.T) {
	binary := os.Getenv("OBOARD_PROCESS_KERNEL")
	if binary == "" {
		t.Skip("opt-in: real kernel required")
	}
	state, err := os.MkdirTemp("", "pf-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(state) })
	if len(filepath.Join(state, "k.sock")) >= 104 {
		t.Fatal("temporary socket path too long")
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	listener.Close()
	now := time.Now().UTC()
	lease := func(revision int64, end time.Time) map[string]any {
		return map[string]any{"revision": revision, "issued_at": now.Format(time.RFC3339Nano), "expires_at": end.Format(time.RFC3339Nano), "grants": map[string]string{"test-key": end.Format(time.RFC3339Nano), "expiry-key": end.Format(time.RFC3339Nano)}}
	}
	oldLease := lease(1, now.Add(time.Minute))
	cfg := map[string]any{
		"log":       map[string]any{"level": "error"},
		"inbounds":  []any{map[string]any{"type": "socks", "tag": "in-test", "listen": "127.0.0.1", "listen_port": port, "users": []any{map[string]string{"username": "test-user", "password": "synthetic-password"}, map[string]string{"username": "expiry-user", "password": "synthetic-password"}}}},
		"outbounds": []any{map[string]string{"type": "direct", "tag": "direct"}},
		"_oboard":   map[string]any{"authorization": oldLease, "rate_limits": map[string]any{"users": map[string]any{"test-user": map[string]any{"user_id": 1, "authorization_key": "test-key"}, "expiry-user": map[string]any{"user_id": 2, "authorization_key": "expiry-key"}}}},
	}
	data, _ := json.Marshal(cfg)
	if err := os.WriteFile(filepath.Join(state, "sing-box.json"), data, 0600); err != nil {
		t.Fatal(err)
	}
	k := &faultKernel{binary: binary, state: state}
	t.Cleanup(func() { k.mu.Lock(); defer k.mu.Unlock(); k.stop() })
	if err := k.restart(); err != nil {
		t.Fatal(err)
	}
	client := unixHTTPClient(filepath.Join(state, "k.sock"))
	client.Timeout = 2 * time.Second
	defer client.CloseIdleConnections()
	post := func(path string, body any) int {
		t.Helper()
		raw, _ := json.Marshal(body)
		resp, err := client.Post("http://unix"+path, "application/json", bytes.NewReader(raw))
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		return resp.StatusCode
	}
	// An echo target keeps an established authenticated stream open across denial.
	target, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var workers sync.WaitGroup
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			c, err := target.Accept()
			if err != nil {
				return
			}
			workers.Add(1)
			go func() {
				defer workers.Done()
				defer c.Close()
				_ = c.SetDeadline(time.Now().Add(15 * time.Second))
				_, _ = io.Copy(c, c)
			}()
		}
	}()
	defer func() { target.Close(); <-done; workers.Wait() }()
	dialer, err := proxy.SOCKS5("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)), &proxy.Auth{User: "test-user", Password: "synthetic-password"}, &net.Dialer{Timeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	dial := func() (net.Conn, error) {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		return dialer.(proxy.ContextDialer).DialContext(ctx, "tcp", target.Addr().String())
	}
	echo := func(c net.Conn) error {
		_ = c.SetDeadline(time.Now().Add(time.Second))
		if _, err := c.Write([]byte("proof")); err != nil {
			return err
		}
		got := make([]byte, 5)
		_, err := io.ReadFull(c, got)
		if err == nil && string(got) != "proof" {
			return fmt.Errorf("wrong target response")
		}
		return err
	}
	allowed := func() net.Conn {
		t.Helper()
		c, err := dial()
		if err != nil {
			t.Fatal(err)
		}
		if err := echo(c); err != nil {
			c.Close()
			t.Fatal(err)
		}
		return c
	}
	denied := func() {
		t.Helper()
		c, err := dial()
		if err == nil {
			defer c.Close()
			if echo(c) == nil {
				t.Fatal("revoked credential passed real SOCKS data plane")
			}
		}
	}
	live := allowed()
	defer live.Close()
	if post("/authorization/deny", map[string]any{"keys": []string{"test-key"}, "revision": 2}) != 200 {
		t.Fatal("deny rejected")
	}
	if echo(live) == nil {
		t.Fatal("revocation left established stream usable")
	}
	denied()
	code := post("/authorization/config", map[string]any{"lease": oldLease})
	if code != 200 && code != 409 {
		t.Fatalf("unexpected stale delivery status %d", code)
	}
	denied()
	if err := k.restart(); err != nil {
		t.Fatal(err)
	}
	denied() // startup still carries the original grant; persisted denial wins.
	// A separate, never-revoked identity expires without further updates.
	dialer, err = proxy.SOCKS5("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)), &proxy.Auth{User: "expiry-user", Password: "synthetic-password"}, &net.Dialer{Timeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	end := time.Now().Add(1500 * time.Millisecond)
	if post("/authorization/config", map[string]any{"lease": lease(3, end)}) != 200 {
		t.Fatal("fresh grant rejected")
	}
	fresh := allowed()
	defer fresh.Close()
	timer := time.NewTimer(time.Until(end) + 100*time.Millisecond)
	defer timer.Stop()
	<-timer.C
	if echo(fresh) == nil {
		t.Fatal("expired lease left established stream usable")
	}
	denied()
	resp, err := client.Get("http://unix/runtime/status")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var status struct {
		PID    int    `json:"pid"`
		Digest string `json:"operational_config_sha256"`
	}
	if json.NewDecoder(resp.Body).Decode(&status) != nil || status.PID <= 0 || status.Digest == "" {
		t.Fatal("missing real runtime evidence")
	}
	t.Logf("runtime_pid=%d operational_digest=%s: revoke, stale grant, restart denial, offline expiry verified", status.PID, status.Digest)
}
