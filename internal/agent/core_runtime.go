package agent

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

const (
	// coreRuntimeDigestCapability is advertised by kernels that expose
	// GET /runtime/status. Older kernels omit it and stay on the previous
	// file-only convergence behaviour so Agent can be upgraded first.
	coreRuntimeDigestCapability = "runtime_config_digest_v1"
	// coreRuntimeBuildIdentityCapability is advertised by kernels that report
	// their own build in GET /runtime/status. Older kernels may still be checked
	// when their JSON GET /version response carries the same build identity.
	coreRuntimeBuildIdentityCapability = "runtime_build_identity_v1"

	coreRuntimeVerificationVerified    = "verified"
	coreRuntimeVerificationUnsupported = "unsupported"
	coreRuntimeVerificationUnavailable = "unavailable"

	// coreBuildState* describe the running kernel executable relative to the
	// one installed on disk. Unknown is the safe default: it never triggers a
	// restart, which keeps old kernels and unreadable binaries untouched.
	coreBuildStateUnknown = "unknown"
	coreBuildStateCurrent = "current"
	coreBuildStateStale   = "stale"

	coreRuntimeVerifyTimeout = 12 * time.Second
)

// coreBuildIdentity fingerprints a kernel executable. Build is the value
// release manifests are keyed on; Commit disambiguates locally built kernels
// that share a build tag.
type coreBuildIdentity struct {
	Version string `json:"version"`
	Build   string `json:"build"`
	Commit  string `json:"commit"`
}

func (i coreBuildIdentity) empty() bool {
	return strings.TrimSpace(i.Build) == "" && strings.TrimSpace(i.Commit) == ""
}

func (i coreBuildIdentity) same(other coreBuildIdentity) bool {
	if i.empty() || other.empty() {
		return false
	}
	if strings.TrimSpace(i.Build) != strings.TrimSpace(other.Build) {
		return false
	}
	if strings.TrimSpace(i.Commit) != "" && strings.TrimSpace(other.Commit) != "" {
		return strings.TrimSpace(i.Commit) == strings.TrimSpace(other.Commit)
	}
	return true
}

func (i coreBuildIdentity) String() string {
	parts := make([]string, 0, 3)
	if v := strings.TrimSpace(i.Version); v != "" {
		parts = append(parts, v)
	}
	if b := strings.TrimSpace(i.Build); b != "" {
		parts = append(parts, "build "+b)
	}
	if c := strings.TrimSpace(i.Commit); c != "" {
		parts = append(parts, "commit "+c)
	}
	if len(parts) == 0 {
		return ""
	}
	return strings.Join(parts, " / ")
}

// coreBinaryIdentityCache avoids executing the kernel once every watchdog tick.
// The installed executable is replaced by rename, so a changed size or mtime is
// a reliable signal that the fingerprint has to be read again.
type coreBinaryIdentityCache struct {
	path     string
	size     int64
	modTime  time.Time
	identity coreBuildIdentity
	err      error
}

func parseCoreBuildIdentity(out string) (coreBuildIdentity, error) {
	trimmed := strings.TrimSpace(out)
	if !strings.HasPrefix(trimmed, "{") {
		return coreBuildIdentity{}, errors.New("core version output is not the oboard-sb JSON form")
	}
	var identity coreBuildIdentity
	if err := json.Unmarshal([]byte(trimmed), &identity); err != nil {
		return coreBuildIdentity{}, err
	}
	if identity.empty() {
		return coreBuildIdentity{}, errors.New("core version output carries no build identity")
	}
	return identity, nil
}

// installedCoreBuild reads the fingerprint of the kernel executable on disk,
// which is the build the next restart will start.
func (r *Runner) installedCoreBuild() (coreBuildIdentity, error) {
	binary := strings.TrimSpace(r.coreBinary())
	if binary == "" {
		return coreBuildIdentity{}, errors.New("core binary is not configured")
	}
	resolved := binary
	if !filepath.IsAbs(resolved) {
		if lookup, err := exec.LookPath(resolved); err == nil {
			resolved = lookup
		}
	}
	info, statErr := os.Stat(resolved)
	r.coreBinaryIdentityMu.Lock()
	defer r.coreBinaryIdentityMu.Unlock()
	cached := r.coreBinaryIdentity
	if statErr == nil && cached.path == resolved && cached.size == info.Size() && cached.modTime.Equal(info.ModTime()) {
		return cached.identity, cached.err
	}
	identity, err := readCoreBuildIdentity(resolved, r.commandTimeout())
	if statErr == nil {
		r.coreBinaryIdentity = coreBinaryIdentityCache{path: resolved, size: info.Size(), modTime: info.ModTime(), identity: identity, err: err}
	} else {
		r.coreBinaryIdentity = coreBinaryIdentityCache{}
	}
	return identity, err
}

func readCoreBuildIdentity(binary string, timeout time.Duration) (coreBuildIdentity, error) {
	out, err := commandOutput(timeout, binary, "-version")
	if err != nil {
		return coreBuildIdentity{}, fmt.Errorf("read core build identity: %w", err)
	}
	return parseCoreBuildIdentity(out)
}

// runtimeOnlyCoreMetadataKeys are the `_oboard` members that are pushed to the
// running kernel over the local API instead of requiring a restart. They stay
// outside the operational digest. The kernel implements the same list in
// minibox.NormalizeOperationalConfig; the two must not diverge.
var runtimeOnlyCoreMetadataKeys = []string{"rate_limits", "connection_audit"}

// normalizeOperationalCoreConfig returns the canonical JSON form of a kernel
// configuration with runtime-only metadata removed.
func normalizeOperationalCoreConfig(raw []byte) ([]byte, error) {
	if len(bytes.TrimSpace(raw)) == 0 {
		return nil, fmt.Errorf("core configuration is empty")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var root any
	if err := decoder.Decode(&root); err != nil {
		return nil, err
	}
	if _, err := decoder.Token(); err != io.EOF {
		return nil, fmt.Errorf("core configuration has trailing content")
	}
	object, ok := root.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("core configuration root must be a JSON object")
	}
	if metadata, ok := object["_oboard"].(map[string]any); ok {
		for _, key := range runtimeOnlyCoreMetadataKeys {
			delete(metadata, key)
		}
		if len(metadata) == 0 {
			delete(object, "_oboard")
		}
	}
	return json.Marshal(object)
}

// operationalCoreConfigDigest is the stable identity of the operational part of
// a kernel configuration. It is the value the kernel reports as
// operational_config_sha256.
func operationalCoreConfigDigest(raw []byte) (string, error) {
	normalized, err := normalizeOperationalCoreConfig(raw)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(normalized)
	return hex.EncodeToString(sum[:]), nil
}

type coreRuntimeStatus struct {
	OperationalDigest string `json:"operational_config_sha256"`
	StartedAt         string `json:"started_at"`
	PID               int    `json:"pid"`
	Generation        uint64 `json:"generation"`
	Version           string `json:"version"`
	Build             string `json:"build"`
	Commit            string `json:"commit"`
}

func (s coreRuntimeStatus) buildIdentity() coreBuildIdentity {
	return coreBuildIdentity{Version: s.Version, Build: s.Build, Commit: s.Commit}
}

// coreRuntimeCheck answers the only question that makes a deployment
// trustworthy: does the process that is actually serving traffic run the
// operational configuration and the executable Agent just installed?
type coreRuntimeCheck struct {
	// Verification is verified, unsupported (old kernel), or unavailable
	// (local API not reachable).
	Verification  string
	DesiredDigest string
	LoadedDigest  string
	PID           int
	Generation    uint64
	Err           error
	// BuildState is unknown, current, or stale, and describes the running
	// executable relative to the one installed on disk.
	BuildState     string
	RunningBuild   coreBuildIdentity
	InstalledBuild coreBuildIdentity
	BuildErr       error
}

func (c coreRuntimeCheck) verified() bool { return c.Verification == coreRuntimeVerificationVerified }

// drift is true only when the kernel positively reported a different
// configuration. An unsupported or unreachable kernel is never reported as
// drift, because that would restart healthy old kernels during a rolling
// upgrade.
func (c coreRuntimeCheck) drift() bool {
	return c.verified() && c.LoadedDigest != c.DesiredDigest
}

// binaryDrift is true only when the kernel positively identified itself as a
// different build from the executable on disk. Replacing the file leaves the
// running process on its original inode, so this is the state an upgrade
// silently produces when nothing restarts the service.
func (c coreRuntimeCheck) binaryDrift() bool {
	return c.BuildState == coreBuildStateStale
}

func (c coreRuntimeCheck) annotate(result map[string]any) {
	result["runtime_verified"] = c.verified()
	result["runtime_verification"] = c.Verification
	result["runtime_drift"] = c.drift()
	if c.LoadedDigest != "" {
		result["runtime_loaded_digest"] = c.LoadedDigest
	}
	if c.DesiredDigest != "" {
		result["runtime_desired_digest"] = c.DesiredDigest
	}
	if c.Err != nil {
		result["runtime_verification_error"] = c.Err.Error()
	}
	result["runtime_build_state"] = c.buildState()
	result["runtime_binary_drift"] = c.binaryDrift()
	if running := c.RunningBuild.String(); running != "" {
		result["runtime_running_build"] = running
	}
	if installed := c.InstalledBuild.String(); installed != "" {
		result["runtime_installed_build"] = installed
	}
	if c.BuildErr != nil {
		result["runtime_build_error"] = c.BuildErr.Error()
	}
}

func (c coreRuntimeCheck) buildState() string {
	if c.BuildState == "" {
		return coreBuildStateUnknown
	}
	return c.BuildState
}

func (r *Runner) coreAPIClient() *http.Client {
	if r.coreClient != nil {
		return r.coreClient
	}
	return unixHTTPClient(coreAPISocket)
}

func (r *Runner) coreKernelCapabilities(ctx context.Context) ([]string, error) {
	body, err := r.coreVersionPayload(ctx)
	if err != nil {
		return nil, err
	}
	var payload struct {
		Capabilities []string `json:"capabilities"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		return nil, err
	}
	return payload.Capabilities, nil
}

// coreVersionResponseLimit bounds the local /version body Agent reads. The
// kernel answers with a small object; anything larger is a bug or a wrong
// socket, not something to buffer.
const coreVersionResponseLimit = 64 << 10

// coreIdentityTimeout bounds the local API call behind the reported kernel
// version. The socket is on the same host, so a slow answer means the kernel is
// unhealthy and the on-disk fallback should take over quickly.
const coreIdentityTimeout = 3 * time.Second

func (r *Runner) coreVersionPayload(ctx context.Context) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://oboard-sb/version", nil)
	if err != nil {
		return nil, err
	}
	res, err := r.coreAPIClient().Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	if res.StatusCode >= 300 {
		return nil, fmt.Errorf("core version status %d", res.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(res.Body, coreVersionResponseLimit+1))
	if err != nil {
		return nil, err
	}
	if len(body) > coreVersionResponseLimit {
		return nil, errors.New("core version response exceeds limit")
	}
	return body, nil
}

func (r *Runner) runningCoreBuild(ctx context.Context) (coreBuildIdentity, error) {
	body, err := r.coreVersionPayload(ctx)
	if err != nil {
		return coreBuildIdentity{}, err
	}
	return parseCoreBuildIdentity(string(body))
}

// runningCoreIdentity reports the version and capabilities of the process that
// is actually serving traffic. The executable on disk answers a different
// question after an upgrade — it is the build the *next* restart will start —
// so reporting it as the node's kernel version hides a stale process behind a
// number that looks correct.
func (r *Runner) runningCoreIdentity(ctx context.Context) (string, []string, bool) {
	body, err := r.coreVersionPayload(ctx)
	if err != nil {
		return "", nil, false
	}
	identity := formatCoreVersion(string(body))
	if identity == "" || identity == "unknown" {
		return "", nil, false
	}
	return identity, parseKernelCapabilities(string(body)), true
}

// coreIdentity is what the panel shows as the node's kernel. It prefers the
// running process and falls back to the executable on disk only when the local
// API cannot answer, which is also the case where no process is serving.
func (r *Runner) coreIdentity() (string, []string) {
	ctx, cancel := context.WithTimeout(context.Background(), coreIdentityTimeout)
	defer cancel()
	if identity, capabilities, ok := r.runningCoreIdentity(ctx); ok {
		return identity, capabilities
	}
	return singBoxIdentity(r.coreBinary(), r.commandTimeout())
}

func (r *Runner) coreRuntimeStatus(ctx context.Context) (coreRuntimeStatus, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://oboard-sb/runtime/status", nil)
	if err != nil {
		return coreRuntimeStatus{}, err
	}
	res, err := r.coreAPIClient().Do(req)
	if err != nil {
		return coreRuntimeStatus{}, err
	}
	defer res.Body.Close()
	if res.StatusCode == http.StatusNotFound {
		return coreRuntimeStatus{}, errCoreRuntimeStatusUnsupported
	}
	if res.StatusCode >= 300 {
		return coreRuntimeStatus{}, fmt.Errorf("core runtime status %d", res.StatusCode)
	}
	var status coreRuntimeStatus
	if err := json.NewDecoder(res.Body).Decode(&status); err != nil {
		return coreRuntimeStatus{}, err
	}
	if status.OperationalDigest == "" {
		return coreRuntimeStatus{}, fmt.Errorf("core runtime status has no operational digest")
	}
	return status, nil
}

var errCoreRuntimeStatusUnsupported = fmt.Errorf("core does not expose %s", coreRuntimeDigestCapability)

// resolveCoreBuildState compares the build serving traffic with the executable
// installed on disk. Both sides must identify themselves for a verdict: a
// running kernel whose runtime-status and legacy version responses omit build
// identity, or a binary Agent cannot execute, leaves the state unknown and
// never causes a watchdog restart.
func (r *Runner) resolveCoreBuildState(check *coreRuntimeCheck) {
	check.BuildState = coreBuildStateUnknown
	if check.RunningBuild.empty() {
		if check.BuildErr == nil {
			check.BuildErr = fmt.Errorf("core does not report %s", coreRuntimeBuildIdentityCapability)
		}
		return
	}
	installed, err := r.installedCoreBuild()
	if err != nil {
		check.BuildErr = err
		return
	}
	check.InstalledBuild = installed
	if installed.same(check.RunningBuild) {
		check.BuildState = coreBuildStateCurrent
		return
	}
	check.BuildState = coreBuildStateStale
}

// checkCoreRuntimeConfig compares the running kernel against the desired
// operational configuration exactly once.
func (r *Runner) checkCoreRuntimeConfig(ctx context.Context, desired []byte) coreRuntimeCheck {
	check := coreRuntimeCheck{Verification: coreRuntimeVerificationUnavailable, BuildState: coreBuildStateUnknown}
	digest, err := operationalCoreConfigDigest(desired)
	if err != nil {
		check.Err = err
		return check
	}
	check.DesiredDigest = digest
	status, err := r.coreRuntimeStatus(ctx)
	if err == nil {
		check.Verification = coreRuntimeVerificationVerified
		check.LoadedDigest = status.OperationalDigest
		check.PID = status.PID
		check.Generation = status.Generation
		check.RunningBuild = status.buildIdentity()
		r.resolveCoreBuildState(&check)
		return check
	}
	check.Err = err
	// A 404 is conclusive: the local API answered and has no runtime status.
	// Anything else may be a kernel that is still starting, so only treat an
	// explicitly missing capability as unsupported.
	if err == errCoreRuntimeStatusUnsupported {
		check.Verification = coreRuntimeVerificationUnsupported
		check.Err = nil
		check.RunningBuild, check.BuildErr = r.runningCoreBuild(ctx)
		r.resolveCoreBuildState(&check)
		return check
	}
	capabilities, capErr := r.coreKernelCapabilities(ctx)
	if capErr == nil {
		for _, capability := range capabilities {
			if capability == coreRuntimeDigestCapability {
				return check
			}
		}
		check.Verification = coreRuntimeVerificationUnsupported
		check.Err = nil
	}
	return check
}

// coreRuntimeVerifyWindow bounds how long Agent waits for the kernel to report
// the desired configuration. When Agent does not manage the process lifecycle
// there is nothing to wait for, so a single check is taken.
func (r *Runner) coreRuntimeVerifyWindow() time.Duration {
	if !r.managedRestartEnabled() {
		return 0
	}
	return coreRuntimeVerifyTimeout
}

// awaitCoreRuntimeConfig polls the kernel until it reports the desired
// operational digest. It is used after a restart, where the local API needs a
// moment to come back. A non-positive timeout performs exactly one check.
func (r *Runner) awaitCoreRuntimeConfig(ctx context.Context, desired []byte, timeout time.Duration) coreRuntimeCheck {
	if timeout <= 0 {
		return r.checkCoreRuntimeConfig(ctx, desired)
	}
	deadline := time.Now().Add(timeout)
	check := r.checkCoreRuntimeConfig(ctx, desired)
	for {
		if check.Verification == coreRuntimeVerificationUnsupported {
			return check
		}
		if check.verified() && !check.drift() {
			return check
		}
		if !time.Now().Before(deadline) || ctx.Err() != nil {
			return check
		}
		select {
		case <-ctx.Done():
			return check
		case <-time.After(400 * time.Millisecond):
		}
		check = r.checkCoreRuntimeConfig(ctx, desired)
	}
}

// awaitCoreRuntimeActivation polls the kernel until it reports both the desired
// operational digest and the installed build. It is used after a kernel binary
// upgrade, where converged configuration alone is not evidence that the new
// executable is the one serving traffic.
func (r *Runner) awaitCoreRuntimeActivation(ctx context.Context, desired []byte, timeout time.Duration) coreRuntimeCheck {
	if timeout <= 0 {
		return r.checkCoreRuntimeConfig(ctx, desired)
	}
	deadline := time.Now().Add(timeout)
	check := r.checkCoreRuntimeConfig(ctx, desired)
	for {
		if check.Verification == coreRuntimeVerificationUnsupported {
			return check
		}
		if check.verified() && !check.drift() && !check.binaryDrift() {
			return check
		}
		if !time.Now().Before(deadline) || ctx.Err() != nil {
			return check
		}
		select {
		case <-ctx.Done():
			return check
		case <-time.After(400 * time.Millisecond):
		}
		check = r.checkCoreRuntimeConfig(ctx, desired)
	}
}

// restartCoreForRuntimeDrift restarts the kernel and confirms that the restarted
// process actually loaded the desired operational configuration.
func (r *Runner) restartCoreForRuntimeDrift(ctx context.Context, desired []byte) (coreRuntimeCheck, error) {
	if err := r.restartCore(); err != nil {
		return coreRuntimeCheck{Verification: coreRuntimeVerificationUnavailable, Err: err}, err
	}
	if r.managedRestartEnabled() {
		if err := r.waitCoreServiceStable(3 * time.Second); err != nil {
			return coreRuntimeCheck{Verification: coreRuntimeVerificationUnavailable, Err: err}, err
		}
	}
	return r.awaitCoreRuntimeConfig(ctx, desired, r.coreRuntimeVerifyWindow()), nil
}

// coreRuntimeConverged reports whether the running kernel serves the
// configuration currently on disk.
//
// It exists for the idempotent-replay paths. Version bookkeeping alone is not
// evidence of convergence: last-applied-version.json records what Agent wrote,
// not what the process loaded, so a replay that trusts it can keep reporting
// "already applied" over a kernel that never picked the change up. When this
// returns false the caller runs the full apply, which verifies the runtime and
// restarts the kernel if it has drifted.
//
// A kernel that is unreachable or too old to report its configuration is never
// treated as drifted, so this only ever forces the work that the non-replay
// path would have done anyway.
func (r *Runner) coreRuntimeConverged(ctx context.Context) bool {
	// #nosec G304 -- a fixed file below the Agent's configured state directory.
	desired, err := os.ReadFile(filepath.Join(r.stateDir(), "sing-box.json"))
	if err != nil || len(bytes.TrimSpace(desired)) == 0 {
		return false
	}
	return !r.checkCoreRuntimeConfig(ctx, desired).drift()
}

// activateInstalledCore makes the kernel executable on disk the one that serves
// traffic. Installing a release replaces the file, but the running process keeps
// the inode it was started from, so an upgrade is only complete once the service
// has been restarted onto the new build.
//
// binaryReplaced is the fallback signal for kernels that cannot report their own
// build: without a verdict from the process, a changed file on disk is the only
// evidence available.
func (r *Runner) activateInstalledCore(ctx context.Context, binaryReplaced bool) (map[string]any, error) {
	r.coreLifecycleMu.Lock()
	defer r.coreLifecycleMu.Unlock()
	return r.activateInstalledCoreLocked(ctx, binaryReplaced)
}

// activateInstalledCoreLocked runs while the caller holds coreLifecycleMu.
// update_agent keeps the lock across atomic installation and activation so the
// watchdog cannot race the file replacement.
func (r *Runner) activateInstalledCoreLocked(ctx context.Context, binaryReplaced bool) (map[string]any, error) {
	result := map[string]any{}
	if !r.managedRestartEnabled() {
		result["core_activation"] = "unmanaged"
		result["core_activation_note"] = "restart_command is \"none\"; restart the kernel out of band to activate the installed build"
		return result, nil
	}
	configPath := filepath.Join(r.stateDir(), "sing-box.json")
	// #nosec G304 -- configPath is a fixed file below the Agent's configured state directory.
	desired, readErr := os.ReadFile(configPath)
	if readErr != nil || len(bytes.TrimSpace(desired)) == 0 {
		// Nothing is deployed yet, so the next apply will start the new build.
		result["core_activation"] = "waiting_for_config"
		return result, nil
	}

	before := r.checkCoreRuntimeConfig(ctx, desired)
	if running := before.RunningBuild.String(); running != "" {
		result["core_running_build_before"] = running
	}
	if installed := before.InstalledBuild.String(); installed != "" {
		result["core_installed_build"] = installed
	}
	result["core_build_state_before"] = before.buildState()
	switch {
	case before.binaryDrift():
		// The running process positively identified itself as an older build.
	case before.BuildState == coreBuildStateCurrent:
		result["core_activation"] = "already_current"
		return result, nil
	case !binaryReplaced:
		result["core_activation"] = "not_required"
		return result, nil
	}
	if err := validateSingBox(r.coreBinary(), configPath, r.commandTimeout()); err != nil {
		// Restarting onto a kernel that rejects the live configuration would
		// turn a stale-but-serving node into an outage.
		result["core_activation"] = "invalid_config"
		result["core_activation_error"] = err.Error()
		return result, fmt.Errorf("installed kernel rejected the active configuration: %w", err)
	}
	if err := r.restartCore(); err != nil {
		result["core_activation"] = "restart_failed"
		result["core_activation_error"] = err.Error()
		return result, fmt.Errorf("restart core to activate the installed build: %w", err)
	}
	if err := r.waitCoreServiceStable(3 * time.Second); err != nil {
		result["core_activation"] = "crashed_after_restart"
		result["core_activation_error"] = err.Error()
		return result, fmt.Errorf("core did not stay running after activating the installed build: %w", err)
	}
	after := r.awaitCoreRuntimeActivation(ctx, desired, r.coreRuntimeVerifyWindow())
	if running := after.RunningBuild.String(); running != "" {
		result["core_running_build_after"] = running
	}
	result["core_build_state_after"] = after.buildState()
	if after.binaryDrift() {
		result["core_activation"] = "still_stale"
		return result, fmt.Errorf("core still runs %s after restart, expected %s", after.RunningBuild.String(), after.InstalledBuild.String())
	}
	if after.drift() {
		result["core_activation"] = "config_drift"
		return result, fmt.Errorf("core runs configuration %s after restart, expected %s", after.LoadedDigest, after.DesiredDigest)
	}
	result["core_activation"] = "restarted"
	return result, nil
}

// coreRuntimeMetadataOnlyChange reports whether two kernel configurations
// differ only in runtime-only metadata, which can be pushed to the running
// kernel without restarting it.
func coreRuntimeMetadataOnlyChange(previous, next []byte) (bool, error) {
	if len(previous) == 0 || len(next) == 0 {
		return false, nil
	}
	previousOperational, err := normalizeOperationalCoreConfig(previous)
	if err != nil {
		return false, err
	}
	nextOperational, err := normalizeOperationalCoreConfig(next)
	if err != nil {
		return false, err
	}
	if !bytes.Equal(previousOperational, nextOperational) {
		return false, nil
	}
	return !bytes.Equal(bytes.TrimSpace(previous), bytes.TrimSpace(next)), nil
}
