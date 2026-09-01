package agent

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

const (
	// coreRuntimeDigestCapability is advertised by kernels that expose
	// GET /runtime/status. Older kernels omit it and stay on the previous
	// file-only convergence behaviour so Agent can be upgraded first.
	coreRuntimeDigestCapability = "runtime_config_digest_v1"

	coreRuntimeVerificationVerified    = "verified"
	coreRuntimeVerificationUnsupported = "unsupported"
	coreRuntimeVerificationUnavailable = "unavailable"

	coreRuntimeVerifyTimeout = 12 * time.Second
)

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
}

// coreRuntimeCheck answers the only question that makes a deployment
// trustworthy: does the process that is actually serving traffic run the
// operational configuration Agent just persisted?
type coreRuntimeCheck struct {
	// Verification is verified, unsupported (old kernel), or unavailable
	// (local API not reachable).
	Verification  string
	DesiredDigest string
	LoadedDigest  string
	PID           int
	Generation    uint64
	Err           error
}

func (c coreRuntimeCheck) verified() bool { return c.Verification == coreRuntimeVerificationVerified }

// drift is true only when the kernel positively reported a different
// configuration. An unsupported or unreachable kernel is never reported as
// drift, because that would restart healthy old kernels during a rolling
// upgrade.
func (c coreRuntimeCheck) drift() bool {
	return c.verified() && c.LoadedDigest != c.DesiredDigest
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
}

func (r *Runner) coreAPIClient() *http.Client {
	if r.coreClient != nil {
		return r.coreClient
	}
	return unixHTTPClient(coreAPISocket)
}

func (r *Runner) coreKernelCapabilities(ctx context.Context) ([]string, error) {
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
	var payload struct {
		Capabilities []string `json:"capabilities"`
	}
	if err := json.NewDecoder(res.Body).Decode(&payload); err != nil {
		return nil, err
	}
	return payload.Capabilities, nil
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

// checkCoreRuntimeConfig compares the running kernel against the desired
// operational configuration exactly once.
func (r *Runner) checkCoreRuntimeConfig(ctx context.Context, desired []byte) coreRuntimeCheck {
	check := coreRuntimeCheck{Verification: coreRuntimeVerificationUnavailable}
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
		return check
	}
	check.Err = err
	// A 404 is conclusive: the local API answered and has no runtime status.
	// Anything else may be a kernel that is still starting, so only treat an
	// explicitly missing capability as unsupported.
	if err == errCoreRuntimeStatusUnsupported {
		check.Verification = coreRuntimeVerificationUnsupported
		check.Err = nil
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
