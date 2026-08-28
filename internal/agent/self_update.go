package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/OboardProject/oboard-agent/internal/security"
	"github.com/OboardProject/oboard-agent/internal/version"
)

const (
	maxReleaseManifestBytes  = 1 << 20
	maxReleaseSignatureBytes = 16 << 10
	maxReleaseBinaryBytes    = 256 << 20
	releaseUpdateTimeout     = 4 * time.Minute
	releaseDownloadAttempts  = 3
)

var (
	errTooManyReleaseRedirects  = errors.New("too many release redirects")
	errReleaseRedirectDowngrade = errors.New("release redirect attempted to downgrade HTTPS")
)

type releaseDownloadPolicy struct {
	attempts    int
	retryDelays []time.Duration
}

var defaultReleaseDownloadPolicy = releaseDownloadPolicy{
	attempts:    releaseDownloadAttempts,
	retryDelays: []time.Duration{time.Second, 2 * time.Second},
}

type signedReleaseTargets struct {
	Agent string
	Core  string
}

func (r *Runner) signedReleaseTargets() (signedReleaseTargets, error) {
	agentPath, err := os.Executable()
	if err != nil {
		return signedReleaseTargets{}, err
	}
	if resolved, err := filepath.EvalSymlinks(agentPath); err == nil {
		agentPath = resolved
	}
	agentPath, err = filepath.Abs(agentPath)
	if err != nil {
		return signedReleaseTargets{}, err
	}
	if filepath.Base(agentPath) != "oboard-agent" {
		return signedReleaseTargets{}, fmt.Errorf("refusing to update unexpected agent executable %s", agentPath)
	}
	corePath := strings.TrimSpace(r.coreBinary())
	if !filepath.IsAbs(corePath) {
		if resolved, lookupErr := exec.LookPath(corePath); lookupErr == nil {
			corePath = resolved
		} else {
			corePath = filepath.Join(filepath.Dir(agentPath), "oboard-sb")
		}
	}
	if resolved, err := filepath.EvalSymlinks(corePath); err == nil {
		corePath = resolved
	}
	if filepath.Base(corePath) != "oboard-sb" {
		corePath = filepath.Join(filepath.Dir(corePath), "oboard-sb")
	}
	if !filepath.IsAbs(corePath) {
		return signedReleaseTargets{}, errors.New("resolved core update path is not absolute")
	}
	return signedReleaseTargets{Agent: filepath.Clean(agentPath), Core: filepath.Clean(corePath)}, nil
}

func downloadAndInstallSignedRelease(ctx context.Context, baseClient *http.Client, baseURL, repo, expectedBuild string, targets signedReleaseTargets) (security.ReleaseManifest, error) {
	baseURL = strings.TrimRight(strings.TrimSpace(baseURL), "/")
	u, err := url.Parse(baseURL)
	if err != nil || u.Host == "" || (u.Scheme != "https" && u.Scheme != "http") {
		return security.ReleaseManifest{}, errors.New("invalid release base URL")
	}
	if targets.Agent == "" || targets.Core == "" || !filepath.IsAbs(targets.Agent) || !filepath.IsAbs(targets.Core) {
		return security.ReleaseManifest{}, errors.New("release install targets must be absolute")
	}
	ctx, cancel := context.WithTimeout(ctx, releaseUpdateTimeout)
	defer cancel()
	client := releaseHTTPClient(baseClient, u.Scheme == "https")
	tmpDir, err := os.MkdirTemp("", "oboard-signed-update.*")
	if err != nil {
		return security.ReleaseManifest{}, err
	}
	defer os.RemoveAll(tmpDir)

	manifestPath := filepath.Join(tmpDir, "release-manifest.json")
	signaturePath := filepath.Join(tmpDir, "release-manifest.json.sig")
	if err := downloadReleaseAsset(ctx, client, baseURL+"/release-manifest.json", manifestPath, maxReleaseManifestBytes, nil); err != nil {
		return security.ReleaseManifest{}, err
	}
	if err := downloadReleaseAsset(ctx, client, baseURL+"/release-manifest.json.sig", signaturePath, maxReleaseSignatureBytes, nil); err != nil {
		return security.ReleaseManifest{}, err
	}
	manifest, err := verifyDownloadedManifest(manifestPath, signaturePath, strings.TrimSpace(repo), strings.TrimSpace(expectedBuild))
	if err != nil {
		return security.ReleaseManifest{}, err
	}
	agentName := "oboard-agent-" + runtime.GOOS + "-" + runtime.GOARCH
	coreName := "oboard-sb-" + runtime.GOOS + "-" + runtime.GOARCH
	agentFile, err := validateManifestBinary(manifest, agentName, "agent")
	if err != nil {
		return security.ReleaseManifest{}, err
	}
	coreFile, err := validateManifestBinary(manifest, coreName, "sb")
	if err != nil {
		return security.ReleaseManifest{}, err
	}
	for _, file := range []security.ReleaseManifestFile{agentFile, coreFile} {
		if err := downloadReleaseAsset(ctx, client, baseURL+"/"+file.Name, filepath.Join(tmpDir, file.Name), maxReleaseBinaryBytes, &file); err != nil {
			return security.ReleaseManifest{}, err
		}
	}
	if err := ctx.Err(); err != nil {
		return security.ReleaseManifest{}, fmt.Errorf("release update stopped before verification: %w", err)
	}
	if err := VerifyReleaseFiles(manifestPath, signaturePath, tmpDir, runtime.GOOS, runtime.GOARCH, []string{agentName, coreName}); err != nil {
		return security.ReleaseManifest{}, err
	}
	if err := ctx.Err(); err != nil {
		return security.ReleaseManifest{}, fmt.Errorf("release update stopped before installation: %w", err)
	}
	if err := installVerifiedReleaseFiles(filepath.Join(tmpDir, agentName), filepath.Join(tmpDir, coreName), targets); err != nil {
		return security.ReleaseManifest{}, err
	}
	return manifest, nil
}

func releaseHTTPClient(base *http.Client, requireHTTPS bool) *http.Client {
	client := &http.Client{Timeout: 2 * time.Minute}
	if base != nil {
		client.Transport = base.Transport
	}
	client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if len(via) >= 5 {
			return errTooManyReleaseRedirects
		}
		if requireHTTPS && req.URL.Scheme != "https" {
			return errReleaseRedirectDowngrade
		}
		return nil
	}
	return client
}

func downloadReleaseAsset(ctx context.Context, client *http.Client, rawURL, path string, maxBytes int64, expected *security.ReleaseManifestFile) error {
	return downloadReleaseAssetWithPolicy(ctx, client, rawURL, path, maxBytes, expected, defaultReleaseDownloadPolicy)
}

func downloadReleaseAssetWithPolicy(ctx context.Context, client *http.Client, rawURL, path string, maxBytes int64, expected *security.ReleaseManifestFile, policy releaseDownloadPolicy) error {
	name := filepath.Base(path)
	attempts := policy.attempts
	if attempts < 1 {
		attempts = 1
	}
	var lastErr error
	for attempt := 1; attempt <= attempts; attempt++ {
		retryable, err := downloadReleaseAssetOnce(ctx, client, rawURL, path, maxBytes, expected)
		if err == nil {
			return nil
		}
		lastErr = err
		if ctxErr := ctx.Err(); ctxErr != nil {
			_ = os.Remove(path)
			return fmt.Errorf("download %s stopped after %d attempts: %w", name, attempt, ctxErr)
		}
		if !retryable {
			_ = os.Remove(path)
			return fmt.Errorf("download %s: %w", name, err)
		}
		if attempt == attempts {
			break
		}
		delay := time.Duration(0)
		if attempt-1 < len(policy.retryDelays) {
			delay = policy.retryDelays[attempt-1]
		}
		if err := waitReleaseRetry(ctx, delay); err != nil {
			_ = os.Remove(path)
			return fmt.Errorf("download %s stopped after %d attempts: %w", name, attempt, err)
		}
	}
	_ = os.Remove(path)
	return fmt.Errorf("download %s failed after %d attempts: %w", name, attempts, lastErr)
}

func downloadReleaseAssetOnce(ctx context.Context, client *http.Client, rawURL, path string, maxBytes int64, expected *security.ReleaseManifestFile) (bool, error) {
	resumeAt := int64(0)
	if expected != nil {
		if info, err := os.Stat(path); err == nil {
			if !info.Mode().IsRegular() || info.Size() < 0 || info.Size() >= expected.Size {
				_ = os.Remove(path)
			} else {
				resumeAt = info.Size()
			}
		} else if !errors.Is(err, os.ErrNotExist) {
			return false, err
		}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return false, err
	}
	if resumeAt > 0 {
		req.Header.Set("Range", fmt.Sprintf("bytes=%d-", resumeAt))
	}
	resp, err := client.Do(req)
	if err != nil {
		if ctx.Err() != nil || errors.Is(err, errTooManyReleaseRedirects) || errors.Is(err, errReleaseRedirectDowngrade) {
			return false, err
		}
		return true, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK && !(resumeAt > 0 && resp.StatusCode == http.StatusPartialContent) {
		return retryableReleaseStatus(resp.StatusCode), fmt.Errorf("returned %s", resp.Status)
	}
	if resumeAt > 0 && resp.StatusCode == http.StatusPartialContent && !validReleaseContentRange(resp.Header.Get("Content-Range"), resumeAt, expected.Size) {
		_ = os.Remove(path)
		return true, errors.New("resume response has an invalid content range")
	}
	if resumeAt > 0 && resp.StatusCode == http.StatusOK {
		// A compliant origin may ignore Range. Restart safely from byte zero
		// instead of appending a second full copy to the partial file.
		resumeAt = 0
	}
	if resp.ContentLength > maxBytes {
		return false, errors.New("response exceeds size limit")
	}
	if expected != nil && resp.ContentLength >= 0 && resp.ContentLength != expected.Size-resumeAt {
		return true, fmt.Errorf("response length %d does not match remaining signed size %d", resp.ContentLength, expected.Size-resumeAt)
	}
	// #nosec G304 -- path is a fixed file inside a newly created private update directory.
	flags := os.O_CREATE | os.O_WRONLY
	if resumeAt > 0 {
		flags |= os.O_APPEND
	} else {
		flags |= os.O_TRUNC
	}
	f, err := os.OpenFile(path, flags, 0o600)
	if err != nil {
		return false, err
	}
	complete := false
	keepPartial := false
	defer func() {
		_ = f.Close()
		if !complete && !keepPartial {
			_ = os.Remove(path)
		}
	}()
	readLimit := maxBytes - resumeAt
	if expected != nil && expected.Size < readLimit {
		readLimit = expected.Size - resumeAt
	}
	written, copyErr := io.Copy(f, io.LimitReader(resp.Body, readLimit+1))
	closeErr := f.Close()
	if copyErr != nil {
		var pathErr *os.PathError
		retryable := !errors.As(copyErr, &pathErr)
		keepPartial = retryable && expected != nil && resumeAt+written < expected.Size
		return retryable, copyErr
	}
	if closeErr != nil {
		return false, closeErr
	}
	if written > readLimit && expected != nil {
		return true, fmt.Errorf("response exceeds signed size %d", expected.Size)
	}
	if written > maxBytes {
		return false, errors.New("response exceeds size limit")
	}
	if resp.ContentLength >= 0 && written != resp.ContentLength {
		keepPartial = expected != nil && resumeAt+written < expected.Size
		return true, fmt.Errorf("received %d of %d bytes", written, resp.ContentLength)
	}
	if expected != nil {
		if resumeAt+written < expected.Size {
			keepPartial = true
			return true, fmt.Errorf("received %d of %d signed bytes", resumeAt+written, expected.Size)
		}
		sha, size, err := security.SHA256File(path)
		if err != nil {
			return false, err
		}
		if size != expected.Size || sha != expected.SHA256 {
			return true, fmt.Errorf("downloaded file does not match signed size or checksum")
		}
	}
	complete = true
	return false, nil
}

func validReleaseContentRange(value string, start, total int64) bool {
	value = strings.TrimSpace(value)
	var gotStart, gotEnd, gotTotal int64
	if n, err := fmt.Sscanf(value, "bytes %d-%d/%d", &gotStart, &gotEnd, &gotTotal); err != nil || n != 3 {
		return false
	}
	return value == fmt.Sprintf("bytes %d-%d/%d", gotStart, gotEnd, gotTotal) && gotStart == start && gotEnd == total-1 && gotTotal == total
}

func retryableReleaseStatus(status int) bool {
	return status == http.StatusRequestTimeout || status == http.StatusTooEarly || status == http.StatusTooManyRequests || status >= http.StatusInternalServerError
}

func waitReleaseRetry(ctx context.Context, delay time.Duration) error {
	if delay <= 0 {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
			return nil
		}
	}
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func verifyDownloadedManifest(manifestPath, signaturePath, repo, expectedBuild string) (security.ReleaseManifest, error) {
	// #nosec G304 -- both paths are fixed names inside the private update directory.
	b, err := os.ReadFile(manifestPath)
	if err != nil {
		return security.ReleaseManifest{}, err
	}
	var manifest security.ReleaseManifest
	if err := json.Unmarshal(b, &manifest); err != nil {
		return security.ReleaseManifest{}, err
	}
	// #nosec G304 -- both paths are fixed names inside the private update directory.
	sig, err := os.ReadFile(signaturePath)
	if err != nil {
		return security.ReleaseManifest{}, err
	}
	signature := strings.TrimSpace(string(sig))
	if version.ReleasePublicKey == "" || signature == "" {
		if !(version.IsDev() && security.EnvBool("OBOARD_ALLOW_UNSIGNED_DEV_UPDATE", false)) {
			return security.ReleaseManifest{}, errors.New("release manifest is unsigned or release public key is missing")
		}
	} else if err := security.VerifyReleaseManifest(manifest, signature, version.ReleasePublicKey); err != nil {
		return security.ReleaseManifest{}, err
	}
	if repo != "" && manifest.Repo != repo {
		return security.ReleaseManifest{}, fmt.Errorf("release manifest repo %q does not match %q", manifest.Repo, repo)
	}
	if expectedBuild != "" && manifest.Build != expectedBuild {
		return security.ReleaseManifest{}, fmt.Errorf("release build %q does not match expected build %q", manifest.Build, expectedBuild)
	}
	return manifest, nil
}

func validateManifestBinary(manifest security.ReleaseManifest, name, component string) (security.ReleaseManifestFile, error) {
	for _, file := range manifest.Files {
		if file.Name != name || file.OS != runtime.GOOS || file.Arch != runtime.GOARCH {
			continue
		}
		if file.Component != component || file.Size <= 0 || file.Size > maxReleaseBinaryBytes {
			return security.ReleaseManifestFile{}, fmt.Errorf("release manifest has invalid metadata for %s", name)
		}
		return file, nil
	}
	return security.ReleaseManifestFile{}, fmt.Errorf("release manifest does not contain %s", name)
}

type stagedReleaseFile struct {
	source string
	target string
	stage  string
	backup string
	hadOld bool
}

func installVerifiedReleaseFiles(agentSource, coreSource string, targets signedReleaseTargets) error {
	items := []stagedReleaseFile{{source: agentSource, target: targets.Agent}, {source: coreSource, target: targets.Core}}
	for i := range items {
		// #nosec G301 -- executable installation directories must remain searchable; files are installed atomically with 0755.
		if err := os.MkdirAll(filepath.Dir(items[i].target), 0o755); err != nil {
			return err
		}
		stage, err := copyReleaseFileBeside(items[i].source, items[i].target, ".oboard-update-new.*")
		if err != nil {
			cleanupStagedReleaseFiles(items)
			return err
		}
		items[i].stage = stage
		if _, err := os.Stat(items[i].target); err == nil {
			backup, err := copyReleaseFileBeside(items[i].target, items[i].target, ".oboard-update-backup.*")
			if err != nil {
				cleanupStagedReleaseFiles(items)
				return err
			}
			items[i].backup = backup
			items[i].hadOld = true
		} else if !errors.Is(err, os.ErrNotExist) {
			cleanupStagedReleaseFiles(items)
			return err
		}
	}
	for i := range items {
		if err := os.Rename(items[i].stage, items[i].target); err != nil {
			for _, installed := range items[:i] {
				if installed.hadOld {
					_ = os.Rename(installed.backup, installed.target)
				} else {
					_ = os.Remove(installed.target)
				}
			}
			cleanupStagedReleaseFiles(items)
			return err
		}
		items[i].stage = ""
	}
	cleanupStagedReleaseFiles(items)
	return nil
}

func copyReleaseFileBeside(source, target, pattern string) (string, error) {
	// #nosec G304 -- source is a verified file in the private update directory or an existing fixed binary target.
	in, err := os.Open(source)
	if err != nil {
		return "", err
	}
	defer in.Close()
	out, err := os.CreateTemp(filepath.Dir(target), pattern)
	if err != nil {
		return "", err
	}
	name := out.Name()
	ok := false
	defer func() {
		_ = out.Close()
		if !ok {
			_ = os.Remove(name)
		}
	}()
	if _, err := io.Copy(out, in); err != nil {
		return "", err
	}
	if err := out.Chmod(0o755); err != nil {
		return "", err
	}
	if err := out.Sync(); err != nil {
		return "", err
	}
	if err := out.Close(); err != nil {
		return "", err
	}
	ok = true
	return name, nil
}

func cleanupStagedReleaseFiles(items []stagedReleaseFile) {
	for _, item := range items {
		if item.stage != "" {
			_ = os.Remove(item.stage)
		}
		if item.backup != "" {
			_ = os.Remove(item.backup)
		}
	}
}
