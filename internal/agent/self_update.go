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
)

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
	client := releaseHTTPClient(baseClient, u.Scheme == "https")
	tmpDir, err := os.MkdirTemp("", "oboard-signed-update.*")
	if err != nil {
		return security.ReleaseManifest{}, err
	}
	defer os.RemoveAll(tmpDir)

	manifestPath := filepath.Join(tmpDir, "release-manifest.json")
	signaturePath := filepath.Join(tmpDir, "release-manifest.json.sig")
	if err := downloadReleaseAsset(ctx, client, baseURL+"/release-manifest.json", manifestPath, maxReleaseManifestBytes); err != nil {
		return security.ReleaseManifest{}, err
	}
	if err := downloadReleaseAsset(ctx, client, baseURL+"/release-manifest.json.sig", signaturePath, maxReleaseSignatureBytes); err != nil {
		return security.ReleaseManifest{}, err
	}
	manifest, err := verifyDownloadedManifest(manifestPath, signaturePath, strings.TrimSpace(repo), strings.TrimSpace(expectedBuild))
	if err != nil {
		return security.ReleaseManifest{}, err
	}
	agentName := "oboard-agent-" + runtime.GOOS + "-" + runtime.GOARCH
	coreName := "oboard-sb-" + runtime.GOOS + "-" + runtime.GOARCH
	if err := validateManifestBinary(manifest, agentName, "agent"); err != nil {
		return security.ReleaseManifest{}, err
	}
	if err := validateManifestBinary(manifest, coreName, "sb"); err != nil {
		return security.ReleaseManifest{}, err
	}
	for _, name := range []string{agentName, coreName} {
		if err := downloadReleaseAsset(ctx, client, baseURL+"/"+name, filepath.Join(tmpDir, name), maxReleaseBinaryBytes); err != nil {
			return security.ReleaseManifest{}, err
		}
	}
	if err := VerifyReleaseFiles(manifestPath, signaturePath, tmpDir, runtime.GOOS, runtime.GOARCH, []string{agentName, coreName}); err != nil {
		return security.ReleaseManifest{}, err
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
			return errors.New("too many release redirects")
		}
		if requireHTTPS && req.URL.Scheme != "https" {
			return errors.New("release redirect attempted to downgrade HTTPS")
		}
		return nil
	}
	return client
}

func downloadReleaseAsset(ctx context.Context, client *http.Client, rawURL, path string, maxBytes int64) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return err
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("download %s returned %s", filepath.Base(path), resp.Status)
	}
	if resp.ContentLength > maxBytes {
		return fmt.Errorf("download %s exceeds size limit", filepath.Base(path))
	}
	// #nosec G304 -- path is a fixed file inside a newly created private update directory.
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	written, copyErr := io.Copy(f, io.LimitReader(resp.Body, maxBytes+1))
	closeErr := f.Close()
	if copyErr != nil {
		return copyErr
	}
	if closeErr != nil {
		return closeErr
	}
	if written > maxBytes {
		return fmt.Errorf("download %s exceeds size limit", filepath.Base(path))
	}
	return nil
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

func validateManifestBinary(manifest security.ReleaseManifest, name, component string) error {
	for _, file := range manifest.Files {
		if file.Name != name || file.OS != runtime.GOOS || file.Arch != runtime.GOARCH {
			continue
		}
		if file.Component != component || file.Size <= 0 || file.Size > maxReleaseBinaryBytes {
			return fmt.Errorf("release manifest has invalid metadata for %s", name)
		}
		return nil
	}
	return fmt.Errorf("release manifest does not contain %s", name)
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
