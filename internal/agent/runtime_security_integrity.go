package agent

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/OboardProject/oboard-agent/internal/model"
	"github.com/OboardProject/oboard-agent/internal/securefile"
	"github.com/OboardProject/oboard-agent/internal/security"
	"github.com/OboardProject/oboard-agent/internal/version"
	"os"
	"runtime"
	"strings"
	"time"
)

const runtimeReleaseProofFile = "runtime-release-proof.json"

type runtimeReleaseProof struct {
	Manifest  security.ReleaseManifest `json:"manifest"`
	Signature string                   `json:"signature"`
}

// RecordReleaseProof is a local installer verb. It accepts no remote input and
// retains signed evidence only; runtime inspection verifies installed bytes.
func (r *Runner) RecordReleaseProof(manifestPath, signaturePath string) error {
	proof, err := r.loadRuntimeReleaseProof(manifestPath, signaturePath)
	if err != nil {
		return err
	}
	raw, err := json.Marshal(proof)
	if err != nil {
		return err
	}
	if err := r.stateWritePathSynced(r.statePath(runtimeReleaseProofFile), raw, 0600); err != nil {
		return err
	}
	r.runtimeSecurityIntegrity.Store(nil)
	return nil
}
func (r *Runner) verifyRuntimeReleaseProof(proof runtimeReleaseProof) error {
	repo := strings.TrimSpace(r.Config().UpdateRepo)
	if repo == "" {
		repo = defaultUpdateRepo
	}
	if proof.Manifest.Repo != repo {
		return errors.New("unexpected release identity")
	}
	return security.VerifyReleaseManifest(proof.Manifest, proof.Signature, version.ReleasePublicKey)
}
func (r *Runner) inspectRuntimeIntegrity(ctx context.Context, now time.Time) []model.RuntimeSecurityCheck {
	if cached := r.runtimeSecurityIntegrity.Load(); cached != nil {
		return append([]model.RuntimeSecurityCheck(nil), (*cached)...)
	}
	checks := []model.RuntimeSecurityCheck{}
	add := func(id, status, message string) {
		severity := "info"
		if status == "failed" {
			severity = "high"
		}
		checks = append(checks, model.RuntimeSecurityCheck{ID: id, Category: "binary", Severity: severity, Status: status, Supported: true, CheckedAt: now, Message: message, Remedy: "安装或更新使用原有 Ed25519 签名与 SHA-256 验证；重新检查可刷新完整性证据"})
	}
	raw, err := r.stateRead(runtimeReleaseProofFile)
	var proof runtimeReleaseProof
	if os.IsNotExist(err) || version.ReleasePublicKey == "" {
		add("release_proof", "unknown", "缺少可验证的签名发布凭据；需要通过签名安装或更新后重新检查")
	} else if err != nil || json.Unmarshal(raw, &proof) != nil || r.verifyRuntimeReleaseProof(proof) != nil {
		add("release_proof", "failed", "本地发布凭据未通过签名验证")
	} else {
		agentPath, pathErr := selfExecutablePath()
		for _, target := range []struct{ component, path string }{{"agent", agentPath}, {"sb", r.coreBinary()}, {"realm", r.realmBinary()}} {
			id := "binary_" + target.component
			if target.path == "" || (target.component == "agent" && pathErr != nil) {
				add(id, "unknown", "无法定位受管二进制")
				continue
			}
			var expected *security.ReleaseManifestFile
			duplicate := false
			for i := range proof.Manifest.Files {
				item := &proof.Manifest.Files[i]
				if item.Component == target.component && item.OS == runtime.GOOS && item.Arch == runtime.GOARCH {
					if expected != nil {
						duplicate = true
					}
					expected = item
				}
			}
			if expected == nil || duplicate || expected.Size <= 0 || expected.Size > 256<<20 {
				add(id, "unknown", "签名清单未提供唯一且可检查的本平台组件")
				continue
			}
			digest, size, err := securefile.Digest(ctx, target.path, 256<<20)
			if err != nil {
				add(id, "unknown", "二进制检查未完成，可能达到资源上限或文件正在更新")
				continue
			}
			if digest != expected.SHA256 || size != expected.Size {
				add(id, "failed", "受管组件 "+target.component+" 与签名发布内容不一致")
			} else {
				add(id, "passed", "受管组件 "+target.component+" 与签名发布内容一致")
			}
		}
	}
	r.runtimeSecurityIntegrity.Store(&checks)
	return append([]model.RuntimeSecurityCheck(nil), checks...)
}

func (r *Runner) installVerifiedReleaseWithProof(prefix, manifestPath, signaturePath string, items []stagedReleaseFile) (err error) {
	old, readErr := r.stateRead(runtimeReleaseProofFile)
	if readErr != nil && !os.IsNotExist(readErr) {
		return errors.New("release evidence unavailable")
	}
	if err := r.RecordReleaseProof(manifestPath, signaturePath); err != nil {
		return err
	}
	if err = r.installVerifiedReleaseFiles(prefix, items); err == nil {
		return nil
	}
	var restoreErr error
	if os.IsNotExist(readErr) {
		restoreErr = securefile.Remove(r.statePath(runtimeReleaseProofFile))
		if os.IsNotExist(restoreErr) {
			restoreErr = nil
		}
	} else {
		restoreErr = r.stateWritePathSynced(r.statePath(runtimeReleaseProofFile), old, 0600)
	}
	r.runtimeSecurityIntegrity.Store(nil)
	if restoreErr != nil {
		return errors.Join(err, errors.New("release evidence rollback failed"))
	}
	return err
}

func (r *Runner) loadRuntimeReleaseProof(manifestPath, signaturePath string) (runtimeReleaseProof, error) {
	var proof runtimeReleaseProof
	raw, err := securefile.Read(manifestPath, 1<<20)
	if err != nil {
		return proof, err
	}
	if json.Unmarshal(raw, &proof.Manifest) != nil {
		return proof, errors.New("invalid release evidence")
	}
	sig, err := securefile.Read(signaturePath, 4096)
	if err != nil {
		return proof, err
	}
	proof.Signature = strings.TrimSpace(string(sig))
	if err := r.verifyRuntimeReleaseProof(proof); err != nil {
		return proof, err
	}
	return proof, nil
}
