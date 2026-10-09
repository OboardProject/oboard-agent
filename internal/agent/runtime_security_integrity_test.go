package agent

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"github.com/OboardProject/oboard-agent/internal/security"
	"github.com/OboardProject/oboard-agent/internal/version"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestRuntimeSecuritySignedIntegrityAndCache(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	old := version.ReleasePublicKey
	version.ReleasePublicKey = base64.RawStdEncoding.EncodeToString(pub)
	t.Cleanup(func() { version.ReleasePublicKey = old })
	dir := t.TempDir()
	core := filepath.Join(dir, "core")
	if err := os.WriteFile(core, []byte("signed fixture"), 0700); err != nil {
		t.Fatal(err)
	}
	hash, size, err := security.SHA256File(core)
	if err != nil {
		t.Fatal(err)
	}
	manifest := security.ReleaseManifest{Repo: "OboardProject/oboard-agent", Build: "test", Files: []security.ReleaseManifestFile{{Name: "oboard-sb-" + runtime.GOOS + "-" + runtime.GOARCH, Component: "sb", OS: runtime.GOOS, Arch: runtime.GOARCH, SHA256: hash, Size: size}}}
	sig, err := security.SignReleaseManifest(manifest, base64.RawStdEncoding.EncodeToString(priv))
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(manifest)
	mp := filepath.Join(dir, "manifest")
	sp := filepath.Join(dir, "signature")
	if err := os.WriteFile(mp, raw, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(sp, []byte(sig), 0600); err != nil {
		t.Fatal(err)
	}
	r := New(Config{StateDir: dir, CoreBinary: core, ConfigPath: filepath.Join(dir, "agent.json")})
	if err := r.RecordReleaseProof(mp, sp); err != nil {
		t.Fatal(err)
	}
	status := func() string {
		for _, check := range r.inspectRuntimeIntegrity(context.Background(), time.Now()) {
			if check.ID == "binary_sb" || check.ID == "release_proof" {
				return check.Status
			}
		}
		return "missing"
	}
	if got := status(); got != "passed" {
		t.Fatal(got)
	}
	staged := filepath.Join(dir, "oboard-sb.new")
	if err := os.WriteFile(staged, []byte("signed fixture"), 0700); err != nil {
		t.Fatal(err)
	}
	if result, err := r.PreflightCoreUpdate(staged, mp, sp); err != nil || !strings.HasPrefix(result, corePreflightNotDeployed) {
		t.Fatal("signed staged name rejected", result, err)
	}
	if err := os.WriteFile(staged, []byte("tampered"), 0700); err != nil {
		t.Fatal(err)
	}
	if _, err := r.PreflightCoreUpdate(staged, mp, sp); err == nil {
		t.Fatal("unsigned staged bytes accepted")
	}

	if err := os.WriteFile(core, []byte("tampered"), 0700); err != nil {
		t.Fatal(err)
	}
	if got := status(); got != "passed" {
		t.Fatal("periodic inspection did not reuse cache", got)
	}
	r.runtimeSecurityIntegrity.Store(nil)
	if got := status(); got != "failed" {
		t.Fatal("tampering not detected", got)
	}
	if err := os.WriteFile(sp, []byte("invalid"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := r.RecordReleaseProof(mp, sp); err == nil {
		t.Fatal("unsigned proof accepted")
	}
}
