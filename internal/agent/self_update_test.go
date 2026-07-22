package agent

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"testing"

	"github.com/OboardProject/oboard-agent/internal/security"
	"github.com/OboardProject/oboard-agent/internal/version"
)

func TestDownloadAndInstallSignedRelease(t *testing.T) {
	oldKey := version.ReleasePublicKey
	defer func() { version.ReleasePublicKey = oldKey }()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	version.ReleasePublicKey = base64.RawStdEncoding.EncodeToString(pub)
	agentName := "oboard-agent-" + runtime.GOOS + "-" + runtime.GOARCH
	coreName := "oboard-sb-" + runtime.GOOS + "-" + runtime.GOARCH
	agentData := []byte("signed-agent-binary")
	coreData := []byte("signed-core-binary")
	manifest := security.ReleaseManifest{
		Version: "1.2.3", Build: "build-123", Commit: "abc123", Date: "2026-07-17T00:00:00Z", Repo: "example/oboard-agent",
		Files: []security.ReleaseManifestFile{
			{Name: agentName, Component: "agent", OS: runtime.GOOS, Arch: runtime.GOARCH, SHA256: sha256Hex(agentData), Size: int64(len(agentData))},
			{Name: coreName, Component: "sb", OS: runtime.GOOS, Arch: runtime.GOARCH, SHA256: sha256Hex(coreData), Size: int64(len(coreData))},
		},
	}
	privateKey := base64.RawStdEncoding.EncodeToString(priv)
	signature, err := security.SignReleaseManifest(manifest, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	manifestJSON, err := security.CanonicalReleaseManifest(manifest)
	if err != nil {
		t.Fatal(err)
	}
	assets := map[string][]byte{
		"/release-manifest.json":     manifestJSON,
		"/release-manifest.json.sig": []byte(signature),
		"/" + agentName:              agentData,
		"/" + coreName:               coreData,
	}
	var mu sync.Mutex
	requested := []string{}
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		requested = append(requested, r.URL.Path)
		mu.Unlock()
		body, ok := assets[r.URL.Path]
		if !ok {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write(body)
	}))
	defer server.Close()
	dir := t.TempDir()
	targets := signedReleaseTargets{Agent: filepath.Join(dir, "oboard-agent"), Core: filepath.Join(dir, "oboard-sb")}
	if err := os.WriteFile(targets.Agent, []byte("old-agent"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(targets.Core, []byte("old-core"), 0o755); err != nil {
		t.Fatal(err)
	}
	got, err := downloadAndInstallSignedRelease(context.Background(), server.Client(), server.URL, manifest.Repo, manifest.Build, targets)
	if err != nil {
		t.Fatal(err)
	}
	if got.Build != manifest.Build {
		t.Fatalf("installed build = %q", got.Build)
	}
	assertFileContent(t, targets.Agent, agentData)
	assertFileContent(t, targets.Core, coreData)
	mu.Lock()
	sort.Strings(requested)
	gotPaths := append([]string(nil), requested...)
	mu.Unlock()
	wantPaths := []string{"/" + agentName, "/" + coreName, "/release-manifest.json", "/release-manifest.json.sig"}
	sort.Strings(wantPaths)
	if len(gotPaths) != len(wantPaths) {
		t.Fatalf("requested paths = %#v", gotPaths)
	}
	for i := range wantPaths {
		if gotPaths[i] != wantPaths[i] {
			t.Fatalf("requested paths = %#v", gotPaths)
		}
	}
}

func TestSignedReleaseRejectsTamperedBinaryBeforeInstall(t *testing.T) {
	oldKey := version.ReleasePublicKey
	defer func() { version.ReleasePublicKey = oldKey }()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	version.ReleasePublicKey = base64.RawStdEncoding.EncodeToString(pub)
	agentName := "oboard-agent-" + runtime.GOOS + "-" + runtime.GOARCH
	coreName := "oboard-sb-" + runtime.GOOS + "-" + runtime.GOARCH
	manifest := security.ReleaseManifest{Version: "1", Build: "2", Repo: "example/oboard-agent", Files: []security.ReleaseManifestFile{
		{Name: agentName, Component: "agent", OS: runtime.GOOS, Arch: runtime.GOARCH, SHA256: sha256Hex([]byte("good-agent")), Size: int64(len("good-agent"))},
		{Name: coreName, Component: "sb", OS: runtime.GOOS, Arch: runtime.GOARCH, SHA256: sha256Hex([]byte("good-core")), Size: int64(len("good-core"))},
	}}
	signature, err := security.SignReleaseManifest(manifest, base64.RawStdEncoding.EncodeToString(priv))
	if err != nil {
		t.Fatal(err)
	}
	manifestJSON, _ := security.CanonicalReleaseManifest(manifest)
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/release-manifest.json":
			_, _ = w.Write(manifestJSON)
		case "/release-manifest.json.sig":
			_, _ = w.Write([]byte(signature))
		case "/" + agentName:
			_, _ = w.Write([]byte("tampered-agent"))
		case "/" + coreName:
			_, _ = w.Write([]byte("good-core"))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	dir := t.TempDir()
	targets := signedReleaseTargets{Agent: filepath.Join(dir, "oboard-agent"), Core: filepath.Join(dir, "oboard-sb")}
	_ = os.WriteFile(targets.Agent, []byte("old-agent"), 0o755)
	_ = os.WriteFile(targets.Core, []byte("old-core"), 0o755)
	if _, err := downloadAndInstallSignedRelease(context.Background(), server.Client(), server.URL, manifest.Repo, manifest.Build, targets); err == nil {
		t.Fatal("tampered signed release was installed")
	}
	assertFileContent(t, targets.Agent, []byte("old-agent"))
	assertFileContent(t, targets.Core, []byte("old-core"))
}

func TestVerifyReleaseFilesRejectsTraversalName(t *testing.T) {
	oldKey := version.ReleasePublicKey
	defer func() { version.ReleasePublicKey = oldKey }()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	version.ReleasePublicKey = base64.RawStdEncoding.EncodeToString(pub)
	manifest := security.ReleaseManifest{
		Version: "1", Build: "2", Repo: "example/oboard-agent",
		Files: []security.ReleaseManifestFile{{Name: "../escape", Component: "agent", OS: runtime.GOOS, Arch: runtime.GOARCH, SHA256: sha256Hex([]byte("x")), Size: 1}},
	}
	signature, err := security.SignReleaseManifest(manifest, base64.RawStdEncoding.EncodeToString(priv))
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	manifestJSON, err := security.CanonicalReleaseManifest(manifest)
	if err != nil {
		t.Fatal(err)
	}
	manifestPath := filepath.Join(dir, "release-manifest.json")
	signaturePath := filepath.Join(dir, "release-manifest.json.sig")
	if err := os.WriteFile(manifestPath, manifestJSON, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(signaturePath, []byte(signature), 0o600); err != nil {
		t.Fatal(err)
	}
	err = VerifyReleaseFiles(manifestPath, signaturePath, dir, runtime.GOOS, runtime.GOARCH, []string{"../escape"})
	if err == nil || !strings.Contains(err.Error(), "base name") {
		t.Fatalf("traversal release name was not rejected: %v", err)
	}
}

func sha256Hex(value []byte) string {
	sum := sha256.Sum256(value)
	return hex.EncodeToString(sum[:])
}

func assertFileContent(t *testing.T, path string, want []byte) {
	t.Helper()
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(want) {
		t.Fatalf("%s = %q, want %q", path, got, want)
	}
}
