package agent

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/OboardProject/oboard-agent/internal/security"
	"github.com/OboardProject/oboard-agent/internal/version"
)

func VerifyReleaseFiles(manifestPath, signaturePath, baseDir, osName, arch string, files []string) error {
	// #nosec G304 -- manifest and signature paths are local operator CLI inputs.
	b, err := os.ReadFile(manifestPath)
	if err != nil {
		return err
	}
	var manifest security.ReleaseManifest
	if err := json.Unmarshal(b, &manifest); err != nil {
		return err
	}
	// #nosec G304 -- manifest and signature paths are local operator CLI inputs.
	sigBytes, err := os.ReadFile(signaturePath)
	if err != nil {
		return err
	}
	sig := string(bytesTrimSpace(sigBytes))
	if version.ReleasePublicKey == "" || sig == "" {
		if !(version.IsDev() && security.EnvBool("OBOARD_ALLOW_UNSIGNED_DEV_UPDATE", false)) {
			return errors.New("release manifest is unsigned or release public key is missing")
		}
	} else if err := security.VerifyReleaseManifest(manifest, sig, version.ReleasePublicKey); err != nil {
		return err
	}
	byName := map[string]security.ReleaseManifestFile{}
	for _, item := range manifest.Files {
		if item.OS == osName && item.Arch == arch {
			byName[item.Name] = item
		}
	}
	for _, name := range files {
		if name == "" || filepath.Base(name) != name || name == "." || name == ".." {
			return fmt.Errorf("release file name %q must be a base name", name)
		}
		item, ok := byName[name]
		if !ok {
			return fmt.Errorf("release manifest does not contain %s for %s/%s", name, osName, arch)
		}
		sha, size, err := security.SHA256File(filepath.Join(baseDir, name))
		if err != nil {
			return err
		}
		if sha != item.SHA256 || size != item.Size {
			return fmt.Errorf("release file %s checksum mismatch", name)
		}
	}
	return nil
}

func bytesTrimSpace(b []byte) []byte {
	for len(b) > 0 && (b[0] == ' ' || b[0] == '\n' || b[0] == '\r' || b[0] == '\t') {
		b = b[1:]
	}
	for len(b) > 0 {
		c := b[len(b)-1]
		if c != ' ' && c != '\n' && c != '\r' && c != '\t' {
			break
		}
		b = b[:len(b)-1]
	}
	return b
}
