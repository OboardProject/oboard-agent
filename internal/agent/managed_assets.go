package agent

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/OboardProject/oboard-agent/internal/model"
)

type managedAssetState struct {
	Version int               `json:"version"`
	Assets  map[string]string `json:"assets"`
}

func (r *Runner) syncManagedAssets(ctx context.Context, references []model.ManagedAssetReference, config string) (string, bool, error) {
	desired, err := validateManagedAssetReferences(references)
	if err != nil {
		return "", false, err
	}
	state, err := r.loadManagedAssetState()
	if err != nil {
		return "", false, err
	}
	missing := make([]model.ManagedAssetReference, 0)
	for _, reference := range desired {
		if !r.managedAssetFilesReady(reference) {
			missing = append(missing, reference)
		}
	}
	changed := len(missing) > 0 || !managedAssetStateMatches(state, desired)
	if len(missing) > 0 {
		var response model.ManagedAssetResponse
		if err := r.postControllerJSON(ctx, "/api/v1/agent/assets", model.ManagedAssetRequest{Assets: missing}, &response, true); err != nil {
			return "", false, fmt.Errorf("request managed assets: %w", err)
		}
		if err := r.installManagedAssets(missing, response.Assets); err != nil {
			return "", false, err
		}
	}
	if strings.TrimSpace(config) == "" && len(desired) == 0 {
		return config, changed, nil
	}
	resolved, err := r.resolveManagedAssetPlaceholders(config, desired)
	if err != nil {
		return "", false, err
	}
	return resolved, changed, nil
}

func validateManagedAssetReferences(references []model.ManagedAssetReference) (map[string]model.ManagedAssetReference, error) {
	out := make(map[string]model.ManagedAssetReference, len(references))
	for _, reference := range references {
		if !supportedManagedAssetKind(reference.Kind) || reference.ID <= 0 || strings.TrimSpace(reference.Revision) == "" {
			return nil, errors.New("invalid managed asset reference")
		}
		key := managedAssetKey(reference)
		if _, exists := out[key]; exists {
			return nil, errors.New("duplicate managed asset reference")
		}
		out[key] = reference
	}
	return out, nil
}

func supportedManagedAssetKind(kind string) bool {
	return kind == "certificate" || kind == "routing_rule_set"
}

func managedAssetFileNames(kind string) []string {
	if kind == "routing_rule_set" {
		return []string{"rules.json", "rules.srs"}
	}
	return []string{"fullchain.pem", "privkey.pem"}
}

func managedAssetKey(reference model.ManagedAssetReference) string {
	return reference.Kind + "/" + strconv.FormatInt(reference.ID, 10)
}

func (r *Runner) managedAssetsRoot() string {
	return filepath.Join(r.stateDir(), "managed-assets")
}

func (r *Runner) managedAssetDir(reference model.ManagedAssetReference) string {
	return filepath.Join(r.managedAssetIDDir(reference), managedAssetRevisionDir(reference.Revision))
}

func (r *Runner) managedAssetIDDir(reference model.ManagedAssetReference) string {
	return filepath.Join(r.managedAssetsRoot(), reference.Kind, strconv.FormatInt(reference.ID, 10))
}

func managedAssetRevisionDir(revision string) string {
	return fmt.Sprintf("%x", sha256.Sum256([]byte(revision)))
}

func (r *Runner) managedAssetStatePath() string {
	return filepath.Join(r.managedAssetsRoot(), "state.json")
}

func (r *Runner) loadManagedAssetState() (managedAssetState, error) {
	state := managedAssetState{Version: 1, Assets: map[string]string{}}
	if info, err := os.Lstat(r.managedAssetStatePath()); err == nil && (info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular()) {
		return state, errors.New("managed asset state path is not a regular file")
	} else if err != nil && !errors.Is(err, os.ErrNotExist) {
		return state, err
	}
	data, err := os.ReadFile(r.managedAssetStatePath()) // #nosec G304 -- fixed path below configured state_dir.
	if errors.Is(err, os.ErrNotExist) {
		return state, nil
	}
	if err != nil {
		return state, err
	}
	if err := json.Unmarshal(data, &state); err != nil {
		return state, fmt.Errorf("decode managed asset state: %w", err)
	}
	if state.Version != 1 || state.Assets == nil {
		return state, errors.New("unsupported managed asset state")
	}
	return state, nil
}

func (r *Runner) saveManagedAssetState(state managedAssetState) error {
	root := r.managedAssetsRoot()
	if err := ensurePrivateAssetDirectory(root); err != nil {
		return err
	}
	data, err := json.Marshal(state)
	if err != nil {
		return err
	}
	return atomicWriteFile(r.managedAssetStatePath(), data, 0o600)
}

func managedAssetStateMatches(state managedAssetState, desired map[string]model.ManagedAssetReference) bool {
	if len(state.Assets) != len(desired) {
		return false
	}
	for key, reference := range desired {
		if state.Assets[key] != reference.Revision {
			return false
		}
	}
	return true
}

func (r *Runner) managedAssetFilesReady(reference model.ManagedAssetReference) bool {
	dir := r.managedAssetDir(reference)
	info, err := os.Lstat(dir)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0o700 {
		return false
	}
	files := map[string][]byte{}
	found := 0
	for _, name := range managedAssetFileNames(reference.Kind) {
		info, err := os.Lstat(filepath.Join(dir, name))
		if errors.Is(err, os.ErrNotExist) && reference.Kind == "routing_rule_set" {
			continue
		}
		if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 || info.Size() == 0 {
			return false
		}
		content, err := os.ReadFile(filepath.Join(dir, name)) // #nosec G304 -- fixed filenames below a validated managed asset directory.
		limit := 1 << 20
		if reference.Kind == "routing_rule_set" {
			limit = 8 << 20
		}
		if err != nil || len(content) == 0 || len(content) > limit {
			return false
		}
		files[name] = content
		found++
	}
	if reference.Kind == "routing_rule_set" {
		if found != 1 {
			return false
		}
		for _, content := range files {
			sum := sha256.Sum256(content)
			return hex.EncodeToString(sum[:]) == reference.Revision
		}
	}
	return found == 2 && managedCertificateRevision(files["fullchain.pem"], files["privkey.pem"]) == reference.Revision
}

func managedCertificateRevision(fullchain, privateKey []byte) string {
	material := make([]byte, 0, len(fullchain)+1+len(privateKey))
	material = append(material, fullchain...)
	material = append(material, 0)
	material = append(material, privateKey...)
	sum := sha256.Sum256(material)
	return hex.EncodeToString(sum[:])
}

func (r *Runner) installManagedAssets(requested []model.ManagedAssetReference, assets []model.ManagedAsset) error {
	wanted := make(map[string]model.ManagedAssetReference, len(requested))
	for _, reference := range requested {
		wanted[managedAssetKey(reference)] = reference
	}
	if len(assets) != len(wanted) {
		return errors.New("controller returned an incomplete managed asset response")
	}
	seen := map[string]bool{}
	for _, asset := range assets {
		key := managedAssetKey(asset.ManagedAssetReference)
		reference, ok := wanted[key]
		if !ok || seen[key] || reference.Revision != asset.Revision {
			return errors.New("controller returned an unexpected managed asset")
		}
		seen[key] = true
		files := map[string][]byte{}
		allowedNames := map[string]bool{}
		for _, name := range managedAssetFileNames(reference.Kind) {
			allowedNames[name] = true
		}
		for _, file := range asset.Files {
			if !allowedNames[file.Name] {
				return errors.New("controller returned an invalid managed asset filename")
			}
			if _, exists := files[file.Name]; exists || file.Mode != 0o600 {
				return errors.New("controller returned invalid managed asset file metadata")
			}
			content, err := base64.StdEncoding.DecodeString(file.ContentB64)
			limit := 1 << 20
			if reference.Kind == "routing_rule_set" {
				limit = 8 << 20
			}
			if err != nil || len(content) == 0 || len(content) > limit {
				return errors.New("controller returned invalid managed asset file content")
			}
			files[file.Name] = content
		}
		if !managedAssetContentMatches(reference, files) {
			return errors.New("controller returned managed asset content that does not match its revision")
		}
		root := r.managedAssetsRoot()
		kindDir := filepath.Join(root, reference.Kind)
		idDir := r.managedAssetIDDir(reference)
		dir := r.managedAssetDir(reference)
		for _, privateDir := range []string{root, kindDir, idDir, dir} {
			if err := ensurePrivateAssetDirectory(privateDir); err != nil {
				return err
			}
		}
		if info, err := os.Lstat(dir); err != nil || info.Mode()&os.ModeSymlink != 0 {
			if err == nil {
				err = errors.New("managed asset directory is a symbolic link")
			}
			return err
		}
		for name := range files {
			if err := atomicWriteFile(filepath.Join(dir, name), files[name], 0o600); err != nil {
				return err
			}
		}
	}
	return nil
}

func managedAssetContentMatches(reference model.ManagedAssetReference, files map[string][]byte) bool {
	if reference.Kind == "certificate" {
		return len(files) == 2 && len(files["fullchain.pem"]) > 0 && len(files["privkey.pem"]) > 0 && managedCertificateRevision(files["fullchain.pem"], files["privkey.pem"]) == reference.Revision
	}
	if reference.Kind == "routing_rule_set" && len(files) == 1 {
		content := files["rules.json"]
		if len(content) == 0 {
			content = files["rules.srs"]
		}
		sum := sha256.Sum256(content)
		return len(content) > 0 && hex.EncodeToString(sum[:]) == reference.Revision
	}
	return false
}

func ensurePrivateAssetDirectory(path string) error {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		if err := os.MkdirAll(path, 0o700); err != nil {
			return err
		}
		info, err = os.Lstat(path)
	}
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("managed asset path is not a private directory")
	}
	return os.Chmod(path, 0o700) // #nosec G302 -- managed asset directories require the execute bit and remain owner-only.
}

func (r *Runner) resolveManagedAssetPlaceholders(config string, desired map[string]model.ManagedAssetReference) (string, error) {
	var value any
	if err := json.Unmarshal([]byte(config), &value); err != nil {
		return "", err
	}
	resolved, err := r.resolveManagedAssetValue(value, desired)
	if err != nil {
		return "", err
	}
	data, err := json.Marshal(resolved)
	return string(data), err
}

func (r *Runner) resolveManagedAssetValue(value any, desired map[string]model.ManagedAssetReference) (any, error) {
	switch item := value.(type) {
	case map[string]any:
		for key, child := range item {
			resolved, err := r.resolveManagedAssetValue(child, desired)
			if err != nil {
				return nil, err
			}
			item[key] = resolved
		}
		return item, nil
	case []any:
		for index, child := range item {
			resolved, err := r.resolveManagedAssetValue(child, desired)
			if err != nil {
				return nil, err
			}
			item[index] = resolved
		}
		return item, nil
	case string:
		const assetPrefix = "oboard-asset://"
		if !strings.HasPrefix(item, assetPrefix) {
			return item, nil
		}
		parts := strings.Split(strings.TrimPrefix(item, assetPrefix), "/")
		if len(parts) != 3 {
			return nil, errors.New("invalid managed asset placeholder")
		}
		kind := parts[0]
		if kind == "routing-rule-set" {
			kind = "routing_rule_set"
		}
		if !supportedManagedAssetKind(kind) {
			return nil, errors.New("invalid managed asset placeholder")
		}
		allowed := false
		for _, name := range managedAssetFileNames(kind) {
			allowed = allowed || parts[2] == name
		}
		if !allowed {
			return nil, errors.New("invalid managed asset filename")
		}
		id, err := strconv.ParseInt(parts[1], 10, 64)
		if err != nil || id <= 0 {
			return nil, errors.New("invalid managed asset id")
		}
		reference, ok := desired[kind+"/"+parts[1]]
		if !ok || reference.ID != id {
			return nil, errors.New("configuration references an undeclared managed asset")
		}
		return filepath.Join(r.managedAssetDir(reference), parts[2]), nil
	default:
		return value, nil
	}
}

func (r *Runner) cleanupManagedAssets(references []model.ManagedAssetReference) error {
	desired, err := validateManagedAssetReferences(references)
	if err != nil {
		return err
	}
	nextState := managedAssetState{Version: 1, Assets: make(map[string]string, len(desired))}
	desiredByKind := make(map[string]map[int64]model.ManagedAssetReference)
	for key, reference := range desired {
		if !r.managedAssetFilesReady(reference) {
			return fmt.Errorf("managed asset %s revision %q is not ready", key, reference.Revision)
		}
		nextState.Assets[key] = reference.Revision
		if desiredByKind[reference.Kind] == nil {
			desiredByKind[reference.Kind] = map[int64]model.ManagedAssetReference{}
		}
		desiredByKind[reference.Kind][reference.ID] = reference
	}
	currentState, err := r.loadManagedAssetState()
	if err != nil {
		return err
	}
	if !managedAssetStateMatches(currentState, desired) {
		if err := r.saveManagedAssetState(nextState); err != nil {
			return err
		}
	}

	for _, kind := range []string{"certificate", "routing_rule_set"} {
		kindRoot := filepath.Join(r.managedAssetsRoot(), kind)
		entries, err := os.ReadDir(kindRoot)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return err
		}
		for _, entry := range entries {
			id, parseErr := strconv.ParseInt(entry.Name(), 10, 64)
			if parseErr != nil || id <= 0 {
				return errors.New("invalid managed asset directory")
			}
			idPath := filepath.Join(kindRoot, entry.Name())
			reference, keep := desiredByKind[kind][id]
			if !keep {
				if err := os.RemoveAll(idPath); err != nil {
					return err
				}
				continue
			}
			info, err := os.Lstat(idPath)
			if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
				if err == nil {
					err = errors.New("managed asset path is not a directory")
				}
				return err
			}
			revisions, err := os.ReadDir(idPath)
			if err != nil {
				return err
			}
			keepRevision := managedAssetRevisionDir(reference.Revision)
			for _, revision := range revisions {
				if revision.Name() == keepRevision {
					continue
				}
				if err := os.RemoveAll(filepath.Join(idPath, revision.Name())); err != nil {
					return err
				}
			}
		}
	}
	return nil
}
