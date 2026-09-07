package minibox

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	"github.com/OboardProject/oboard-agent/kernel/oboard-sb/internal/runtimeuser"
	box "github.com/sagernet/sing-box"
)

const (
	maxUserInstallEntries = 8192
	maxUserInstallChunks  = 64
)

var (
	ErrUserInstallIllegal    = errors.New("invalid users install")
	ErrUserInstallIncomplete = errors.New("users install is incomplete")
	ErrUserInstallDigest     = errors.New("users digest mismatch")
	ErrUserInstallBase       = errors.New("users install base revision mismatch")
	ErrUserInstallCapability = errors.New("inbound does not support runtime users")
)

// UserInstallRequest is the body of POST /users/install.
type UserInstallRequest struct {
	Scope         []string           `json:"scope"`
	UsersRevision int64              `json:"users_revision"`
	UsersDigest   string             `json:"users_digest"`
	Mode          string             `json:"mode"`
	BaseRevision  int64              `json:"base_revision,omitempty"`
	Chunk         *UserInstallChunk  `json:"chunk,omitempty"`
	Entries       []UserInstallEntry `json:"entries"`
}

type UserInstallChunk struct {
	Index  int    `json:"index"`
	Total  int    `json:"total"`
	SHA256 string `json:"sha256"`
}

type UserInstallEntry struct {
	InboundTag       string           `json:"inbound_tag"`
	AuthUser         string           `json:"auth_user"`
	Credential       UserCredential   `json:"credential"`
	AuthorizationKey string           `json:"authorization_key"`
	Identity         UserIdentity     `json:"identity"`
	RouteOutbound    string           `json:"route_outbound"`
	Policy           RuntimeUserLimit `json:"policy"`
}

type UserCredential struct {
	UUID     string `json:"uuid,omitempty"`
	Password string `json:"password,omitempty"`
	UserKey  string `json:"userkey,omitempty"`
	Flow     string `json:"flow,omitempty"`
}

type UserIdentity struct {
	UserID           int64  `json:"user_id,omitempty"`
	InboundID        int64  `json:"inbound_id,omitempty"`
	PathID           int64  `json:"path_id,omitempty"`
	DeviceIDHash     string `json:"device_id_hash,omitempty"`
	CredentialEpoch  int64  `json:"credential_epoch,omitempty"`
	CredentialStatus string `json:"credential_status,omitempty"`
}

type UserSnapshot struct {
	Revision int64              `json:"users_revision"`
	Digest   string             `json:"users_digest"`
	Scope    []string           `json:"scope"`
	Entries  []UserInstallEntry `json:"entries"`
}

type UsersStatus struct {
	UsersRevision int64             `json:"users_revision"`
	UsersDigest   string            `json:"users_digest"`
	BootID        string            `json:"boot_id"`
	PerInbound    map[string]string `json:"per_inbound,omitempty"`
}

type persistedUsers struct {
	Current   *UserSnapshot `json:"current,omitempty"`
	Candidate *UserSnapshot `json:"candidate,omitempty"`
	Commit    string        `json:"commit,omitempty"`
	Chunks    *chunkBuffer  `json:"chunks,omitempty"`
}

type chunkBuffer struct {
	Revision int64              `json:"revision"`
	Digest   string             `json:"digest"`
	Mode     string             `json:"mode"`
	Base     int64              `json:"base_revision"`
	Scope    []string           `json:"scope"`
	Total    int                `json:"total"`
	Parts    []json.RawMessage  `json:"parts"`
}

// RuntimeUsers applies inbound user tables independently of configuration
// restart. Its durable file is kernel-users.json beside the configuration.
type RuntimeUsers struct {
	mu       sync.Mutex
	path     string
	bootID   string
	scope    map[string]struct{}
	instance *box.Box
	tracker  *RateLimitTracker
	current  *UserSnapshot
	chunks   *chunkBuffer
}

func NewRuntimeUsers(path string, instance *box.Box, tracker *RateLimitTracker, declared []string) *RuntimeUsers {
	scope := map[string]struct{}{}
	for _, tag := range declared {
		tag = strings.TrimSpace(tag)
		if tag != "" {
			scope[tag] = struct{}{}
		}
	}
	return &RuntimeUsers{
		path:     path,
		bootID:   newUsersBootID(),
		scope:    scope,
		instance: instance,
		tracker:  tracker,
	}
}

func newUsersBootID() string {
	var raw [12]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return fmt.Sprintf("users-%d", os.Getpid())
	}
	return hex.EncodeToString(raw[:])
}

func (r *RuntimeUsers) Restore() error {
	if r == nil {
		return nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	state, err := r.load()
	if err != nil {
		return err
	}
	snapshot := state.Current
	if state.Commit == "candidate" && state.Candidate != nil {
		snapshot = state.Candidate
	}
	if snapshot == nil {
		return nil
	}
	if err := r.publishLocked(snapshot); err != nil {
		return err
	}
	r.current = snapshot
	if state.Commit != "current" {
		return r.persist(persistedUsers{Current: snapshot, Commit: "current"})
	}
	return nil
}

func (r *RuntimeUsers) Status() UsersStatus {
	if r == nil {
		return UsersStatus{}
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	out := UsersStatus{BootID: r.bootID, PerInbound: map[string]string{}}
	if r.current != nil {
		out.UsersRevision = r.current.Revision
		out.UsersDigest = r.current.Digest
		for _, tag := range r.current.Scope {
			out.PerInbound[tag] = r.inboundCapability(tag)
		}
	}
	for tag := range r.scope {
		if _, ok := out.PerInbound[tag]; !ok {
			out.PerInbound[tag] = r.inboundCapability(tag)
		}
	}
	return out
}

func (r *RuntimeUsers) Install(req UserInstallRequest) (UsersStatus, error) {
	if r == nil {
		return UsersStatus{}, ErrUserInstallIllegal
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if err := validateUserInstall(req); err != nil {
		return UsersStatus{}, err
	}
	entries := req.Entries
	if req.Chunk != nil {
		assembled, done, err := r.acceptChunk(req)
		if err != nil {
			return UsersStatus{}, err
		}
		if !done {
			return r.statusLocked(), ErrUserInstallIncomplete
		}
		entries = assembled
	}
	snapshot, err := r.buildSnapshot(req, entries)
	if err != nil {
		return UsersStatus{}, err
	}
	// Persist the candidate before publishing so a crash between the two
	// cannot lose a snapshot the data plane already accepted.
	if err := r.persist(persistedUsers{Current: r.current, Candidate: snapshot, Commit: "candidate"}); err != nil {
		return UsersStatus{}, err
	}
	if err := r.publishLocked(snapshot); err != nil {
		return UsersStatus{}, err
	}
	if err := r.persist(persistedUsers{Current: snapshot, Commit: "current"}); err != nil {
		return UsersStatus{}, err
	}
	r.current = snapshot
	r.chunks = nil
	return r.statusLocked(), nil
}

func (r *RuntimeUsers) statusLocked() UsersStatus {
	out := UsersStatus{BootID: r.bootID, PerInbound: map[string]string{}}
	if r.current != nil {
		out.UsersRevision = r.current.Revision
		out.UsersDigest = r.current.Digest
		for _, tag := range r.current.Scope {
			out.PerInbound[tag] = r.inboundCapability(tag)
		}
	}
	return out
}

func validateUserInstall(req UserInstallRequest) error {
	if req.UsersRevision <= 0 || strings.TrimSpace(req.UsersDigest) == "" || len(req.UsersDigest) > 128 {
		return ErrUserInstallIllegal
	}
	switch req.Mode {
	case "full", "delta":
	default:
		return ErrUserInstallIllegal
	}
	if len(req.Scope) == 0 || len(req.Scope) > 256 {
		return ErrUserInstallIllegal
	}
	for _, tag := range req.Scope {
		if strings.TrimSpace(tag) == "" {
			return ErrUserInstallIllegal
		}
	}
	if req.Chunk != nil {
		if req.Chunk.Total < 1 || req.Chunk.Total > maxUserInstallChunks || req.Chunk.Index < 0 || req.Chunk.Index >= req.Chunk.Total || req.Chunk.SHA256 == "" {
			return ErrUserInstallIllegal
		}
	}
	if len(req.Entries) > maxUserInstallEntries {
		return ErrUserInstallIllegal
	}
	return nil
}

func (r *RuntimeUsers) acceptChunk(req UserInstallRequest) ([]UserInstallEntry, bool, error) {
	payload, err := json.Marshal(req.Entries)
	if err != nil {
		return nil, false, err
	}
	sum := sha256.Sum256(payload)
	if hex.EncodeToString(sum[:]) != strings.ToLower(req.Chunk.SHA256) && hex.EncodeToString(sum[:]) != req.Chunk.SHA256 {
		return nil, false, ErrUserInstallDigest
	}
	if r.chunks == nil || r.chunks.Revision != req.UsersRevision || r.chunks.Digest != req.UsersDigest || r.chunks.Total != req.Chunk.Total {
		r.chunks = &chunkBuffer{
			Revision: req.UsersRevision,
			Digest:   req.UsersDigest,
			Mode:     req.Mode,
			Base:     req.BaseRevision,
			Scope:    append([]string(nil), req.Scope...),
			Total:    req.Chunk.Total,
			Parts:    make([]json.RawMessage, req.Chunk.Total),
		}
	}
	r.chunks.Parts[req.Chunk.Index] = append(json.RawMessage(nil), payload...)
	for _, part := range r.chunks.Parts {
		if len(part) == 0 {
			return nil, false, nil
		}
	}
	var assembled []UserInstallEntry
	for _, part := range r.chunks.Parts {
		var entries []UserInstallEntry
		if err := json.Unmarshal(part, &entries); err != nil {
			return nil, false, ErrUserInstallIllegal
		}
		assembled = append(assembled, entries...)
	}
	if len(assembled) > maxUserInstallEntries {
		return nil, false, ErrUserInstallIllegal
	}
	return assembled, true, nil
}

func (r *RuntimeUsers) buildSnapshot(req UserInstallRequest, entries []UserInstallEntry) (*UserSnapshot, error) {
	scope := uniqueSorted(req.Scope)
	cleaned := make([]UserInstallEntry, 0, len(entries))
	for _, entry := range entries {
		entry.InboundTag = strings.TrimSpace(entry.InboundTag)
		entry.AuthUser = strings.TrimSpace(entry.AuthUser)
		if entry.InboundTag == "" || entry.AuthUser == "" {
			return nil, ErrUserInstallIllegal
		}
		deleted := entry.Credential == (UserCredential{})
		if !deleted && strings.TrimSpace(entry.AuthorizationKey) == "" {
			return nil, ErrUserInstallIllegal
		}
		if deleted && req.Mode != "delta" {
			return nil, ErrUserInstallIllegal
		}
		if !containsString(scope, entry.InboundTag) {
			return nil, ErrUserInstallIllegal
		}
		cleaned = append(cleaned, entry)
	}
	sort.Slice(cleaned, func(i, j int) bool {
		if cleaned[i].InboundTag != cleaned[j].InboundTag {
			return cleaned[i].InboundTag < cleaned[j].InboundTag
		}
		return cleaned[i].AuthUser < cleaned[j].AuthUser
	})
	switch req.Mode {
	case "full":
	case "delta":
		if r.current == nil || r.current.Revision != req.BaseRevision {
			return nil, ErrUserInstallBase
		}
		cleaned = mergeUserEntries(r.current.Entries, cleaned)
	}
	snapshot := &UserSnapshot{Revision: req.UsersRevision, Scope: scope, Entries: cleaned}
	digest, err := UserSnapshotDigest(snapshot)
	if err != nil {
		return nil, err
	}
	if digest != req.UsersDigest {
		return nil, ErrUserInstallDigest
	}
	snapshot.Digest = digest
	return snapshot, nil
}

func mergeUserEntries(base, delta []UserInstallEntry) []UserInstallEntry {
	index := map[string]UserInstallEntry{}
	order := make([]string, 0, len(base)+len(delta))
	keyOf := func(entry UserInstallEntry) string { return entry.InboundTag + "\x00" + entry.AuthUser }
	for _, entry := range base {
		key := keyOf(entry)
		index[key] = entry
		order = append(order, key)
	}
	for _, entry := range delta {
		key := keyOf(entry)
		if _, ok := index[key]; !ok {
			order = append(order, key)
		}
		if entry.Credential == (UserCredential{}) && entry.AuthorizationKey == "" {
			delete(index, key)
			continue
		}
		index[key] = entry
	}
	out := make([]UserInstallEntry, 0, len(index))
	seen := map[string]struct{}{}
	for _, key := range order {
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		if entry, ok := index[key]; ok {
			out = append(out, entry)
		}
	}
	return out
}

func UserSnapshotDigest(snapshot *UserSnapshot) (string, error) {
	if snapshot == nil {
		return "", ErrUserInstallIllegal
	}
	return UsersDigest(snapshot.Revision, snapshot.Scope, snapshot.Entries)
}

// UsersDigest is the shared canonical identity of a user snapshot. Controller
// and Agent compute the same value from the same revision, scope, and entries.
func UsersDigest(revision int64, scope []string, entries []UserInstallEntry) (string, error) {
	sortedScope := uniqueSorted(scope)
	sortedEntries := append([]UserInstallEntry(nil), entries...)
	sort.Slice(sortedEntries, func(i, j int) bool {
		if sortedEntries[i].InboundTag != sortedEntries[j].InboundTag {
			return sortedEntries[i].InboundTag < sortedEntries[j].InboundTag
		}
		return sortedEntries[i].AuthUser < sortedEntries[j].AuthUser
	})
	canonical, err := json.Marshal(struct {
		Revision int64              `json:"users_revision"`
		Scope    []string           `json:"scope"`
		Entries  []UserInstallEntry `json:"entries"`
	}{Revision: revision, Scope: sortedScope, Entries: sortedEntries})
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(canonical)
	return hex.EncodeToString(sum[:]), nil
}

func (r *RuntimeUsers) publishLocked(snapshot *UserSnapshot) error {
	if r.instance == nil {
		return fmt.Errorf("kernel instance is not available")
	}
	byInbound := map[string][]UserInstallEntry{}
	for _, tag := range snapshot.Scope {
		byInbound[tag] = []UserInstallEntry{}
	}
	for _, entry := range snapshot.Entries {
		byInbound[entry.InboundTag] = append(byInbound[entry.InboundTag], entry)
	}
	for tag, entries := range byInbound {
		if len(r.scope) > 0 {
			if _, declared := r.scope[tag]; !declared {
				return fmt.Errorf("%w: %s", ErrUserInstallCapability, tag)
			}
		}
		inbound, ok := r.instance.Inbound().Get(tag)
		if !ok {
			return fmt.Errorf("%w: %s", ErrUserInstallCapability, tag)
		}
		runtimeInbound, ok := inbound.(runtimeuser.Inbound)
		if !ok || runtimeInbound.RuntimeUsersCapability() == "" {
			return fmt.Errorf("%w: %s", ErrUserInstallCapability, tag)
		}
		specs := make([]runtimeuser.Spec, 0, len(entries))
		routes := map[string]string{}
		for _, entry := range entries {
			specs = append(specs, runtimeuser.Spec{
				Name:     entry.AuthUser,
				UUID:     entry.Credential.UUID,
				Password: entry.Credential.Password,
				UserKey:  entry.Credential.UserKey,
				Flow:     entry.Credential.Flow,
			})
			if entry.RouteOutbound != "" {
				routes[entry.AuthUser] = entry.RouteOutbound
			}
		}
		if err := runtimeInbound.UpdateRuntimeUsers(specs); err != nil {
			return err
		}
		if selector, ok := r.instance.Outbound().Outbound(userSelectorTag(tag)); ok {
			if updater, ok := selector.(runtimeuser.Selector); ok {
				if err := updater.UpdateUsers(routes); err != nil {
					return err
				}
			}
		}
	}
	if r.tracker != nil {
		r.tracker.ReplaceScopedUsers(snapshot.Scope, snapshot.Entries)
	}
	return nil
}

func (r *RuntimeUsers) inboundCapability(tag string) string {
	if r.instance == nil {
		return ""
	}
	inbound, ok := r.instance.Inbound().Get(tag)
	if !ok {
		return ""
	}
	runtimeInbound, ok := inbound.(runtimeuser.Inbound)
	if !ok {
		return ""
	}
	return runtimeInbound.RuntimeUsersCapability()
}

func (r *RuntimeUsers) load() (persistedUsers, error) {
	if r.path == "" {
		return persistedUsers{}, nil
	}
	data, err := os.ReadFile(r.path)
	if err != nil {
		if os.IsNotExist(err) {
			return persistedUsers{}, nil
		}
		return persistedUsers{}, err
	}
	var state persistedUsers
	if err := json.Unmarshal(data, &state); err != nil {
		return persistedUsers{}, fmt.Errorf("kernel-users.json is unreadable")
	}
	return state, nil
}

func (r *RuntimeUsers) persist(state persistedUsers) error {
	if r.path == "" {
		return nil
	}
	data, err := json.Marshal(state)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(r.path), 0700); err != nil {
		return err
	}
	tmp := r.path + ".tmp"
	if err := os.WriteFile(tmp, data, 0600); err != nil {
		return err
	}
	return os.Rename(tmp, r.path)
}

func userSelectorTag(inbound string) string {
	return "userselector-" + inbound
}

func uniqueSorted(values []string) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}

func containsString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}
