package agentsecurity

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/OboardProject/oboard-agent/internal/model"
)

const (
	DefaultPath = "/etc/oboard-agent/local-security.json"
	FileMode    = 0o600
)

type Policy struct {
	Version int                         `json:"version"`
	Mode    string                      `json:"mode"`
	Allow   model.RemoteAccessLocalAllow `json:"allow"`
}

func DefaultPolicy() Policy {
	return Policy{Version: 1, Mode: model.RemoteAccessModeStandard}
}

func (p Policy) Normalized() Policy {
	if p.Version == 0 {
		p.Version = 1
	}
	switch strings.ToLower(strings.TrimSpace(p.Mode)) {
	case model.RemoteAccessModeHardened:
		p.Mode = model.RemoteAccessModeHardened
	default:
		p.Mode = model.RemoteAccessModeStandard
	}
	return p
}

func (p Policy) Allows(feature string) bool {
	p = p.Normalized()
	if p.Mode != model.RemoteAccessModeHardened {
		return true
	}
	switch feature {
	case "remote_terminal":
		return p.Allow.RemoteTerminal
	case "mcp_remote_operations", "mcp_structured_exec", "mcp_raw_shell", "mcp_interactive_terminal", "mcp_interactive", "mcp_enabled":
		return p.Allow.MCPEnabled
	default:
		return false
	}
}

type Store struct {
	mu   sync.Mutex
	path string
}

func NewStore(path string) *Store {
	if strings.TrimSpace(path) == "" {
		path = DefaultPath
	}
	return &Store{path: path}
}

func PathForConfig(configPath string) string {
	configPath = strings.TrimSpace(configPath)
	if configPath == "" {
		return DefaultPath
	}
	return filepath.Join(filepath.Dir(configPath), "local-security.json")
}

func (s *Store) Path() string { return s.path }

func (s *Store) Load() (Policy, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.loadLocked()
}

func (s *Store) loadLocked() (Policy, error) {
	raw, err := os.ReadFile(s.path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return DefaultPolicy(), nil
		}
		return Policy{}, err
	}
	var policy Policy
	if err := json.Unmarshal(raw, &policy); err != nil {
		return Policy{}, err
	}
	return policy.Normalized(), nil
}

func (s *Store) Save(policy Policy) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	policy = policy.Normalized()
	if err := os.MkdirAll(filepath.Dir(s.path), 0o700); err != nil {
		return err
	}
	raw, err := json.MarshalIndent(policy, "", "  ")
	if err != nil {
		return err
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, append(raw, '\n'), FileMode); err != nil {
		return err
	}
	if err := os.Chmod(tmp, FileMode); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return os.Rename(tmp, s.path)
}

func (s *Store) SetMode(mode string) error {
	policy, err := s.Load()
	if err != nil {
		return err
	}
	policy.Mode = mode
	return s.Save(policy)
}

func (s *Store) SetAllow(feature string, allow bool) error {
	policy, err := s.Load()
	if err != nil {
		return err
	}
	switch feature {
	case "terminal", "remote_terminal":
		policy.Allow.RemoteTerminal = allow
	case "mcp-operations", "mcp_remote_operations", "mcp-exec", "mcp_structured_exec", "mcp-shell", "mcp_raw_shell", "mcp_interactive_terminal", "mcp_interactive", "mcp-interactive", "mcp_enabled", "mcp":
		policy.Allow.MCPEnabled = allow
	default:
		return errors.New("unknown remote-access feature")
	}
	return s.Save(policy)
}
