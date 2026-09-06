package authorization

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"sync"
	"time"
)

const MaxLifetime = 5 * time.Minute

type Lease struct {
	Revision int64             `json:"revision"`
	IssuedAt string            `json:"issued_at"`
	Grants   map[string]string `json:"grants"`
}

func (l *Lease) Validate() error {
	if l == nil {
		return nil
	}
	issued, err := time.Parse(time.RFC3339Nano, l.IssuedAt)
	if err != nil || l.Revision <= 0 || len(l.Grants) > 65536 {
		return errors.New("invalid authorization snapshot")
	}
	for key, raw := range l.Grants {
		end, err := time.Parse(time.RFC3339Nano, raw)
		if key == "" || len(key) > 256 || err != nil || end.After(issued.Add(MaxLifetime)) {
			return errors.New("invalid authorization grant")
		}
	}
	return nil
}

func (l *Lease) Allows(key string, now time.Time) bool {
	if key == "" {
		return false
	}
	if l == nil {
		return false
	}
	issued, err := time.Parse(time.RFC3339Nano, l.IssuedAt)
	if err != nil || now.Before(issued) || !now.Before(issued.Add(MaxLifetime)) {
		return false
	}
	end, err := time.Parse(time.RFC3339Nano, l.Grants[key])
	return err == nil && !end.After(issued.Add(MaxLifetime)) && now.Before(end)
}

// Store never lets configuration replay or rollback replace a newer full snapshot.
type Store struct {
	mu     sync.Mutex
	path   string
	loaded bool
	err    error
	lease  *Lease
}

func NewStore(path string) *Store { return &Store{path: path} }

func clone(l *Lease) *Lease {
	if l == nil {
		return nil
	}
	out := *l
	out.Grants = make(map[string]string, len(l.Grants))
	for k, v := range l.Grants {
		out.Grants[k] = v
	}
	return &out
}

func (s *Store) load() {
	if s.loaded {
		return
	}
	s.loaded = true
	if s.path == "" {
		return
	}
	data, err := os.ReadFile(s.path)
	if errors.Is(err, os.ErrNotExist) {
		return
	}
	if err != nil {
		s.err = err
		return
	}
	var l Lease
	if err := json.Unmarshal(data, &l); err != nil {
		s.err = err
		return
	}
	if err := l.Validate(); err != nil {
		s.err = err
		return
	}
	s.lease = clone(&l)
}

func (s *Store) Snapshot() (*Lease, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.load()
	return clone(s.lease), s.err
}

func (s *Store) Allows(key string, now time.Time) bool {
	if key == "" {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.load()
	return s.err == nil && s.lease.Allows(key, now)
}

func (s *Store) Update(incoming *Lease) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.load()
	if s.err != nil {
		return fmt.Errorf("authorization state unreadable: %w", s.err)
	}
	if incoming == nil {
		return nil
	}
	if err := incoming.Validate(); err != nil {
		return err
	}
	candidate := clone(incoming)
	if s.lease != nil {
		previousTime, _ := time.Parse(time.RFC3339Nano, s.lease.IssuedAt)
		nextTime, _ := time.Parse(time.RFC3339Nano, candidate.IssuedAt)
		if candidate.Revision < s.lease.Revision || candidate.Revision == s.lease.Revision && nextTime.Before(previousTime) {
			return nil
		}
		if candidate.Revision == s.lease.Revision && nextTime.Equal(previousTime) {
			if !reflect.DeepEqual(candidate.Grants, s.lease.Grants) {
				return errors.New("authorization snapshot identity reused with different grants")
			}
			return nil
		}
	}
	if s.path != "" {
		data, err := json.Marshal(candidate)
		if err != nil {
			return err
		}
		if err := writeAtomic(s.path, data); err != nil {
			s.err = err
			return err
		}
	}
	s.lease = candidate
	return nil
}

func writeAtomic(path string, data []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	file, err := os.CreateTemp(filepath.Dir(path), ".authorization-*")
	if err != nil {
		return err
	}
	defer os.Remove(file.Name())
	if err := file.Chmod(0600); err != nil {
		file.Close()
		return err
	}
	if _, err := file.Write(data); err != nil {
		file.Close()
		return err
	}
	if err := file.Sync(); err != nil {
		file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	if err := os.Rename(file.Name(), path); err != nil {
		return err
	}
	dir, err := os.Open(filepath.Dir(path))
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}
