package agent

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

const (
	remoteExecStateRunning   = "running"
	remoteExecStateCompleted = "completed"
	remoteExecJournalKeep    = 100
	remoteExecJournalTTL     = 24 * time.Hour
)

var (
	errRemoteExecRunning  = errors.New("request_id is already running")
	errRemoteExecConflict = errors.New("request_id_conflict")
)

type remoteExecJournalRecord struct {
	RequestID  string    `json:"request_id"`
	Digest     string    `json:"digest"`
	State      string    `json:"state"`
	StartedAt  time.Time `json:"started_at"`
	FinishedAt time.Time `json:"finished_at,omitempty"`
	ResultJSON []byte    `json:"result_json,omitempty"`
}

type remoteExecJournal struct {
	mu  sync.Mutex
	dir string
}

func newRemoteExecJournal(dir string) *remoteExecJournal {
	return &remoteExecJournal{dir: dir}
}

func (j *remoteExecJournal) Begin(requestID, digest string) (*remoteExecJournalRecord, error) {
	j.mu.Lock()
	defer j.mu.Unlock()
	if err := os.MkdirAll(j.dir, 0o700); err != nil {
		return nil, err
	}
	j.pruneLocked()
	record, err := j.readLocked(requestID)
	if err == nil {
		if record.Digest != digest {
			return nil, errRemoteExecConflict
		}
		if record.State == remoteExecStateRunning {
			return nil, errRemoteExecRunning
		}
		return record, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	record = &remoteExecJournalRecord{RequestID: requestID, Digest: digest, State: remoteExecStateRunning, StartedAt: time.Now().UTC()}
	return nil, j.writeLocked(record)
}

func (j *remoteExecJournal) Complete(requestID, digest string, result []byte) error {
	j.mu.Lock()
	defer j.mu.Unlock()
	record := &remoteExecJournalRecord{
		RequestID: requestID, Digest: digest, State: remoteExecStateCompleted,
		StartedAt: time.Now().UTC(), FinishedAt: time.Now().UTC(), ResultJSON: result,
	}
	if existing, err := j.readLocked(requestID); err == nil {
		record.StartedAt = existing.StartedAt
	}
	return j.writeLocked(record)
}

func (j *remoteExecJournal) readLocked(requestID string) (*remoteExecJournalRecord, error) {
	raw, err := os.ReadFile(j.path(requestID))
	if err != nil {
		return nil, err
	}
	var record remoteExecJournalRecord
	if err := json.Unmarshal(raw, &record); err != nil {
		return nil, err
	}
	return &record, nil
}

func (j *remoteExecJournal) writeLocked(record *remoteExecJournalRecord) error {
	raw, err := json.Marshal(record)
	if err != nil {
		return err
	}
	tmp := j.path(record.RequestID) + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, j.path(record.RequestID))
}

func (j *remoteExecJournal) path(requestID string) string {
	safe := strings.Map(func(r rune) rune {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' || r == '_' {
			return r
		}
		return -1
	}, requestID)
	if safe == "" {
		safe = "invalid"
	}
	return filepath.Join(j.dir, safe+".json")
}

func (j *remoteExecJournal) pruneLocked() {
	entries, err := os.ReadDir(j.dir)
	if err != nil {
		return
	}
	type item struct {
		name string
		mod  time.Time
	}
	keep := make([]item, 0, len(entries))
	cutoff := time.Now().Add(-remoteExecJournalTTL)
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		info, err := entry.Info()
		if err != nil {
			continue
		}
		if info.ModTime().Before(cutoff) {
			_ = os.Remove(filepath.Join(j.dir, entry.Name()))
			continue
		}
		keep = append(keep, item{name: entry.Name(), mod: info.ModTime()})
	}
	if len(keep) <= remoteExecJournalKeep {
		return
	}
	sort.Slice(keep, func(i, k int) bool { return keep[i].mod.Before(keep[k].mod) })
	for _, item := range keep[:len(keep)-remoteExecJournalKeep] {
		_ = os.Remove(filepath.Join(j.dir, item.name))
	}
}
