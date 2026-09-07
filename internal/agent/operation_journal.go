package agent

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"
)

const (
	operationJournalKeep     = 64
	operationJournalTTL      = 36 * time.Hour
	operationJournalFileName = "host-power-journal.json"
)

var (
	errOperationConflict   = errors.New("operation_id_conflict")
	errOperationInFlight   = errors.New("operation_id is already running")
	errOperationJournalFull = errors.New("operation journal is full")
)

type operationJournalRecord struct {
	OperationID string          `json:"operation_id"`
	Digest      string          `json:"digest"`
	State       string          `json:"state"`
	Action      string          `json:"action"`
	ResultJSON  json.RawMessage `json:"result_json,omitempty"`
	StartedAt   time.Time       `json:"started_at"`
	FinishedAt  time.Time       `json:"finished_at,omitempty"`
}

type operationJournal struct {
	mu   sync.Mutex
	path string
}

func newOperationJournal(dir string) *operationJournal {
	return &operationJournal{path: filepath.Join(dir, operationJournalFileName)}
}

func (j *operationJournal) Begin(operationID, digest, action string) (*operationJournalRecord, error) {
	j.mu.Lock()
	defer j.mu.Unlock()
	items, err := j.loadLocked()
	if err != nil {
		return nil, err
	}
	if existing, ok := items[operationID]; ok {
		if existing.Digest != digest {
			return nil, errOperationConflict
		}
		if existing.State == "pending" || existing.State == "initiated" {
			return nil, errOperationInFlight
		}
		return &existing, nil
	}
	if journalWouldEvictPending(items) {
		return nil, errOperationJournalFull
	}
	record := operationJournalRecord{OperationID: operationID, Digest: digest, Action: action, State: "pending", StartedAt: time.Now().UTC()}
	items[operationID] = record
	if err := j.saveLocked(items); err != nil {
		return nil, err
	}
	return &record, nil
}

func (j *operationJournal) Complete(operationID, digest, state string, result json.RawMessage) error {
	j.mu.Lock()
	defer j.mu.Unlock()
	items, err := j.loadLocked()
	if err != nil {
		return err
	}
	existing, ok := items[operationID]
	if !ok {
		existing = operationJournalRecord{OperationID: operationID, Digest: digest, StartedAt: time.Now().UTC()}
	}
	if existing.Digest != "" && existing.Digest != digest {
		return errOperationConflict
	}
	existing.Digest = digest
	existing.State = state
	existing.ResultJSON = result
	existing.FinishedAt = time.Now().UTC()
	items[operationID] = existing
	return j.saveLocked(items)
}

func (j *operationJournal) loadLocked() (map[string]operationJournalRecord, error) {
	raw, err := os.ReadFile(j.path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return map[string]operationJournalRecord{}, nil
		}
		return nil, err
	}
	var items []operationJournalRecord
	if err := json.Unmarshal(raw, &items); err != nil {
		return nil, err
	}
	out := map[string]operationJournalRecord{}
	for _, item := range items {
		out[item.OperationID] = item
	}
	return out, nil
}

func (j *operationJournal) saveLocked(items map[string]operationJournalRecord) error {
	if err := os.MkdirAll(filepath.Dir(j.path), 0o700); err != nil {
		return err
	}
	list := make([]operationJournalRecord, 0, len(items))
	for _, item := range items {
		list = append(list, item)
	}
	sort.Slice(list, func(i, k int) bool { return list[i].StartedAt.After(list[k].StartedAt) })
	kept := make([]operationJournalRecord, 0, len(list))
	now := time.Now().UTC()
	for _, item := range list {
		terminal := item.State == "succeeded" || item.State == "failed"
		if terminal && now.Sub(item.StartedAt) > operationJournalTTL && len(kept) >= operationJournalKeep {
			continue
		}
		if !terminal || len(kept) < operationJournalKeep {
			kept = append(kept, item)
		}
	}
	raw, err := json.Marshal(kept)
	if err != nil {
		return err
	}
	tmp := j.path + ".tmp"
	file, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	if _, err := file.Write(append(raw, '\n')); err != nil {
		_ = file.Close()
		_ = os.Remove(tmp)
		return err
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		_ = os.Remove(tmp)
		return err
	}
	if err := file.Close(); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	if dir, err := os.Open(filepath.Dir(j.path)); err == nil {
		_ = dir.Sync()
		_ = dir.Close()
	}
	if err := os.Rename(tmp, j.path); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return syncPath(j.path)
}

func journalWouldEvictPending(items map[string]operationJournalRecord) bool {
	pending := 0
	for _, item := range items {
		if item.State == "pending" || item.State == "initiated" || item.State == "unknown" {
			pending++
		}
	}
	return pending >= operationJournalKeep
}

func syncPath(path string) error {
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()
	return file.Sync()
}

func isJournalStorageError(err error) bool {
	if err == nil {
		return false
	}
	return errors.Is(err, syscall.ENOSPC) || strings.Contains(err.Error(), "no space")
}
