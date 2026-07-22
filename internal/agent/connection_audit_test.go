package agent

import (
	"context"
	"io"
	"net/http"
	"os"
	"sync/atomic"
	"testing"
)

func TestDisabledConnectionAuditDoesNotPollCoreOrWriteState(t *testing.T) {
	stateDir := t.TempDir()
	runner := New(Config{StateDir: stateDir, ConnectionAuditEnabled: false})
	var calls atomic.Int64
	runner.coreClient = &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		calls.Add(1)
		return &http.Response{StatusCode: http.StatusOK, Body: http.NoBody, Header: make(http.Header)}, nil
	})}
	if err := runner.collectAndReportConnectionAudits(context.Background()); err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 0 {
		t.Fatalf("disabled connection audit called core %d times", calls.Load())
	}
	finish := runner.connectionAudit.start(connectionAuditSnapshotItem{UserID: 7, SourceIP: "198.51.100.4"})
	finish()
	if runner.connectionAudit.buckets != nil || runner.connectionAudit.activeByUser != nil {
		t.Fatalf("disabled SSH audit allocated state: buckets=%#v active=%#v", runner.connectionAudit.buckets, runner.connectionAudit.activeByUser)
	}
	if _, err := os.Stat(runner.connectionAuditStatePath()); !os.IsNotExist(err) {
		t.Fatalf("disabled connection audit state file exists: %v", err)
	}
}

func TestConnectionAuditPolicyOnlySyncsCoreWhenChanged(t *testing.T) {
	runner := New(Config{StateDir: t.TempDir(), ConnectionAuditEnabled: false})
	var calls atomic.Int64
	runner.coreClient = &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		calls.Add(1)
		return &http.Response{StatusCode: http.StatusOK, Body: http.NoBody, Header: make(http.Header)}, nil
	})}

	runner.setConnectionAuditPolicy(false)
	runner.setConnectionAuditPolicy(true)
	runner.setConnectionAuditPolicy(true)
	runner.setConnectionAuditPolicy(false)

	if got := calls.Load(); got != 3 {
		t.Fatalf("core audit policy sync calls = %d, want 3", got)
	}
}

func TestConnectionAuditPolicyRetriesFailedCoreSync(t *testing.T) {
	runner := New(Config{StateDir: t.TempDir(), ConnectionAuditEnabled: false})
	var calls atomic.Int64
	runner.coreClient = &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		status := http.StatusOK
		if calls.Add(1) == 1 {
			status = http.StatusInternalServerError
		}
		return &http.Response{StatusCode: status, Body: io.NopCloser(http.NoBody), Header: make(http.Header)}, nil
	})}

	runner.setConnectionAuditPolicy(false)
	runner.setConnectionAuditPolicy(false)
	runner.setConnectionAuditPolicy(false)

	if got := calls.Load(); got != 2 {
		t.Fatalf("core audit retry calls = %d, want 2", got)
	}
}

func TestConnectionAuditPeakSpansDestinationBuckets(t *testing.T) {
	audit := newConnectionAuditAccumulator(true)
	first := audit.start(connectionAuditSnapshotItem{UserID: 7, SourceIP: "198.51.100.4", Destination: "one.example", DestinationPort: 443})
	second := audit.start(connectionAuditSnapshotItem{UserID: 7, SourceIP: "198.51.100.4", Destination: "two.example", DestinationPort: 443})
	items := audit.drain()
	if len(items) != 2 {
		t.Fatalf("drain items = %d, want 2: %#v", len(items), items)
	}
	peak := int64(0)
	for _, item := range items {
		if item.ActivePeak > peak {
			peak = item.ActivePeak
		}
	}
	if peak != 2 {
		t.Fatalf("cross-destination active peak = %d, want 2: %#v", peak, items)
	}
	first()
	second()
}

func TestConnectionAuditOldCloseDoesNotAffectReenabledGeneration(t *testing.T) {
	audit := newConnectionAuditAccumulator(true)
	oldFinish := audit.start(connectionAuditSnapshotItem{UserID: 7, SourceIP: "198.51.100.4", Destination: "example.com", DestinationPort: 443})
	audit.setEnabled(false)
	audit.setEnabled(true)
	newFinish := audit.start(connectionAuditSnapshotItem{UserID: 7, SourceIP: "198.51.100.4", Destination: "example.com", DestinationPort: 443})
	oldFinish()

	items := audit.drain()
	if len(items) != 1 || items[0].ActiveAtEnd != 1 {
		t.Fatalf("old close affected re-enabled audit state: %#v", items)
	}
	newFinish()
}
