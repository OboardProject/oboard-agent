package agent

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"
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
	if runner.connectionAudit.buckets != nil || runner.connectionAudit.activeByIdentity != nil {
		t.Fatalf("disabled SSH audit allocated state: buckets=%#v active=%#v", runner.connectionAudit.buckets, runner.connectionAudit.activeByIdentity)
	}
	if _, err := os.Stat(runner.connectionAuditStatePath()); !os.IsNotExist(err) {
		t.Fatalf("disabled connection audit state file exists: %v", err)
	}
}

func TestConnectionPresenceCombinesKernelAndSSHWithGlobalSequence(t *testing.T) {
	runner := New(Config{StateDir: t.TempDir(), ServerID: 9, ConnectionAuditEnabled: true})
	runner.coreClient = &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		switch req.URL.Path {
		case "/version":
			return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(`{"capabilities":["connection_presence_v1"]}`)), Header: make(http.Header)}, nil
		case "/connections/presence/drain":
			body, _ := json.Marshal(map[string]any{"events": []map[string]any{{"user_id": 7, "inbound_id": 11, "device_id_hash": "device-core", "credential_epoch": 1, "source_ip": "198.51.100.10", "network": "tcp", "event": "first_authenticated", "state": "active", "active_connections": 1, "at": time.Now().UTC().Format(time.RFC3339Nano)}}})
			return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(string(body))), Header: make(http.Header)}, nil
		default:
			return &http.Response{StatusCode: http.StatusNotFound, Body: http.NoBody, Header: make(http.Header)}, nil
		}
	})}
	session := runner.connectionAudit.startSession(connectionAuditSnapshotItem{UserID: 8, InboundID: 12, DeviceIDHash: "device-ssh", CredentialEpoch: 3, SourceIP: "198.51.100.11", Network: "tcp"})
	defer session.finish()

	delta, err := runner.collectConnectionPresenceDelta(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(delta.Events) != 2 {
		t.Fatalf("presence events = %#v", delta.Events)
	}
	if delta.Events[0].ServerID != 9 || delta.Events[1].ServerID != 9 || delta.Events[0].Sequence == 0 || delta.Events[1].Sequence <= delta.Events[0].Sequence {
		t.Fatalf("presence identity or sequence = %#v", delta.Events)
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

func TestConnectionAuditPeakIsScopedToDevice(t *testing.T) {
	audit := newConnectionAuditAccumulator(true)
	first := audit.start(connectionAuditSnapshotItem{UserID: 7, DeviceIDHash: "device-a", SourceIP: "198.51.100.4", Destination: "one.example", DestinationPort: 443})
	second := audit.start(connectionAuditSnapshotItem{UserID: 7, DeviceIDHash: "device-b", SourceIP: "198.51.100.5", Destination: "two.example", DestinationPort: 443})
	items := audit.drain()
	if len(items) != 2 {
		t.Fatalf("drain items = %d, want 2: %#v", len(items), items)
	}
	for _, item := range items {
		if item.ActivePeak != 1 {
			t.Fatalf("device %s peak = %d, want 1", item.DeviceIDHash, item.ActivePeak)
		}
	}
	first()
	second()
}

func TestConnectionAuditDurationAndCoverageSurviveDrain(t *testing.T) {
	audit := newConnectionAuditAccumulator(true)
	finish := audit.start(connectionAuditSnapshotItem{UserID: 7, SourceIP: "198.51.100.4", Destination: "one.example", DestinationPort: 443})
	finish()
	items := audit.drain()
	if len(items) != 1 || items[0].ClosedCount != 1 || items[0].BucketCapacity != maxAgentAuditBuckets || items[0].CollectionStartedAt == "" || items[0].CollectionEndedAt == "" {
		t.Fatalf("duration or coverage metadata was lost: %#v", items)
	}
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
