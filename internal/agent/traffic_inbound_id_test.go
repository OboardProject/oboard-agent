package agent

import (
	"testing"
)

// A pending report that names no inbound can never be accepted by any
// Controller. Before the fix, one such entry - produced when the Controller
// rendered a single-user inbound runtime limit without inbound_id - was resent
// in every batch, and the request-fatal 400 it earned never carried the
// per-report acknowledgement that would let it drain, so it wedged every
// healthy report behind it for as long as the state file existed.

func inboundlessPending(id string) *trafficPendingRange {
	return &trafficPendingRange{
		ReportID: id, Source: "core", StreamID: trafficStreamID("core", "user:7"),
		CounterEpoch: "ce_1", PeriodKey: "2026-09-01", UserID: 7,
		FromUpload: 0, ToUpload: 100, FromDownload: 0, ToDownload: 200,
		SnapshotKey: "user:7",
	}
}

func inboundfulPending(id string) *trafficPendingRange {
	report := inboundlessPending(id)
	inboundID := int64(104)
	report.InboundID = &inboundID
	return report
}

// Loading a poisoned state file drops the inbound-less pending entries and
// keeps the healthy ones, so a server poisoned by an older configuration
// self-heals on restart instead of resending the same batch forever.
func TestLoadTrafficStateDropsInboundlessPendingReports(t *testing.T) {
	runner := New(Config{StateDir: t.TempDir(), AgentID: "agent-1"})
	state := trafficLocalState{
		SchemaVersion: trafficStateSchemaV2,
		PendingReports: map[string]*trafficPendingRange{
			"tr-poison":  inboundlessPending("tr-poison"),
			"tr-healthy": inboundfulPending("tr-healthy"),
		},
	}
	if err := runner.saveTrafficState(state); err != nil {
		t.Fatal(err)
	}
	loaded := migrateLoadedTrafficState(runner.loadTrafficState(), false)
	if _, ok := loaded.PendingReports["tr-poison"]; ok {
		t.Fatal("inbound-less pending report survived the load-time cleanup")
	}
	if _, ok := loaded.PendingReports["tr-healthy"]; !ok {
		t.Fatal("healthy pending report was dropped by the load-time cleanup")
	}
}

// A counter without inbound identity never queues a report in the first place.
func TestObserveTrafficSnapshotSkipsInboundlessCounters(t *testing.T) {
	runner := New(Config{StateDir: t.TempDir(), AgentID: "agent-1"})
	state := runner.trafficStateLocked()
	state.RecoveryRequired = false
	state.Sync.Status = trafficStatusHealthy
	changed := runner.observeTrafficSnapshotLocked(state, []trafficSnapshotItem{
		{Key: "user:7", Source: "core", CounterEpoch: "ce_1", UserID: 7, PeriodKey: "2026-09-01", Upload: 10, Download: 20},
		{Key: "user:8", Source: "core", CounterEpoch: "ce_2", UserID: 8, InboundID: 104, PeriodKey: "2026-09-01", Upload: 30, Download: 40},
	}, false)
	if !changed {
		t.Fatal("expected the healthy counter to be observed")
	}
	if len(state.PendingReports) != 1 {
		t.Fatalf("pending = %#v, want only the inbound-identified report", state.PendingReports)
	}
	for _, report := range state.PendingReports {
		if report.InboundID == nil || *report.InboundID != 104 {
			t.Fatalf("queued report = %#v, want the inbound-identified one", report)
		}
	}
}

// The wire batch never carries an inbound-less report, even if a future
// regression writes one into the state file.
func TestLedgerReportBatchOmitsInboundlessReports(t *testing.T) {
	batch := trafficLedgerReportBatch(map[string]*trafficPendingRange{
		"tr-poison":  inboundlessPending("tr-poison"),
		"tr-healthy": inboundfulPending("tr-healthy"),
	})
	if len(batch) != 1 || batch[0].InboundID == nil || *batch[0].InboundID != 104 {
		t.Fatalf("batch = %#v, want only the inbound-identified report", batch)
	}
}

// The Controller's per-report invalid_report rejection is terminal: the
// pending entry is dropped without entering counter recovery, because local
// counters remain consistent.
func TestInvalidReportRejectionIsTerminal(t *testing.T) {
	if !terminalTrafficRejectionReason("invalid_report") {
		t.Fatal("invalid_report must be a terminal rejection reason")
	}
	state := &trafficLocalState{SchemaVersion: 2, Streams: map[string]*trafficStreamState{}, PendingReports: map[string]*trafficPendingRange{}}
	state.PendingReports["tr-poison"] = inboundfulPending("tr-poison")
	applyTrafficLedgerResponse(state, trafficReportResponse{
		AcceptedReports: []trafficAcceptedReport{{ReportID: "tr-poison", Status: "rejected", Reason: "invalid_report"}},
	})
	if _, ok := state.PendingReports["tr-poison"]; ok {
		t.Fatal("rejected report was not dropped")
	}
	if state.RecoveryRequired {
		t.Fatal("a terminal rejection must not open counter recovery")
	}
}
