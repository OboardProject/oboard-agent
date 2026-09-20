package agent

import (
	"fmt"
	"testing"
	"time"
)

func TestBasicSSHActivitySurvivesDiagnosticCapacity(t *testing.T) {
	now := int64(120)
	a := newConnectionAuditAccumulator(true, func() time.Time { return time.Unix(now, 0) })
	// Fill destination diagnostics, without any business activity.
	for i := 0; i < maxAgentAuditBuckets; i++ {
		a.startSession(connectionAuditSnapshotItem{UserID: 7, InboundID: 11, SourceIP: "198.51.100.1", Destination: fmt.Sprintf("%d.example", i)})
	}
	session := a.startSession(connectionAuditSnapshotItem{UserID: 7, InboundID: 11, SourceIP: "198.51.100.2", Destination: "overflow.example"})
	if session.key != "" {
		t.Fatal("fixture did not exhaust diagnostic capacity")
	}
	if len(a.activity.Snapshot(now).Buckets) != 0 {
		t.Fatal("no business payload")
	}
	session.addTraffic(true, 100)
	now = 135
	session.addTraffic(false, 200)
	s := a.activity.Snapshot(now)
	if len(s.Buckets) != 1 || s.Buckets[0].ActivityBits != 9 || s.Buckets[0].UploadBytes != 100 || s.Buckets[0].DownloadBytes != 200 {
		t.Fatalf("SSH payload hooks: %+v", s)
	}
	a.setEnabled(false)
	session.addTraffic(true, 1)
	if len(a.activity.Snapshot(now).Buckets) != 0 {
		t.Fatal("disabled collection")
	}
}
