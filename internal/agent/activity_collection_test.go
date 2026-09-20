package agent

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestAccountActivityCollectionScopeAndExpiry(t *testing.T) {
	now := time.Unix(600, 0)
	r := New(Config{StateDir: t.TempDir(), ConnectionAuditEnabled: true})
	r.connectionAudit.activityNow = func() time.Time { return now }
	r.coreClient = &http.Client{Transport: roundTripFunc(func(q *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(`{}`)), Header: make(http.Header)}, nil
	})}
	item := connectionAuditSnapshotItem{UserID: 1, InboundID: 2, SourceIP: "8.8.8.8", Destination: "example.org"}
	s := r.connectionAudit.startSession(item)
	s.addTraffic(true, 100)
	if len(r.connectionAudit.buckets) != 0 || len(r.connectionAudit.activity.Snapshot(600).Buckets) != 1 {
		t.Fatal("light coupled to detail")
	}
	p := auditCollectionPolicy{Mode: "diagnostic", DiagnosticUserIDs: []int64{1}, DiagnosticUntil: now.Add(time.Minute), Revision: 1, BaseMode: "light"}
	r.setAuditCollectionPolicy(&p)
	s = r.connectionAudit.startSession(item)
	s.addTraffic(true, 100)
	if len(r.connectionAudit.buckets) != 1 {
		t.Fatal("selected account not collected")
	}
	item.UserID = 2
	r.connectionAudit.startSession(item).addTraffic(true, 100)
	if len(r.connectionAudit.buckets) != 1 {
		t.Fatal("unselected account collected")
	}
	now = now.Add(time.Minute)
	s.addTraffic(true, 100)
	r.collectDiagnosticActivity(context.Background())
	if len(r.connectionAudit.buckets) != 0 || r.connectionAudit.collection.Load().Mode != "light" {
		t.Fatal("expired diagnostic retained detail")
	}
	if len(r.connectionAudit.activity.Snapshot(660).Buckets) == 0 {
		t.Fatal("expiry disabled basic activity")
	}
	r.setAuditCollectionPolicy(&p)
	if r.connectionAudit.collection.Load().Mode != "light" {
		t.Fatal("heartbeat revived expired diagnostic")
	}
}
func TestAccountActivityCapabilityRequiresKernel(t *testing.T) {
	r := New(Config{StateDir: t.TempDir()})
	has := func(caps []string) bool {
		for _, v := range caps {
			if v == "account_activity_v1" {
				return true
			}
		}
		return false
	}
	if has(r.agentCapabilities(nil)) || !has(r.agentCapabilities([]string{"account_activity_local_v1"})) {
		t.Fatal("capability gate")
	}
}
