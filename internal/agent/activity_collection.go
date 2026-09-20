package agent

import (
	"context"
	"github.com/OboardProject/oboard-agent/internal/auditwire"
	"net/http"
	"os"
	"reflect"
	"time"
)

type auditCollectionPolicy = auditwire.CollectionPolicy

func (r *Runner) collectDiagnosticActivity(ctx context.Context) {
	if r.connectionAudit == nil {
		return
	}
	p := r.connectionAudit.collection.Load()
	if p == nil {
		return
	}
	now := r.connectionAudit.activityNow()
	if p.Mode == "diagnostic" && !now.Before(p.DiagnosticUntil) {
		resolved := *p
		resolved.Mode = p.BaseMode
		if resolved.Mode == "" {
			resolved.Mode = "light"
		}
		resolved.DiagnosticUserIDs = nil
		r.setAuditCollectionPolicy(&resolved)
		p = &resolved
	}
	if p.Mode == "standard" || p.Mode == "diagnostic" {
		_ = r.collectAndReportConnectionAudits(ctx)
	}
}

func (a *connectionAuditAccumulator) setCollectionPolicy(p auditCollectionPolicy) {
	if !p.Valid() {
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	old := a.collection.Load()
	if old != nil && (p.Revision < old.Revision || reflect.DeepEqual(*old, p)) {
		return
	}
	p.DiagnosticUserIDs = append([]int64(nil), p.DiagnosticUserIDs...)
	a.collection.Store(&p)
	// Existing detail sessions reference generation-qualified keys and cannot
	// resume writing after a policy switch. Activity accounting is untouched.
	a.buckets = nil
	a.activeByIdentity = nil
	a.presenceStates = nil
	a.presenceEvents = nil
	a.generation++
}
func (r *Runner) setAuditCollectionPolicy(p *auditCollectionPolicy) {
	if p == nil {
		p = &auditCollectionPolicy{Mode: "light"}
		if r.connectionAudit != nil {
			if old := r.connectionAudit.collection.Load(); old != nil {
				p.Revision = old.Revision
			}
		}
	}
	if !p.Valid() {
		return
	}
	if r.connectionAudit != nil && p.Mode == "diagnostic" && !r.connectionAudit.activityNow().Before(p.DiagnosticUntil) {
		resolved := *p
		resolved.Mode = p.BaseMode
		if resolved.Mode == "" {
			resolved.Mode = "light"
		}
		resolved.DiagnosticUserIDs = nil
		p = &resolved
	}
	if r.connectionAudit != nil {
		old := r.connectionAudit.collection.Load()
		if old != nil && p.Revision < old.Revision {
			return
		}
		r.connectionAudit.setCollectionPolicy(*p)
	}
	if p.Mode == "light" {
		r.connectionAuditMu.Lock()
		r.connectionAuditState = connectionAuditLocalState{}
		r.connectionAuditStateLoaded = false
		_ = os.Remove(r.connectionAuditStatePath())
		r.connectionAuditMu.Unlock()
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	_ = r.activityLocal(ctx, http.MethodPost, "/activity/config", p, nil)
}
