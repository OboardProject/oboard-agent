package minibox

import (
	"github.com/OboardProject/oboard-agent/kernel/oboard-sb/internal/auditwire"
	"reflect"
)

func (t *RateLimitTracker) SetActivityCollection(p auditwire.CollectionPolicy) bool {
	if !p.Valid() {
		return false
	}
	t.auditMu.Lock()
	defer t.auditMu.Unlock()
	old := t.auditCollection.Load()
	if old != nil {
		if p.Revision < old.Revision {
			return false
		}
		if reflect.DeepEqual(*old, p) {
			return true
		}
	}
	p.DiagnosticUserIDs = append([]int64(nil), p.DiagnosticUserIDs...)
	t.auditCollection.Store(&p)
	t.auditDiagnostics.Store(p.Mode != "light")
	t.auditBuckets = nil
	t.auditActiveByIdentity = nil
	t.auditFamilyChildTypes = nil
	t.presenceStates = nil
	t.presenceEvents = nil
	t.auditGeneration++
	return true
}

func (t *RateLimitTracker) AlignActivityClock(controllerUnix int64) {
	now := t.timeNow().Unix()
	aligned := controllerUnix > 0 && now >= controllerUnix-2 && now <= controllerUnix+2
	t.activity.AlignClock(now, aligned)
}
func (t *RateLimitTracker) ReadActivity() *auditwire.Report {
	return t.activity.Read(t.timeNow(), "kernel")
}
func (t *RateLimitTracker) AckActivity(boot string, sequence uint64) bool {
	return t.activity.Ack(boot, sequence)
}
