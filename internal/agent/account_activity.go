package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/OboardProject/oboard-agent/internal/auditwire"
	"io"
	"net/http"
	"os"
	"time"
)

func (r *Runner) activityLocal(ctx context.Context, method, path string, input, output any) error {
	var body io.Reader
	if input != nil {
		b, err := json.Marshal(input)
		if err != nil {
			return err
		}
		body = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, "http://oboard-sb"+path, body)
	if err != nil {
		return err
	}
	client := r.coreClient
	if client == nil {
		client = unixHTTPClient(r.coreAPISocketPath())
	}
	res, err := client.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	if res.StatusCode != 200 {
		return fmt.Errorf("activity local status %d", res.StatusCode)
	}
	if output != nil {
		return json.NewDecoder(io.LimitReader(res.Body, auditwire.MaxReportBytes+1)).Decode(output)
	}
	return nil
}

// The synced pending file is the ownership boundary: local ACK follows fsync,
// Controller ACK precedes removal. Failed saves never advance either boundary.
func (r *Runner) collectAndReportAccountActivity(ctx context.Context) (outErr error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	r.connectionAuditMu.Lock()
	defer r.connectionAuditMu.Unlock()
	path := r.statePath("account-activity-pending.json")
	if !r.Config().ConnectionAuditEnabled {
		return r.clearAccountActivityPending()
	}
	var pending []auditwire.Report
	defer func() { r.noteSyncOutcome("account_activity", "durable_delivery", 0, len(pending), outErr) }()
	raw, err := r.stateReadPath(path)
	if err == nil {
		if len(raw) > auditwire.MaxPendingBytes {
			return errors.New("activity pending over budget")
		}
		if err = json.Unmarshal(raw, &pending); err != nil {
			return err
		}
	} else if !os.IsNotExist(err) {
		return err
	}
	save := func(items []auditwire.Report) error {
		b, e := json.Marshal(items)
		if e != nil {
			return e
		}
		if len(items) > auditwire.MaxPending || len(b) > auditwire.MaxPendingBytes {
			return errors.New("activity pending capacity")
		}
		if e = os.MkdirAll(r.stateDir(), 0700); e != nil {
			return e
		}
		return r.stateWritePathSynced(path, b, 0600)
	}
	accept := func(report *auditwire.Report, ack func() error) error {
		if report == nil {
			return nil
		}
		encoded, e := json.Marshal(report)
		if e != nil {
			return e
		}
		if len(encoded) > auditwire.MaxReportBytes || len(report.Items) > 4096 {
			return errors.New("activity report capacity")
		}
		for _, p := range pending {
			if p.CollectorBootID == report.CollectorBootID && p.StreamType == report.StreamType && p.Sequence == report.Sequence {
				old, _ := json.Marshal(p)
				if !bytes.Equal(old, encoded) {
					return errors.New("activity local identity conflict")
				}
				return ack()
			}
		}
		next := append(append([]auditwire.Report{}, pending...), *report)
		if e = save(next); e != nil {
			return e
		}
		pending = next
		return ack()
	}
	controllerUnix := int64(0)
	if reference, ok := r.controllerReferenceNow(); ok {
		controllerUnix = reference.Unix()
	}
	_ = r.activityLocal(ctx, http.MethodPost, "/activity/clock", map[string]int64{"controller_unix": controllerUnix}, nil)
	if r.connectionAudit != nil {
		now := r.connectionAudit.activityNow().Unix()
		r.connectionAudit.activity.AlignClock(now, controllerUnix > 0 && now >= controllerUnix-2 && now <= controllerUnix+2)
	}
	var kernel *auditwire.Report
	localErr := r.activityLocal(ctx, http.MethodGet, "/activity/read", nil, &kernel)
	if localErr == nil {
		localErr = accept(kernel, func() error {
			return r.activityLocal(ctx, http.MethodPost, "/activity/ack", auditwire.Ack{CollectorBootID: kernel.CollectorBootID, Sequence: kernel.Sequence}, nil)
		})
	}
	if r.connectionAudit != nil {
		ssh := r.connectionAudit.activity.Read(r.connectionAudit.activityNow(), "ssh")
		if e := accept(ssh, func() error { r.connectionAudit.activity.Ack(ssh.CollectorBootID, ssh.Sequence); return nil }); e != nil {
			localErr = e
		}
	}
	r.noteSyncOutcome("account_activity_local", "persist_then_ack", 0, len(pending), localErr)
	// Bounded catch-up; failures leave immutable bytes on disk.
	for sent := 0; sent < 8 && len(pending) > 0; sent++ {
		var ack auditwire.Ack
		if err = r.postControllerJSON(ctx, "/api/v1/agent/account-activity", pending[0], &ack, true); err != nil {
			return err
		}
		if ack.Sequence != pending[0].Sequence || (!ack.Accepted && !ack.Terminal) {
			return errors.New("activity response did not acknowledge report")
		}
		if ack.Terminal && ack.Reason != "expired" && ack.Reason != "disabled" && ack.Reason != "subject_removed" {
			return errors.New("activity unknown terminal reason")
		}
		if err = save(pending[1:]); err != nil {
			return err
		}
		pending = pending[1:]
	}
	return localErr
}
func (r *Runner) clearAccountActivityPending() error {
	err := os.Remove(r.statePath("account-activity-pending.json"))
	if os.IsNotExist(err) {
		return nil
	}
	return err
}
