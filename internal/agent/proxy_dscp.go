package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/OboardProject/oboard-agent/internal/model"
	"io"
	"net"
	"net/http"
	"syscall"
	"time"
)

func (r *Runner) proxyDSCPRequest(ctx context.Context, method string, body []byte) (*model.ProxyDSCPReport, error) {
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, method, "http://oboard-sb/proxy/dscp", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	client := r.coreClient
	if client == nil {
		return nil, fmt.Errorf("kernel local API is unavailable")
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("kernel DSCP returned HTTP %d", resp.StatusCode)
	}
	var report model.ProxyDSCPReport
	if err = json.NewDecoder(io.LimitReader(resp.Body, 4096)).Decode(&report); err != nil {
		return nil, err
	}
	return &report, nil
}
func (r *Runner) applyProxyDSCP(raw string) (map[string]any, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	return r.applyProxyDSCPContext(ctx, raw, time.Second)
}

func (r *Runner) applyProxyDSCPContext(ctx context.Context, raw string, retryInterval time.Duration) (map[string]any, error) {
	var p model.ProxyDSCPPolicy
	if err := json.Unmarshal([]byte(raw), &p); err != nil {
		return nil, err
	}
	if p.Revision <= 0 {
		return nil, fmt.Errorf("invalid DSCP revision")
	}
	var report *model.ProxyDSCPReport
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		var err error
		report, err = r.proxyDSCPRequest(ctx, http.MethodPost, []byte(raw))
		if err == nil {
			break
		}
		var op *net.OpError
		if !errors.As(err, &op) || op.Op != "dial" || op.Net != "unix" || (!errors.Is(err, syscall.ENOENT) && !errors.Is(err, syscall.ECONNREFUSED)) {
			return nil, err
		}
		timer := time.NewTimer(retryInterval)
		select {
		case <-ctx.Done():
			timer.Stop()
			return nil, fmt.Errorf("waiting for kernel DSCP API: %w (last error: %v)", ctx.Err(), err)
		case <-timer.C:
		}
	}
	if report.Revision != p.Revision || report.Enabled != p.Enabled {
		return nil, fmt.Errorf("kernel DSCP acknowledgement mismatch")
	}
	return map[string]any{"proxy_dscp": report, "requires_restart": false}, nil
}
func (r *Runner) proxyDSCPHealth() *model.ProxyDSCPReport {
	report, err := r.proxyDSCPRequest(context.Background(), http.MethodGet, nil)
	if err != nil {
		return nil
	}
	return report
}
