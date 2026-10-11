package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"github.com/OboardProject/oboard-agent/internal/model"
	"io"
	"net/http"
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
	var p model.ProxyDSCPPolicy
	if err := json.Unmarshal([]byte(raw), &p); err != nil {
		return nil, err
	}
	if p.Revision <= 0 {
		return nil, fmt.Errorf("invalid DSCP revision")
	}
	report, err := r.proxyDSCPRequest(context.Background(), http.MethodPost, []byte(raw))
	if err != nil {
		return nil, err
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
