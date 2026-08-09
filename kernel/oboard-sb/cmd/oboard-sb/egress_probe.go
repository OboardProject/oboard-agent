package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"regexp"
	"strings"
	"time"

	box "github.com/sagernet/sing-box"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

var pathOutboundTagPattern = regexp.MustCompile(`^path-[1-9][0-9]*-step-[1-9][0-9]*$`)

var outboundEgressSources = []string{
	"https://api.ip.sb/ip",
	"https://icanhazip.com",
}

type outboundEgressLookup func(tag string) (N.Dialer, bool)

func registerOutboundEgressHandler(mux *http.ServeMux, instance *box.Box) {
	lookup := func(tag string) (N.Dialer, bool) {
		if instance == nil {
			return nil, false
		}
		outbound, loaded := instance.Outbound().Outbound(tag)
		if !loaded {
			return nil, false
		}
		return outbound, true
	}
	mux.Handle("/outbounds/egress-ip", newOutboundEgressHandler(lookup, outboundEgressSources))
}

func newOutboundEgressHandler(lookup outboundEgressLookup, sources []string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, 1024)
		var request struct {
			OutboundTag string `json:"outbound_tag"`
		}
		decoder := json.NewDecoder(r.Body)
		if err := decoder.Decode(&request); err != nil {
			http.Error(w, "invalid request", http.StatusBadRequest)
			return
		}
		request.OutboundTag = strings.TrimSpace(request.OutboundTag)
		if !pathOutboundTagPattern.MatchString(request.OutboundTag) {
			http.Error(w, "outbound tag is not probeable", http.StatusBadRequest)
			return
		}
		dialer, loaded := lookup(request.OutboundTag)
		if !loaded || dialer == nil {
			http.Error(w, "outbound not found", http.StatusNotFound)
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 8*time.Second)
		defer cancel()
		exitIP, err := probeOutboundEgressIP(ctx, dialer, sources)
		if err != nil {
			http.Error(w, "egress probe failed", http.StatusBadGateway)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"exit_ip": exitIP})
	})
}

func probeOutboundEgressIP(ctx context.Context, dialer N.Dialer, sources []string) (string, error) {
	transport := &http.Transport{
		Proxy: nil,
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			return dialer.DialContext(ctx, network, M.ParseSocksaddr(address))
		},
		DisableCompression:    true,
		ForceAttemptHTTP2:     false,
		TLSHandshakeTimeout:   5 * time.Second,
		ResponseHeaderTimeout: 5 * time.Second,
		MaxConnsPerHost:       1,
		IdleConnTimeout:       time.Second,
	}
	defer transport.CloseIdleConnections()
	client := &http.Client{
		Transport: transport,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return errors.New("redirects are disabled")
		},
	}
	var lastErr error
	for _, source := range sources {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, source, nil)
		if err != nil {
			lastErr = err
			continue
		}
		res, err := client.Do(req)
		if err != nil {
			lastErr = err
			continue
		}
		body, readErr := io.ReadAll(io.LimitReader(res.Body, 257))
		_ = res.Body.Close()
		if readErr != nil {
			lastErr = readErr
			continue
		}
		if res.StatusCode != http.StatusOK {
			lastErr = fmt.Errorf("source returned status %d", res.StatusCode)
			continue
		}
		if len(body) > 256 {
			lastErr = errors.New("source response is too large")
			continue
		}
		addr, err := netip.ParseAddr(strings.TrimSpace(string(body)))
		if err != nil {
			lastErr = errors.New("source returned an invalid IP")
			continue
		}
		addr = addr.Unmap()
		if !isPublicOutboundEgressAddr(addr) {
			lastErr = errors.New("source returned a non-public IP")
			continue
		}
		return addr.String(), nil
	}
	if lastErr == nil {
		lastErr = errors.New("no egress probe sources configured")
	}
	return "", lastErr
}

func isPublicOutboundEgressAddr(addr netip.Addr) bool {
	if !addr.IsValid() || !addr.IsGlobalUnicast() || addr.IsPrivate() || addr.IsLoopback() || addr.IsUnspecified() || addr.IsLinkLocalUnicast() || addr.IsLinkLocalMulticast() || addr.IsMulticast() {
		return false
	}
	for _, raw := range []string{
		"0.0.0.0/8", "100.64.0.0/10", "192.0.0.0/24", "192.0.2.0/24", "192.88.99.0/24",
		"198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24", "240.0.0.0/4",
		"2001:2::/48", "2001:10::/28", "2001:db8::/32",
	} {
		if netip.MustParsePrefix(raw).Contains(addr) {
			return false
		}
	}
	return true
}
