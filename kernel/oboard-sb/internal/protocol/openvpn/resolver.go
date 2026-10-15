// SPDX-License-Identifier: GPL-3.0-or-later

package openvpn

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

const (
	resolveTimeout    = 4 * time.Second
	resolverQueryWait = 2 * time.Second
	maxCacheEntries   = 1024
	minCacheTTL       = 10 * time.Second
	maxCacheTTL       = 5 * time.Minute
	negativeCacheTTL  = 5 * time.Second
)

var errNoIPv4Answer = errors.New("domain has no IPv4 address")

type cacheEntry struct {
	addrs   []netip.Addr
	err     error
	expires time.Time
}

// resolver answers A queries over resolvers reached through the tunnel itself,
// so name resolution follows the same exit as the connection it serves.
type resolver struct {
	tunnel    *Tunnel
	resolvers []netip.Addr
	mu        sync.Mutex
	cache     map[string]cacheEntry
}

func newResolver(t *Tunnel, servers []string) *resolver {
	r := &resolver{tunnel: t, cache: map[string]cacheEntry{}}
	for _, raw := range servers {
		if addr, err := netip.ParseAddr(raw); err == nil {
			r.resolvers = append(r.resolvers, addr.Unmap())
		}
	}
	return r
}

func (r *resolver) lookupIPv4(ctx context.Context, name string) ([]netip.Addr, error) {
	name = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(name)), ".")
	if name == "" {
		return nil, fmt.Errorf("empty domain")
	}
	if addr, err := netip.ParseAddr(name); err == nil {
		if !addr.Unmap().Is4() {
			return nil, ErrIPv6Unsupported
		}
		return []netip.Addr{addr.Unmap()}, nil
	}
	now := time.Now()
	r.mu.Lock()
	if entry, ok := r.cache[name]; ok && now.Before(entry.expires) {
		r.mu.Unlock()
		return entry.addrs, entry.err
	}
	r.mu.Unlock()
	if _, ok := ctx.Deadline(); !ok {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, resolveTimeout)
		defer cancel()
	}
	addrs, ttl, err := r.query(ctx, name)
	expires := now.Add(ttl)
	if err != nil {
		expires = now.Add(negativeCacheTTL)
	}
	r.mu.Lock()
	if len(r.cache) >= maxCacheEntries {
		r.cache = map[string]cacheEntry{}
	}
	r.cache[name] = cacheEntry{addrs: addrs, err: err, expires: expires}
	r.mu.Unlock()
	return addrs, err
}

func (r *resolver) query(ctx context.Context, name string) ([]netip.Addr, time.Duration, error) {
	message := new(dns.Msg)
	message.SetQuestion(dns.Fqdn(name), dns.TypeA)
	message.RecursionDesired = true
	var lastErr error
	for _, server := range r.resolvers {
		if err := ctx.Err(); err != nil {
			return nil, 0, err
		}
		response, err := r.exchange(ctx, server, message, N.NetworkUDP)
		if err == nil && response.Truncated {
			response, err = r.exchange(ctx, server, message, N.NetworkTCP)
		}
		if err != nil {
			lastErr = err
			continue
		}
		if response.Rcode == dns.RcodeNameError {
			return nil, 0, fmt.Errorf("domain %s does not exist", name)
		}
		if response.Rcode != dns.RcodeSuccess {
			lastErr = fmt.Errorf("resolver returned %s", dns.RcodeToString[response.Rcode])
			continue
		}
		var addrs []netip.Addr
		ttl := maxCacheTTL
		for _, answer := range response.Answer {
			record, ok := answer.(*dns.A)
			if !ok {
				continue
			}
			addr, ok := netip.AddrFromSlice(record.A)
			if !ok || !addr.Unmap().Is4() {
				continue
			}
			addrs = append(addrs, addr.Unmap())
			if recordTTL := time.Duration(record.Hdr.Ttl) * time.Second; recordTTL < ttl {
				ttl = recordTTL
			}
		}
		if len(addrs) == 0 {
			return nil, 0, errNoIPv4Answer
		}
		if ttl < minCacheTTL {
			ttl = minCacheTTL
		}
		return addrs, ttl, nil
	}
	if lastErr == nil {
		lastErr = errors.New("no resolver available")
	}
	return nil, 0, fmt.Errorf("resolve %s inside tunnel: %w", name, lastErr)
}

func (r *resolver) exchange(ctx context.Context, server netip.Addr, message *dns.Msg, network string) (*dns.Msg, error) {
	queryCtx, cancel := context.WithTimeout(ctx, resolverQueryWait)
	defer cancel()
	conn, err := r.tunnel.device.DialContext(queryCtx, network, M.SocksaddrFrom(server, 53))
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	if deadline, ok := queryCtx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}
	dnsConn := &dns.Conn{Conn: conn}
	if err := dnsConn.WriteMsg(message); err != nil {
		return nil, err
	}
	for {
		response, err := dnsConn.ReadMsg()
		if err != nil {
			return nil, err
		}
		if response.Id == message.Id {
			return response, nil
		}
	}
}
