package dnsgroup

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net/netip"
	"sync"
	"time"

	"github.com/OboardProject/oboard-agent/kernel/oboard-sb/internal/restrictedtarget"
	mDNS "github.com/miekg/dns"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/dns"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing/service"
)

const Type = "oboard-dns-group"

type Options struct {
	Members           []string `json:"members"`
	TimeoutMS         int      `json:"timeout_ms,omitempty"`
	MaxConcurrency    int      `json:"max_concurrency,omitempty"`
	PublicAnswersOnly bool     `json:"public_answers_only,omitempty"`
}

func Register(registry *dns.TransportRegistry) { dns.RegisterTransport[Options](registry, Type, New) }

type Transport struct {
	dns.TransportAdapter
	ctx     context.Context
	cancel  context.CancelFunc
	manager adapter.DNSTransportManager
	options Options
	mu      sync.Mutex
	members []adapter.DNSTransport
	closed  bool
	wg      sync.WaitGroup
	slots   chan struct{}
}

func New(ctx context.Context, _ log.ContextLogger, tag string, options Options) (adapter.DNSTransport, error) {
	if len(options.Members) < 1 || len(options.Members) > 2 {
		return nil, errors.New("DNS group requires one or two members")
	}
	seen := map[string]bool{}
	for _, member := range options.Members {
		if member == "" || member == tag || seen[member] {
			return nil, errors.New("DNS group contains an empty, duplicate or self member")
		}
		seen[member] = true
	}
	if options.TimeoutMS == 0 {
		options.TimeoutMS = 5000
	}
	if options.TimeoutMS < 10 || options.TimeoutMS > 30000 {
		return nil, errors.New("DNS group timeout_ms must be 10..30000")
	}
	if options.MaxConcurrency == 0 {
		options.MaxConcurrency = 128
	}
	if options.MaxConcurrency < 1 || options.MaxConcurrency > 1024 {
		return nil, errors.New("DNS group max_concurrency must be 1..1024")
	}
	ctx, cancel := context.WithCancel(ctx)
	return &Transport{TransportAdapter: dns.NewTransportAdapter(Type, tag, append([]string(nil), options.Members...)), ctx: ctx, cancel: cancel, manager: service.FromContext[adapter.DNSTransportManager](ctx), options: options, slots: make(chan struct{}, options.MaxConcurrency)}, nil
}

func (t *Transport) Start(stage adapter.StartStage) error {
	if stage != adapter.StartStateStart {
		return nil
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.closed {
		return errors.New("DNS group is closed")
	}
	if t.manager == nil {
		return errors.New("DNS transport manager is unavailable")
	}
	members := make([]adapter.DNSTransport, 0, len(t.options.Members))
	for _, tag := range t.options.Members {
		member, ok := t.manager.Transport(tag)
		if !ok {
			return fmt.Errorf("DNS group member %q not found", tag)
		}
		if member.Type() == Type {
			return errors.New("nested DNS groups are not supported")
		}
		members = append(members, member)
	}
	t.members = members
	return nil
}

func (t *Transport) Close() error {
	t.mu.Lock()
	t.closed = true
	t.cancel()
	t.mu.Unlock()
	t.wg.Wait()
	return nil
}

// The manager owns member lifecycle and resets each transport on network changes.
func (t *Transport) Reset() {}

func (t *Transport) Environment() []string {
	t.mu.Lock()
	members := append([]adapter.DNSTransport(nil), t.members...)
	t.mu.Unlock()
	var result []string
	for _, member := range members {
		if environment, ok := member.(adapter.DNSTransportWithEnvironment); ok {
			for _, value := range environment.Environment() {
				result = append(result, member.Tag()+":"+value)
			}
		}
	}
	return result
}

func (t *Transport) acquire() ([]adapter.DNSTransport, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.closed || len(t.members) == 0 {
		return nil, errors.New("DNS group is not active")
	}
	select {
	case t.slots <- struct{}{}:
	default:
		return nil, errors.New("DNS group concurrency limit reached")
	}
	t.wg.Add(1)
	return t.members, nil
}

func (t *Transport) Exchange(ctx context.Context, message *mDNS.Msg) (*mDNS.Msg, error) {
	members, err := t.acquire()
	if err != nil {
		return nil, err
	}
	return t.exchange(ctx, message, members)
}

func (t *Transport) ExchangeAsync(ctx context.Context, message *mDNS.Msg, callback func(*mDNS.Msg, error)) {
	members, err := t.acquire()
	if err != nil {
		callback(nil, err)
		return
	}
	request := message.Copy()
	go func() { response, err := t.exchange(ctx, request, members); callback(response, err) }()
}

func (t *Transport) exchange(ctx context.Context, message *mDNS.Msg, members []adapter.DNSTransport) (*mDNS.Msg, error) {
	defer func() { <-t.slots; t.wg.Done() }()
	ctx, cancel := context.WithTimeout(ctx, time.Duration(t.options.TimeoutMS)*time.Millisecond)
	defer cancel()
	stop := context.AfterFunc(t.ctx, cancel)
	defer stop()
	deadline, _ := ctx.Deadline()
	var last error
	for i, member := range members {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		attempt, cancelAttempt := context.WithTimeout(ctx, time.Until(deadline)/time.Duration(len(members)-i))
		response, err := member.Exchange(attempt, message.Copy())
		cancelAttempt()
		if err == nil && response != nil {
			if response.Rcode != mDNS.RcodeServerFailure && response.Rcode != mDNS.RcodeRefused {
				if t.options.PublicAnswersOnly {
					if err := validatePublicAnswers(response); err != nil {
						return nil, err
					}
				}
				return response, nil
			}
			err = fmt.Errorf("DNS member returned %s", mDNS.RcodeToString[response.Rcode])
		}
		if err == nil {
			err = errors.New("DNS member returned no response")
		}
		var hostname x509.HostnameError
		var authority x509.UnknownAuthorityError
		var invalid x509.CertificateInvalidError
		var verify *tls.CertificateVerificationError
		if errors.As(err, &hostname) || errors.As(err, &authority) || errors.As(err, &invalid) || errors.As(err, &verify) {
			return nil, err
		}
		last = err
	}
	return nil, fmt.Errorf("DNS group exhausted its configured members: %w", last)
}

func validatePublicAnswers(message *mDNS.Msg) error {
	for _, section := range [][]mDNS.RR{message.Answer, message.Extra} {
		for _, record := range section {
			var address netip.Addr
			switch record := record.(type) {
			case *mDNS.A:
				address, _ = netip.AddrFromSlice(record.A)
			case *mDNS.AAAA:
				address, _ = netip.AddrFromSlice(record.AAAA)
			default:
				continue
			}
			address = address.Unmap()
			if !restrictedtarget.Public(address) {
				return errors.New("restricted SSH DNS answer is not public")
			}
		}
	}
	return nil
}
