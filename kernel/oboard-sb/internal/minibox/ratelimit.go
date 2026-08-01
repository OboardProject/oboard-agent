package minibox

import (
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/bufio"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/common/ntp"
	"github.com/sagernet/sing/service"
	"golang.org/x/time/rate"
)

const rateLimitIOChunk = 64 * 1024

type RateLimitTracker struct {
	mu                sync.RWMutex
	states            map[string]*runtimeState
	active            map[string]map[*trackedConn]struct{}
	activePacket      map[string]map[*trackedPacketConn]struct{}
	auditMu           sync.Mutex
	auditBuckets      map[string]*ConnectionAuditBucket
	auditActiveByUser map[int64]int64
	auditGeneration   uint64
	auditDropped      int64
	auditWindowStart  time.Time
	auditEnabled      atomic.Bool
	trustedMu         sync.RWMutex
	trustedSources    map[string]netip.Addr
	trustedInbounds   []string
	activeTCP         atomic.Int64
	socketGovernor    *SocketBufferGovernor
	now               func() time.Time
}

func (t *RateLimitTracker) timeNow() time.Time {
	if t != nil && t.now != nil {
		return t.now()
	}
	return time.Now()
}

func (t *RateLimitTracker) SetSocketGovernor(governor *SocketBufferGovernor) {
	if t != nil {
		t.socketGovernor = governor
	}
}

type runtimeState struct {
	key      string
	user     string
	inbound  string
	config   atomic.Pointer[runtimeConfig]
	periodMu sync.Mutex
	usage    *runtimeUserUsage
	now      func() time.Time
}

type runtimeConfig struct {
	policy       RuntimeUserLimit
	readLimiter  *rate.Limiter
	writeLimiter *rate.Limiter
	counters     *runtimeCounters
}

type runtimeCounters struct {
	upload               atomic.Int64
	download             atomic.Int64
	acknowledgedUpload   atomic.Int64
	acknowledgedDownload atomic.Int64
}

type runtimeUserUsage struct {
	mu      sync.Mutex
	periods map[string]*runtimeUsagePeriod
}

type runtimeUsagePeriod struct {
	upload               atomic.Int64
	download             atomic.Int64
	acknowledgedUpload   atomic.Int64
	acknowledgedDownload atomic.Int64
}

type TrafficCounter struct {
	Key       string `json:"key"`
	User      string `json:"user"`
	Inbound   string `json:"inbound"`
	UserID    int64  `json:"user_id"`
	InboundID int64  `json:"inbound_id,omitempty"`
	PathID    int64  `json:"path_id,omitempty"`
	PeriodKey string `json:"period_key,omitempty"`
	Upload    int64  `json:"upload_bytes"`
	Download  int64  `json:"download_bytes"`
}

type TrafficCounterAcknowledgement struct {
	PeriodKey string `json:"period_key"`
	Upload    int64  `json:"upload_bytes"`
	Download  int64  `json:"download_bytes"`
}

func NewRateLimitTracker(metadata RuntimeMetadata) *RateLimitTracker {
	return newRateLimitTracker(metadata, time.Now)
}

func newRateLimitTracker(metadata RuntimeMetadata, now func() time.Time) *RateLimitTracker {
	if now == nil {
		now = time.Now
	}
	tracker := &RateLimitTracker{states: map[string]*runtimeState{}, active: map[string]map[*trackedConn]struct{}{}, activePacket: map[string]map[*trackedPacketConn]struct{}{}, now: now}
	auditEnabled := metadata.ConnectionAudit != nil && metadata.ConnectionAudit.Enabled
	tracker.auditEnabled.Store(auditEnabled)
	if auditEnabled {
		tracker.auditWindowStart = now().UTC()
	}
	if metadata.TrustedForward != nil {
		for _, receiver := range metadata.TrustedForward.Receivers {
			tracker.trustedInbounds = append(tracker.trustedInbounds, receiver.InboundTag)
		}
	}
	usageByUser := map[int64]*runtimeUserUsage{}
	usageFor := func(userID int64) *runtimeUserUsage {
		if userID <= 0 {
			return nil
		}
		usage := usageByUser[userID]
		if usage == nil {
			usage = &runtimeUserUsage{periods: map[string]*runtimeUsagePeriod{}}
			usageByUser[userID] = usage
		}
		return usage
	}
	for user, limit := range metadata.RateLimits.Users {
		if user == "" {
			continue
		}
		if !limit.Billable && limit.UserID > 0 {
			limit.Billable = true
		}
		key := "user:" + user
		state := newRuntimeStateWithClock(key, user, "", limit, now)
		state.usage = usageFor(limit.UserID)
		tracker.states[key] = state
	}
	for inbound, limit := range metadata.RateLimits.Inbounds {
		if inbound == "" {
			continue
		}
		key := "inbound:" + inbound
		state := newRuntimeStateWithClock(key, "", inbound, limit, now)
		state.usage = usageFor(limit.UserID)
		tracker.states[key] = state
	}
	return tracker
}

func (t *RateLimitTracker) SetConnectionAuditEnabled(enabled bool) {
	if t == nil {
		return
	}
	wasEnabled := t.auditEnabled.Swap(enabled)
	if enabled {
		if !wasEnabled {
			t.auditMu.Lock()
			t.auditWindowStart = t.timeNow().UTC()
			t.auditDropped = 0
			t.auditMu.Unlock()
		}
		return
	}
	t.auditMu.Lock()
	t.auditBuckets = nil
	t.auditActiveByUser = nil
	t.auditGeneration++
	t.auditDropped = 0
	t.auditWindowStart = time.Time{}
	t.auditMu.Unlock()
	t.trustedMu.Lock()
	t.trustedSources = nil
	t.trustedMu.Unlock()
}

func (t *RateLimitTracker) RegisterTrustedSource(local net.Addr, source netip.Addr) {
	if t == nil || local == nil || !source.IsValid() || !t.auditEnabled.Load() {
		return
	}
	t.trustedMu.Lock()
	if t.trustedSources == nil {
		t.trustedSources = make(map[string]netip.Addr)
	}
	t.trustedSources[local.String()] = source.Unmap()
	t.trustedMu.Unlock()
}

func (t *RateLimitTracker) RemoveTrustedSource(local net.Addr) {
	if t == nil || local == nil {
		return
	}
	t.trustedMu.Lock()
	delete(t.trustedSources, local.String())
	t.trustedMu.Unlock()
}

func (t *RateLimitTracker) trustedAuditSource(metadata adapter.InboundContext) (netip.Addr, bool, bool) {
	trustedInbound := false
	for _, tag := range t.trustedInbounds {
		if metadata.Inbound == tag {
			trustedInbound = true
			break
		}
	}
	if !trustedInbound {
		return metadata.Source.Addr.Unmap(), false, metadata.Source.Addr.IsValid()
	}
	t.trustedMu.RLock()
	source, ok := t.trustedSources[metadata.Source.String()]
	t.trustedMu.RUnlock()
	return source, true, ok && source.IsValid()
}

func (t *RateLimitTracker) ConnectionAuditEnabled() bool {
	return t != nil && t.auditEnabled.Load()
}

func newRuntimeState(key, user, inbound string, policy RuntimeUserLimit) *runtimeState {
	return newRuntimeStateWithClock(key, user, inbound, policy, time.Now)
}

func newRuntimeStateWithClock(key, user, inbound string, policy RuntimeUserLimit, now func() time.Time) *runtimeState {
	if now == nil {
		now = time.Now
	}
	state := &runtimeState{key: key, user: user, inbound: inbound, now: now}
	state.storePolicyLocked(policy, true)
	return state
}

func (s *runtimeState) storePolicyLocked(policy RuntimeUserLimit, resetTraffic bool) *runtimeConfig {
	counters := &runtimeCounters{}
	if current := s.config.Load(); !resetTraffic && current != nil && current.counters != nil {
		counters = current.counters
	}
	readLimiter, writeLimiter := newRuntimeLimiters(policy)
	next := &runtimeConfig{policy: policy, readLimiter: readLimiter, writeLimiter: writeLimiter, counters: counters}
	s.config.Store(next)
	return next
}

func (s *runtimeState) currentConfig() *runtimeConfig {
	config := s.loadedConfig()
	if config.policy.PeriodEnd == "" {
		return config
	}
	end, err := time.Parse(time.RFC3339Nano, config.policy.PeriodEnd)
	if err != nil || s.now().Before(end) {
		return config
	}

	s.periodMu.Lock()
	defer s.periodMu.Unlock()
	config = s.loadedConfig()
	policy := config.policy
	end, err = time.Parse(time.RFC3339Nano, policy.PeriodEnd)
	if err != nil || s.now().Before(end) {
		return config
	}
	loc := time.FixedZone("Asia/Shanghai", 8*3600)
	if policy.Timezone != "" {
		if loaded, loadErr := time.LoadLocation(policy.Timezone); loadErr == nil {
			loc = loaded
		}
	}
	periodKey, start, nextEnd := runtimeTrafficWindow(s.now(), policy.ResetMode, policy.ResetDay, loc)
	policy.PeriodKey = periodKey
	policy.PeriodStart = start.UTC().Format(time.RFC3339Nano)
	policy.PeriodEnd = nextEnd.UTC().Format(time.RFC3339Nano)
	policy.UsedBaselineBytes = 0
	if policy.LeaseEnforced {
		policy.LeaseBytes = policy.ResetLeaseBytes
	}
	policy.QuotaState = "active"
	return s.storePolicyLocked(policy, true)
}

func (s *runtimeState) loadedConfig() *runtimeConfig {
	if s != nil {
		if config := s.config.Load(); config != nil {
			return config
		}
	}
	return &runtimeConfig{counters: &runtimeCounters{}}
}

func (s *runtimeState) currentPolicy() RuntimeUserLimit {
	return s.currentConfig().policy
}

func (s *runtimeState) loadedPolicy() RuntimeUserLimit {
	if s == nil {
		return RuntimeUserLimit{}
	}
	return s.loadedConfig().policy
}

func (s *runtimeState) currentLimiter() *rate.Limiter {
	if s == nil {
		return nil
	}
	return s.currentConfig().readLimiter
}

func (s *runtimeState) currentReadLimiter() *rate.Limiter {
	if s == nil {
		return nil
	}
	return s.currentConfig().readLimiter
}

func (s *runtimeState) currentWriteLimiter() *rate.Limiter {
	if s == nil {
		return nil
	}
	return s.currentConfig().writeLimiter
}

func (s *runtimeState) addTraffic(upload, download int64) {
	config := s.currentConfig()
	policy := config.policy
	if !policy.Billable || policy.UserID <= 0 {
		return
	}
	if upload > 0 {
		config.counters.upload.Add(upload)
	}
	if download > 0 {
		config.counters.download.Add(download)
	}
	if s.usage != nil {
		period := s.usage.period(policy.PeriodKey)
		if upload > 0 {
			period.upload.Add(upload)
		}
		if download > 0 {
			period.download.Add(download)
		}
	}
}

func (s *runtimeState) denied() bool {
	config := s.currentConfig()
	return runtimeConfigDenied(config, s.unacknowledged(config))
}

func (s *runtimeState) deniedForConnection(admitted bool) bool {
	config := s.currentConfig()
	if !runtimeConfigDenied(config, s.unacknowledged(config)) {
		return false
	}
	return config.policy.EnforcementMode != "reject_new" || !admitted
}

func runtimeConfigDenied(config *runtimeConfig, unacknowledged int64) bool {
	policy := config.policy
	if !policy.Billable || policy.UserID <= 0 {
		return false
	}
	if policy.QuotaState == "quota_exceeded" {
		return true
	}
	if policy.TrafficLimitBytes <= 0 {
		return false
	}
	used := policy.UsedBaselineBytes + unacknowledged
	capBytes := policy.TrafficLimitBytes
	if policy.LeaseEnforced && policy.UsedBaselineBytes+policy.LeaseBytes < capBytes {
		capBytes = policy.UsedBaselineBytes + policy.LeaseBytes
	}
	return used >= capBytes
}

func (s *runtimeState) unacknowledged(config *runtimeConfig) int64 {
	if config == nil || config.counters == nil {
		return 0
	}
	if s.usage != nil {
		return s.usage.period(config.policy.PeriodKey).unacknowledged()
	}
	return runtimePositiveDifference(config.counters.upload.Load(), config.counters.acknowledgedUpload.Load()) + runtimePositiveDifference(config.counters.download.Load(), config.counters.acknowledgedDownload.Load())
}

func (s *runtimeState) acknowledge(checkpoint TrafficCounterAcknowledgement) {
	if s == nil || checkpoint.PeriodKey == "" {
		return
	}
	s.periodMu.Lock()
	defer s.periodMu.Unlock()
	config := s.loadedConfig()
	if config.policy.PeriodKey != checkpoint.PeriodKey || config.counters == nil {
		return
	}
	upload := runtimeMinInt64(checkpoint.Upload, config.counters.upload.Load())
	download := runtimeMinInt64(checkpoint.Download, config.counters.download.Load())
	if upload < 0 {
		upload = 0
	}
	if download < 0 {
		download = 0
	}
	previousUpload := config.counters.acknowledgedUpload.Load()
	previousDownload := config.counters.acknowledgedDownload.Load()
	if upload < previousUpload {
		upload = previousUpload
	}
	if download < previousDownload {
		download = previousDownload
	}
	config.counters.acknowledgedUpload.Store(upload)
	config.counters.acknowledgedDownload.Store(download)
	if s.usage != nil {
		period := s.usage.period(checkpoint.PeriodKey)
		period.acknowledgedUpload.Add(upload - previousUpload)
		period.acknowledgedDownload.Add(download - previousDownload)
	}
}

func (u *runtimeUserUsage) period(periodKey string) *runtimeUsagePeriod {
	u.mu.Lock()
	defer u.mu.Unlock()
	if u.periods == nil {
		u.periods = map[string]*runtimeUsagePeriod{}
	}
	period := u.periods[periodKey]
	if period == nil {
		period = &runtimeUsagePeriod{}
		u.periods[periodKey] = period
	}
	return period
}

func (p *runtimeUsagePeriod) unacknowledged() int64 {
	return runtimePositiveDifference(p.upload.Load(), p.acknowledgedUpload.Load()) + runtimePositiveDifference(p.download.Load(), p.acknowledgedDownload.Load())
}

func runtimePositiveDifference(total, acknowledged int64) int64 {
	if total <= acknowledged {
		return 0
	}
	return total - acknowledged
}

func runtimeMinInt64(left, right int64) int64 {
	if left < right {
		return left
	}
	return right
}

func (s *runtimeState) updatePolicy(policy RuntimeUserLimit) {
	s.periodMu.Lock()
	defer s.periodMu.Unlock()
	current := s.loadedPolicy()
	reset := current.PeriodKey != "" && policy.PeriodKey != "" && current.PeriodKey != policy.PeriodKey
	s.storePolicyLocked(policy, reset)
}

func (s *runtimeState) snapshot() (TrafficCounter, bool) {
	config := s.currentConfig()
	upload := config.counters.upload.Load()
	download := config.counters.download.Load()
	if upload == 0 && download == 0 {
		return TrafficCounter{}, false
	}
	policy := config.policy
	return TrafficCounter{Key: s.key, User: s.user, Inbound: s.inbound, UserID: policy.UserID, InboundID: policy.InboundID, PathID: policy.PathID, PeriodKey: policy.PeriodKey, Upload: upload, Download: download}, true
}

func (t *RateLimitTracker) Enabled() bool {
	return t != nil && len(t.states) > 0
}

func (t *RateLimitTracker) stateForKey(key string) *runtimeState {
	if t == nil || key == "" {
		return nil
	}
	t.mu.RLock()
	state := t.states[key]
	t.mu.RUnlock()
	return state
}

func (t *RateLimitTracker) LimiterForUser(user string) *rate.Limiter {
	state := t.stateForKey("user:" + user)
	if state == nil {
		return nil
	}
	return state.currentLimiter()
}

func (t *RateLimitTracker) RoutedConnection(ctx context.Context, conn net.Conn, metadata adapter.InboundContext, _ adapter.Rule, outbound adapter.Outbound) net.Conn {
	state := t.runtimeFor(metadata)
	if state == nil {
		return conn
	}
	config := state.currentConfig()
	if config.readLimiter == nil && config.writeLimiter == nil && !config.policy.Billable {
		return conn
	}
	tracked := &trackedConn{ExtendedConn: bufio.NewExtendedConn(conn), ctx: ctx, tracker: t, state: state, admitted: !state.denied(), auditKey: t.recordConnectionStart(state, metadata, outbound, "tcp")}
	t.registerConn(state.key, tracked)
	if tracked.deny() {
		_ = tracked.Close()
	}
	if config.readLimiter == nil && config.writeLimiter == nil {
		return &trackedCounterConn{trackedConn: tracked}
	}
	return tracked
}

func (t *RateLimitTracker) RoutedPacketConnection(ctx context.Context, conn N.PacketConn, metadata adapter.InboundContext, _ adapter.Rule, outbound adapter.Outbound) N.PacketConn {
	state := t.runtimeFor(metadata)
	if state == nil {
		return conn
	}
	config := state.currentConfig()
	if config.readLimiter == nil && config.writeLimiter == nil && !config.policy.Billable {
		return conn
	}
	tracked := &trackedPacketConn{PacketConn: conn, ctx: ctx, tracker: t, state: state, admitted: !state.denied(), auditKey: t.recordConnectionStart(state, metadata, outbound, "udp")}
	t.registerPacketConn(state.key, tracked)
	if tracked.deny() {
		_ = tracked.Close()
	}
	return tracked
}

func (t *RateLimitTracker) runtimeFor(metadata adapter.InboundContext) *runtimeState {
	if metadata.User != "" {
		if state := t.stateForKey("user:" + metadata.User); state != nil {
			return state
		}
	}
	if metadata.Inbound != "" {
		return t.stateForKey("inbound:" + metadata.Inbound)
	}
	return nil
}

func newRuntimeLimiters(limit RuntimeUserLimit) (*rate.Limiter, *rate.Limiter) {
	if limit.SpeedLimitMbps <= 0 {
		return nil, nil
	}
	bytesPerSecond := limit.SpeedLimitMbps * 1_000_000 / 8
	if bytesPerSecond <= 0 {
		return nil, nil
	}
	burst := bytesPerSecond / 5
	if burst < rateLimitIOChunk {
		burst = rateLimitIOChunk
	}
	return rate.NewLimiter(rate.Limit(bytesPerSecond), burst), rate.NewLimiter(rate.Limit(bytesPerSecond), burst)
}

func AttachRuntimeTrackers(ctx context.Context, metadata RuntimeMetadata) *RateLimitTracker {
	tracker := newRateLimitTracker(metadata, ntp.TimeFuncFromContext(ctx))
	if !tracker.Enabled() {
		return tracker
	}
	router := service.FromContext[adapter.Router](ctx)
	if router != nil {
		router.AppendTracker(tracker)
	}
	return tracker
}

type trackedConn struct {
	N.ExtendedConn
	ctx      context.Context
	tracker  *RateLimitTracker
	state    *runtimeState
	admitted bool
	auditKey string
	closed   atomic.Bool
}

func (c *trackedConn) Read(p []byte) (int, error) {
	if c.deny() {
		return 0, errors.New("oboard traffic quota exceeded")
	}
	readBuffer := p
	if c.state.currentReadLimiter() != nil && len(readBuffer) > rateLimitIOChunk {
		readBuffer = readBuffer[:rateLimitIOChunk]
	}
	n, err := c.ExtendedConn.Read(readBuffer)
	if n > 0 {
		if waitErr := waitBytes(c.ctx, c.state.currentReadLimiter(), n); waitErr != nil && err == nil {
			err = waitErr
		}
		c.state.addTraffic(int64(n), 0)
		if c.deny() {
			_ = c.Close()
		}
	}
	return n, err
}

func (c *trackedConn) Write(p []byte) (int, error) {
	if c.deny() {
		return 0, errors.New("oboard traffic quota exceeded")
	}
	limiter := c.state.currentWriteLimiter()
	if limiter == nil {
		n, err := c.ExtendedConn.Write(p)
		if n > 0 {
			c.state.addTraffic(0, int64(n))
			if c.deny() {
				_ = c.Close()
			}
		}
		return n, err
	}
	total := 0
	for total < len(p) {
		end := total + rateLimitIOChunk
		if end > len(p) {
			end = len(p)
		}
		chunkSize := end - total
		if err := waitBytes(c.ctx, limiter, chunkSize); err != nil {
			return total, err
		}
		n, err := c.ExtendedConn.Write(p[total:end])
		total += n
		if n > 0 {
			c.state.addTraffic(0, int64(n))
		}
		if err != nil {
			return total, err
		}
		if n != chunkSize {
			return total, io.ErrShortWrite
		}
	}
	if c.deny() {
		_ = c.Close()
	}
	return total, nil
}

func (c *trackedConn) ReadBuffer(buffer *buf.Buffer) error {
	if c.deny() {
		return errors.New("oboard traffic quota exceeded")
	}
	before := 0
	if buffer != nil {
		before = buffer.Len()
	}
	err := c.ExtendedConn.ReadBuffer(buffer)
	read := 0
	if buffer != nil && buffer.Len() > before {
		read = buffer.Len() - before
	}
	if read > 0 {
		if waitErr := waitBytes(c.ctx, c.state.currentReadLimiter(), read); waitErr != nil && err == nil {
			return waitErr
		}
		c.state.addTraffic(int64(read), 0)
		if c.deny() {
			_ = c.Close()
		}
	}
	return err
}

func (c *trackedConn) WriteBuffer(buffer *buf.Buffer) error {
	if c.deny() {
		return errors.New("oboard traffic quota exceeded")
	}
	if buffer == nil {
		return nil
	}
	if buffer.Len() == 0 {
		return c.ExtendedConn.WriteBuffer(buffer)
	}
	limiter := c.state.currentWriteLimiter()
	if limiter == nil {
		before := buffer.Len()
		err := c.ExtendedConn.WriteBuffer(buffer)
		written := before - buffer.Len()
		if written > 0 {
			c.state.addTraffic(0, int64(written))
			if c.deny() {
				_ = c.Close()
			}
		}
		return err
	}
	for buffer.Len() > rateLimitIOChunk {
		if err := waitBytes(c.ctx, limiter, rateLimitIOChunk); err != nil {
			return err
		}
		n, err := c.ExtendedConn.Write(buffer.To(rateLimitIOChunk))
		if n > 0 {
			c.state.addTraffic(0, int64(n))
			buffer.Advance(n)
		}
		if err != nil {
			return err
		}
		if n != rateLimitIOChunk {
			return io.ErrShortWrite
		}
	}
	size := buffer.Len()
	if err := waitBytes(c.ctx, limiter, size); err != nil {
		return err
	}
	err := c.ExtendedConn.WriteBuffer(buffer)
	written := size - buffer.Len()
	if written > 0 {
		c.state.addTraffic(0, int64(written))
	}
	if c.deny() {
		_ = c.Close()
	}
	return err
}

func (c *trackedConn) Upstream() any { return c.ExtendedConn }

func (c *trackedConn) Close() error {
	if c.closed.CompareAndSwap(false, true) && c.tracker != nil && c.state != nil {
		c.tracker.recordConnectionEnd(c.auditKey)
		c.tracker.unregisterConn(c.state.key, c)
	}
	return c.ExtendedConn.Close()
}

func (c *trackedConn) deny() bool {
	return c.state != nil && c.state.deniedForConnection(c.admitted)
}

// trackedCounterConn lets sing's copy engine unwrap traffic accounting into
// callbacks. Unrestricted users can then keep the official direct-copy/splice
// path instead of forcing every payload through Go buffers.
type trackedCounterConn struct {
	*trackedConn
}

func (c *trackedCounterConn) UnwrapReader() (io.Reader, []N.CountFunc) {
	return c.ExtendedConn, []N.CountFunc{c.countUpload}
}

func (c *trackedCounterConn) UnwrapWriter() (io.Writer, []N.CountFunc) {
	return c.ExtendedConn, []N.CountFunc{c.countDownload}
}

func (c *trackedCounterConn) countUpload(n int64) {
	if n <= 0 || c.state == nil {
		return
	}
	c.state.addTraffic(n, 0)
	if c.deny() {
		_ = c.Close()
	}
}

func (c *trackedCounterConn) countDownload(n int64) {
	if n <= 0 || c.state == nil {
		return
	}
	c.state.addTraffic(0, n)
	if c.deny() {
		_ = c.Close()
	}
}

type trackedPacketConn struct {
	N.PacketConn
	ctx      context.Context
	tracker  *RateLimitTracker
	state    *runtimeState
	admitted bool
	auditKey string
	closed   atomic.Bool
}

func (c *trackedPacketConn) ReadPacket(buffer *buf.Buffer) (destination M.Socksaddr, err error) {
	if c.deny() {
		return destination, errors.New("oboard traffic quota exceeded")
	}
	destination, err = c.PacketConn.ReadPacket(buffer)
	if err == nil && buffer != nil && buffer.Len() > 0 {
		if limiter := c.state.currentReadLimiter(); limiter != nil && !limiter.AllowN(time.Now(), buffer.Len()) {
			buffer.Reset()
			return destination, nil
		}
		c.state.addTraffic(int64(buffer.Len()), 0)
		if c.deny() {
			_ = c.Close()
		}
	}
	return destination, err
}

func (c *trackedPacketConn) WritePacket(buffer *buf.Buffer, destination M.Socksaddr) error {
	if c.deny() {
		return errors.New("oboard traffic quota exceeded")
	}
	size := 0
	if buffer != nil {
		size = buffer.Len()
	}
	if size > 0 {
		if limiter := c.state.currentWriteLimiter(); limiter != nil && !limiter.AllowN(time.Now(), size) {
			return nil
		}
	}
	if err := c.PacketConn.WritePacket(buffer, destination); err != nil {
		return err
	}
	if size > 0 {
		c.state.addTraffic(0, int64(size))
		if c.deny() {
			_ = c.Close()
		}
	}
	return nil
}

func (c *trackedPacketConn) Close() error {
	if c.closed.CompareAndSwap(false, true) && c.tracker != nil && c.state != nil {
		c.tracker.recordConnectionEnd(c.auditKey)
		c.tracker.unregisterPacketConn(c.state.key, c)
	}
	return c.PacketConn.Close()
}

func (c *trackedPacketConn) deny() bool {
	return c.state != nil && c.state.deniedForConnection(c.admitted)
}

func (c *trackedPacketConn) Upstream() any { return c.PacketConn }

var (
	_ N.ExtendedConn = (*trackedConn)(nil)
	_ N.ReadCounter  = (*trackedCounterConn)(nil)
	_ N.WriteCounter = (*trackedCounterConn)(nil)
	_ N.PacketConn   = (*trackedPacketConn)(nil)
)

func runtimeTrafficWindow(now time.Time, mode string, day int, loc *time.Location) (string, time.Time, time.Time) {
	n := now.In(loc)
	if day < 1 {
		day = 1
	}
	if day > 31 {
		day = 31
	}
	if mode != "month_day" {
		start := time.Date(n.Year(), n.Month(), 1, 0, 0, 0, 0, loc)
		return start.Format("2006-01-02"), start, start.AddDate(0, 1, 0)
	}
	start := time.Date(n.Year(), n.Month(), runtimeClampedMonthDay(n.Year(), n.Month(), day), 0, 0, 0, 0, loc)
	if n.Before(start) {
		prev := start.AddDate(0, -1, 0)
		start = time.Date(prev.Year(), prev.Month(), runtimeClampedMonthDay(prev.Year(), prev.Month(), day), 0, 0, 0, 0, loc)
	}
	next := start.AddDate(0, 1, 0)
	end := time.Date(next.Year(), next.Month(), runtimeClampedMonthDay(next.Year(), next.Month(), day), 0, 0, 0, 0, loc)
	return start.Format("2006-01-02"), start, end
}

func runtimeClampedMonthDay(year int, month time.Month, day int) int {
	last := time.Date(year, month+1, 0, 0, 0, 0, 0, time.UTC).Day()
	if day > last {
		return last
	}
	if day < 1 {
		return 1
	}
	return day
}

func (t *RateLimitTracker) Snapshot() []TrafficCounter {
	if t == nil {
		return nil
	}
	t.mu.RLock()
	states := make([]*runtimeState, 0, len(t.states))
	for _, state := range t.states {
		states = append(states, state)
	}
	t.mu.RUnlock()
	out := make([]TrafficCounter, 0, len(states))
	for _, state := range states {
		if counter, ok := state.snapshot(); ok {
			out = append(out, counter)
		}
	}
	return out
}

func (t *RateLimitTracker) UpdatePolicies(policies map[string]RuntimeUserLimit) {
	if t == nil || len(policies) == 0 {
		return
	}
	t.mu.RLock()
	states := make(map[string]*runtimeState, len(t.states))
	for key, state := range t.states {
		states[key] = state
	}
	t.mu.RUnlock()
	updates := map[*runtimeState]RuntimeUserLimit{}
	for key, policy := range policies {
		if state := states[key]; state != nil {
			updates[state] = policy
		}
		if policy.UserID <= 0 {
			continue
		}
		for _, state := range states {
			current := state.loadedPolicy()
			if current.UserID == policy.UserID {
				updates[state] = mergeRuntimePolicy(current, policy)
			}
		}
	}
	for state, policy := range updates {
		state.updatePolicy(policy)
		if policy.EnforcementMode != "reject_new" && state.denied() {
			t.closeActive(state.key)
		}
	}
}

func (t *RateLimitTracker) AcknowledgeTraffic(acknowledged map[string]TrafficCounterAcknowledgement) {
	if t == nil || len(acknowledged) == 0 {
		return
	}
	t.mu.RLock()
	states := make(map[string]*runtimeState, len(t.states))
	for key, state := range t.states {
		states[key] = state
	}
	t.mu.RUnlock()
	for key, checkpoint := range acknowledged {
		if state := states[key]; state != nil {
			state.acknowledge(checkpoint)
		}
	}
}

func mergeRuntimePolicy(current, update RuntimeUserLimit) RuntimeUserLimit {
	update.InboundID = current.InboundID
	update.PathID = current.PathID
	return update
}

func (t *RateLimitTracker) registerConn(key string, c *trackedConn) {
	if t == nil || key == "" || c == nil {
		return
	}
	t.mu.Lock()
	if t.active[key] == nil {
		t.active[key] = map[*trackedConn]struct{}{}
	}
	t.active[key][c] = struct{}{}
	t.mu.Unlock()
	active := t.activeTCP.Add(1)
	if t.socketGovernor != nil {
		t.socketGovernor.ObserveConnections(active)
	}
	policy := c.state.currentPolicy()
	if policy.EnforcementMode != "reject_new" && c.state.denied() {
		t.closeActive(key)
	}
}

func (t *RateLimitTracker) unregisterConn(key string, c *trackedConn) {
	t.mu.Lock()
	delete(t.active[key], c)
	if len(t.active[key]) == 0 {
		delete(t.active, key)
	}
	t.mu.Unlock()
	active := t.activeTCP.Add(-1)
	if active < 0 {
		t.activeTCP.Store(0)
		active = 0
	}
	if t.socketGovernor != nil {
		t.socketGovernor.ObserveConnections(active)
	}
}

func (t *RateLimitTracker) registerPacketConn(key string, c *trackedPacketConn) {
	if t == nil || key == "" || c == nil {
		return
	}
	t.mu.Lock()
	if t.activePacket[key] == nil {
		t.activePacket[key] = map[*trackedPacketConn]struct{}{}
	}
	t.activePacket[key][c] = struct{}{}
	t.mu.Unlock()
	policy := c.state.currentPolicy()
	if policy.EnforcementMode != "reject_new" && c.state.denied() {
		t.closeActive(key)
	}
}

func (t *RateLimitTracker) unregisterPacketConn(key string, c *trackedPacketConn) {
	t.mu.Lock()
	delete(t.activePacket[key], c)
	if len(t.activePacket[key]) == 0 {
		delete(t.activePacket, key)
	}
	t.mu.Unlock()
}

func (t *RateLimitTracker) closeActive(key string) {
	t.mu.RLock()
	conns := make([]*trackedConn, 0, len(t.active[key]))
	for conn := range t.active[key] {
		conns = append(conns, conn)
	}
	packets := make([]*trackedPacketConn, 0, len(t.activePacket[key]))
	for conn := range t.activePacket[key] {
		packets = append(packets, conn)
	}
	t.mu.RUnlock()
	for _, conn := range conns {
		_ = conn.Close()
	}
	for _, conn := range packets {
		_ = conn.Close()
	}
}

func waitBytes(ctx context.Context, limiter *rate.Limiter, n int) error {
	if limiter == nil || n <= 0 {
		return nil
	}
	burst := limiter.Burst()
	if burst <= 0 {
		burst = 1
	}
	for n > 0 {
		chunk := n
		if chunk > burst {
			chunk = burst
		}
		if err := limiter.WaitN(ctx, chunk); err != nil {
			return err
		}
		n -= chunk
	}
	return nil
}
