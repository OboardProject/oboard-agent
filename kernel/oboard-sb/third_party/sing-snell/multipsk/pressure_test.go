package multipsk_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	snell "github.com/sagernet/sing-snell"
	"github.com/sagernet/sing-snell/multipsk"
	"github.com/sagernet/sing-snell/snellv5"
	"github.com/sagernet/sing-snell/snellv6"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"io"
	"net"
	"os"
	"runtime"
	"sort"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type memoryConn struct {
	in  *bytes.Reader
	out bytes.Buffer
}

func (c *memoryConn) Read(b []byte) (int, error) {
	if c.in == nil {
		return 0, io.EOF
	}
	return c.in.Read(b)
}
func (c *memoryConn) Write(b []byte) (int, error)      { return c.out.Write(b) }
func (c *memoryConn) Close() error                     { return nil }
func (c *memoryConn) LocalAddr() net.Addr              { return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1} }
func (c *memoryConn) RemoteAddr() net.Addr             { return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 2} }
func (c *memoryConn) SetDeadline(time.Time) error      { return nil }
func (c *memoryConn) SetReadDeadline(time.Time) error  { return nil }
func (c *memoryConn) SetWriteDeadline(time.Time) error { return nil }

type pressureHandler struct{ admitted atomic.Int64 }

func (h *pressureHandler) NewConnectionEx(ctx context.Context, c net.Conn, src, dst M.Socksaddr, done N.CloseHandlerFunc) {
	h.admitted.Add(1)
	_, _ = io.Copy(io.Discard, c)
	c.Close()
	if done != nil {
		done(nil)
	}
}
func (h *pressureHandler) NewPacketConnectionEx(ctx context.Context, c N.PacketConn, src, dst M.Socksaddr, done N.CloseHandlerFunc) {
	c.Close()
	if done != nil {
		done(nil)
	}
}

func TestAuthenticationPressure(t *testing.T) {
	if os.Getenv("OBOARD_SNELL_STRESS") != "1" {
		t.Skip("set OBOARD_SNELL_STRESS=1 for measured pressure scenarios")
	}
	initialGoroutines := runtime.NumGoroutine()
	runtime.GC()
	var before runtime.MemStats
	runtime.ReadMemStats(&before)
	for _, version := range []int{4, 6} {
		modes := []snellv6.Mode{0}
		if version == 6 {
			modes = append(modes, snellv6.ModeUnshaped)
		}
		for _, mode := range modes {
			for _, count := range []int{1, 10, 50, 64} {
				for _, workload := range []string{"warm", "cold", "shared_nat", "wrong_keys", "update"} {
					t.Run(fmt.Sprintf("v%d_mode%d_n%d_%s", version, mode, count, workload), func(t *testing.T) {
						h := &pressureHandler{}
						var s multiService
						var metrics *multipsk.Metrics
						if version == 4 {
							p, e := snellv5.NewPSKService(snellv5.ServiceOptions{Handler: h}, t.Name(), nil)
							if e != nil {
								t.Fatal(e)
							}
							s, metrics = p, p.Metrics()
						} else {
							p, e := snellv6.NewPSKService(snellv6.ServerOptions{Handler: h, Mode: mode}, t.Name(), nil)
							if e != nil {
								t.Fatal(e)
							}
							s, metrics = p, p.Metrics()
						}
						users := make([]multipsk.User, count)
						for i := range users {
							users[i] = multipsk.User{Name: fmt.Sprintf("identity-%d", i), PSK: []byte(fmt.Sprintf("independent-pressure-credential-%04d", i))}
						}
						if e := s.UpdatePSKs(users); e != nil {
							t.Fatal(e)
						}
						const requests = 40
						latencies := make([]int64, requests)
						var wg sync.WaitGroup
						permits := make(chan struct{}, 8)
						start := time.Now()
						var memBefore runtime.MemStats
						runtime.ReadMemStats(&memBefore)
						for i := 0; i < requests; i++ {
							if i > 0 {
								time.Sleep(20 * time.Millisecond)
							}
							permits <- struct{}{}
							wg.Add(1)
							go func(i int) {
								defer wg.Done()
								defer func() { <-permits }()
								index := count - 1
								if workload == "shared_nat" {
									index = i % count
								}
								psk := string(users[index].PSK)
								if workload == "wrong_keys" {
									psk = "wrong-independent-key"
								}
								producer := &memoryConn{}
								c := method(t, version, mode, 0, psk, "").DialEarlyConn(producer, M.ParseSocksaddr("example.test:443"))
								if _, e := c.Write([]byte("payload")); e != nil {
									t.Error(e)
									return
								}
								source := M.ParseSocksaddr(fmt.Sprintf("192.0.2.%d:1234", i+1))
								if workload == "warm" || workload == "shared_nat" {
									source = M.ParseSocksaddr("192.0.2.1:1234")
								}
								begin := time.Now()
								_ = s.NewConnection(context.Background(), &memoryConn{in: bytes.NewReader(producer.out.Bytes())}, source, nil)
								latencies[i] = time.Since(begin).Nanoseconds()
							}(i)
							if workload == "update" {
								if e := s.UpdatePSKs(users); e != nil {
									t.Fatal(e)
								}
							}
						}
						wg.Wait()
						var memAfter runtime.MemStats
						runtime.ReadMemStats(&memAfter)
						sort.Slice(latencies, func(i, j int) bool { return latencies[i] < latencies[j] })
						result := map[string]any{"scenario": t.Name(), "requests": requests, "elapsed_ms": time.Since(start).Milliseconds(), "success": metrics.Success.Load(), "admitted": h.admitted.Load(), "failure": metrics.Failure.Load(), "timeout": metrics.Timeout.Load(), "budget_rejected": metrics.BudgetRejected.Load(), "attempts": metrics.Attempts.Load(), "cache_hits": metrics.CacheHit.Load(), "queue_ns": metrics.QueueNanos.Load(), "pending_end": metrics.Pending.Load(), "p50_us": latencies[requests/2] / 1000, "p95_us": latencies[requests*95/100] / 1000, "p99_us": latencies[requests-1] / 1000, "allocated_bytes": memAfter.TotalAlloc - memBefore.TotalAlloc, "allocations": memAfter.Mallocs - memBefore.Mallocs, "goroutines": runtime.NumGoroutine()}
						raw, _ := json.Marshal(result)
						t.Log(string(raw))
						if metrics.Pending.Load() != 0 {
							t.Fatal("handshake queue did not drain")
						}
						if workload == "wrong_keys" && h.admitted.Load() != 0 {
							t.Fatal("wrong key admitted")
						}
						if workload != "wrong_keys" && h.admitted.Load() == 0 {
							t.Fatal("all valid clients starved")
						}
					})
				}
			}
		}
	}
	runtime.GC()
	var after runtime.MemStats
	runtime.ReadMemStats(&after)
	t.Logf("resource_return baseline_goroutines=%d final_goroutines=%d baseline_heap=%d final_heap=%d", initialGoroutines, runtime.NumGoroutine(), before.HeapAlloc, after.HeapAlloc)
	if runtime.NumGoroutine() > initialGoroutines+8 {
		t.Fatal("goroutines did not return after pressure")
	}
}

var _ snell.Service = (multiService)(nil)
