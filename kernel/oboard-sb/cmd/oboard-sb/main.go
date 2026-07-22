package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/OboardProject/oboard-agent/kernel/oboard-sb/internal/minibox"
	"github.com/OboardProject/oboard-agent/kernel/oboard-sb/internal/version"
	box "github.com/sagernet/sing-box"
	C "github.com/sagernet/sing-box/constant"
)

func main() {
	config := flag.String("config", "config.json", "sing-box config path")
	check := flag.Bool("check", false, "validate config and exit")
	api := flag.String("api", "", "optional local health API listen address; supports unix:/path.sock")
	resourceProfile := flag.String("resource-profile", "auto", "resource profile: auto, small, or large")
	gomaxprocs := flag.Int("gomaxprocs", 0, "runtime GOMAXPROCS override; 0 uses the resource profile")
	memoryLimit := flag.Int64("memory-limit-bytes", 0, "Go runtime memory target override; 0 uses the resource profile")
	hy2UpMbps := flag.Int("hy2-up-mbps", 0, "override Hysteria2 inbound advertised upload bandwidth in Mbps")
	hy2DownMbps := flag.Int("hy2-down-mbps", 0, "override Hysteria2 inbound advertised download bandwidth in Mbps")
	hy2IgnoreClientBandwidth := flag.Bool("hy2-ignore-client-bandwidth", false, "force Hysteria2 server bandwidth settings instead of client-advertised bandwidth")
	hy2BrutalDebug := flag.Bool("hy2-brutal-debug", false, "enable Hysteria2 brutal congestion debug logging")
	showVersion := flag.Bool("version", false, "print version and supported protocols")
	flag.Parse()

	if *showVersion {
		printVersion()
		return
	}

	runtimeTuning, err := minibox.ApplyRuntimeDefaults(*resourceProfile, *gomaxprocs, *memoryLimit)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("kernel resource profile=%s memory_class=%s virtualization=%s container=%t effective_memory=%d gomaxprocs=%d gogc=%d gomemlimit=%d", runtimeTuning.Profile, runtimeTuning.MemoryClass, runtimeTuning.Virtualization, runtimeTuning.Container, runtimeTuning.EffectiveMemoryBytes, runtime.GOMAXPROCS(0), runtimeTuning.GCPercent, runtimeTuning.MemoryLimitBytes)
	tuning := minibox.HY2Tuning{
		Enabled:               *hy2UpMbps > 0 || *hy2DownMbps > 0 || *hy2IgnoreClientBandwidth || *hy2BrutalDebug,
		UpMbps:                *hy2UpMbps,
		DownMbps:              *hy2DownMbps,
		IgnoreClientBandwidth: *hy2IgnoreClientBandwidth,
		BrutalDebug:           *hy2BrutalDebug,
	}
	opts, runtimeMetadata, err := minibox.LoadConfig(*config, tuning)
	if err != nil {
		log.Fatal(err)
	}
	if *check {
		checkCtx := minibox.Context(context.Background())
		instance, err := box.New(box.Options{Context: checkCtx, Options: opts})
		if err != nil {
			log.Fatal(err)
		}
		if err := instance.Close(); err != nil {
			log.Fatal(err)
		}
		fmt.Println("configuration is valid for oboard-sb")
		return
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	memoryReclaimer := minibox.StartMemoryReclaimer(ctx, runtimeTuning)
	boxCtx := minibox.Context(context.Background())
	b, err := box.New(box.Options{Context: boxCtx, Options: opts})
	if err != nil {
		log.Fatal(err)
	}
	tracker := minibox.AttachRuntimeTrackers(boxCtx, runtimeMetadata)
	socketGovernor := minibox.StartAdaptiveSocketGovernor(ctx, runtimeTuning)
	tracker.SetSocketGovernor(socketGovernor)
	if *api != "" {
		go func() {
			if err := serveHealth(ctx, *api, tracker, runtimeTuning, memoryReclaimer, socketGovernor); err != nil && ctx.Err() == nil {
				log.Println(err)
			}
		}()
	}
	if err := b.Start(); err != nil {
		log.Fatal(err)
	}
	<-ctx.Done()
	if err := b.Close(); err != nil {
		log.Println(err)
	}
}

func printVersion() {
	payload := map[string]any{
		"name":                "oboard-sb",
		"version":             version.Version,
		"build":               version.Build,
		"commit":              version.Commit,
		"built_at":            version.Date,
		"sing_box_version":    C.Version,
		"supported_protocols": minibox.SupportedProtocols,
	}
	data, _ := json.MarshalIndent(payload, "", "  ")
	fmt.Println(string(data))
}

func serveHealth(ctx context.Context, listen string, tracker *minibox.RateLimitTracker, tuning minibox.RuntimeTuning, memoryReclaimer *minibox.MemoryReclaimer, socketGovernor *minibox.SocketBufferGovernor) error {
	if err := validateLocalAPIListen(listen); err != nil {
		return err
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/health", func(w http.ResponseWriter, _ *http.Request) { _, _ = fmt.Fprintln(w, "ok") })
	mux.HandleFunc("/version", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"name": "oboard-sb", "version": version.Version, "build": version.Build, "commit": version.Commit, "built_at": version.Date, "sing_box_version": C.Version, "supported_protocols": minibox.SupportedProtocols, "resource_profile": tuning.Profile, "memory_class": tuning.MemoryClass, "virtualization": tuning.Virtualization, "container": tuning.Container, "effective_memory_bytes": tuning.EffectiveMemoryBytes, "gomaxprocs": runtime.GOMAXPROCS(0), "gc_percent": tuning.GCPercent, "memory_limit_bytes": tuning.MemoryLimitBytes, "memory_reclaimer": memoryReclaimer.Snapshot(), "socket_governor": socketGovernor.Snapshot()})
	})
	mux.HandleFunc("/resources", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"resource_profile": tuning.Profile, "memory_class": tuning.MemoryClass, "effective_memory_bytes": tuning.EffectiveMemoryBytes, "gomaxprocs": runtime.GOMAXPROCS(0), "gc_percent": tuning.GCPercent, "memory_limit_bytes": tuning.MemoryLimitBytes, "memory_reclaimer": memoryReclaimer.Snapshot(), "socket_governor": socketGovernor.Snapshot()})
	})
	mux.HandleFunc("/traffic/snapshot", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"items": tracker.Snapshot(), "time": time.Now().UTC().Format(time.RFC3339Nano)})
	})
	mux.HandleFunc("/connections/drain", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"items": tracker.DrainConnectionAudits(), "time": time.Now().UTC().Format(time.RFC3339Nano)})
	})
	mux.HandleFunc("/connections/config", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, 1024)
		var req struct {
			Enabled bool `json:"enabled"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		tracker.SetConnectionAuditEnabled(req.Enabled)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"ok": true, "enabled": tracker.ConnectionAuditEnabled()})
	})
	mux.HandleFunc("/traffic/policy", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
		var req struct {
			Policies     map[string]minibox.RuntimeUserLimit              `json:"policies"`
			Acknowledged map[string]minibox.TrafficCounterAcknowledgement `json:"acknowledged"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		// The Controller baseline already contains accepted reports. Advance the
		// local counter checkpoints first so a policy refresh cannot momentarily
		// double count and disconnect healthy sessions.
		tracker.AcknowledgeTraffic(req.Acknowledged)
		tracker.UpdatePolicies(req.Policies)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"ok": true})
	})

	var (
		ln         net.Listener
		err        error
		socketPath string
	)
	if strings.HasPrefix(listen, "unix:") {
		socketPath = strings.TrimPrefix(listen, "unix:")
		_ = os.Remove(socketPath)
		ln, err = net.Listen("unix", socketPath)
	} else {
		ln, err = net.Listen("tcp", listen)
	}
	if err != nil {
		return err
	}
	if socketPath != "" {
		defer os.Remove(socketPath)
		if err := os.Chmod(socketPath, 0o600); err != nil {
			_ = ln.Close()
			return err
		}
	}
	srv := &http.Server{Handler: mux, ReadHeaderTimeout: 3 * time.Second, ReadTimeout: 5 * time.Second, WriteTimeout: 10 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 16 << 10}
	// #nosec G118 -- serverCtx is the caller's lifecycle context; the fresh timeout is only for bounded shutdown after cancellation.
	go func(serverCtx context.Context) {
		<-serverCtx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdownCtx)
	}(ctx)
	return srv.Serve(ln)
}

func validateLocalAPIListen(listen string) error {
	if strings.HasPrefix(listen, "unix:") {
		if strings.TrimSpace(strings.TrimPrefix(listen, "unix:")) == "" {
			return fmt.Errorf("local API unix socket path is empty")
		}
		return nil
	}
	host, _, err := net.SplitHostPort(listen)
	if err != nil {
		return err
	}
	ip := net.ParseIP(host)
	if host != "localhost" && (ip == nil || !ip.IsLoopback()) {
		return fmt.Errorf("local API TCP address must be loopback, got %q", host)
	}
	return nil
}
