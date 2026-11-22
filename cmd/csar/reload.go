package main

import (
	"fmt"
	"log/slog"
	"net/http"
	"sync"
	"sync/atomic"

	"github.com/ledatu/csar/internal/config"
	"github.com/ledatu/csar/internal/coordclient"
	"github.com/ledatu/csar/internal/proxy"
	"github.com/ledatu/csar/internal/router"
	"github.com/ledatu/csar/internal/telemetry"
	"github.com/ledatu/csar/internal/throttle"
)

// reloadableHandler wraps an http.Handler with an atomic pointer so it can be
// swapped at runtime (on SIGHUP) without dropping in-flight connections.
type reloadableHandler struct {
	handler atomic.Pointer[http.Handler]
}

// newReloadableHandler creates a reloadableHandler with the given initial handler.
func newReloadableHandler(h http.Handler) *reloadableHandler {
	rh := &reloadableHandler{}
	rh.handler.Store(&h)
	return rh
}

// ServeHTTP delegates to the current handler.
func (rh *reloadableHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	(*rh.handler.Load()).ServeHTTP(w, r)
}

// swap atomically replaces the current handler.
func (rh *reloadableHandler) swap(h http.Handler) {
	rh.handler.Store(&h)
}

// ---------------------------------------------------------------------------
// Startup summary log
// ---------------------------------------------------------------------------

// logStartupSummary prints a structured summary of the CSAR configuration at startup.
func logStartupSummary(logger *slog.Logger, cfg *config.Config, r *router.Router) {
	profile := cfg.Profile
	if profile == "" {
		profile = "(none)"
	}

	tlsStatus := "disabled"
	if cfg.TLS != nil {
		minVer := "TLS 1.2"
		if cfg.TLS.MinVersion == "1.3" {
			minVer = "TLS 1.3"
		}
		tlsStatus = fmt.Sprintf("enabled (%s)", minVer)
	}

	kmsProvider := "(none)"
	if cfg.KMS != nil && cfg.KMS.Provider != "" {
		kmsProvider = cfg.KMS.Provider
	}

	tokenSource := "file"
	if cfg.Coordinator.Enabled && cfg.Coordinator.Address != "" {
		tokenSource = "coordinator"
	}

	coordStatus := "disabled"
	if cfg.Coordinator.Enabled {
		transport := "plaintext"
		if cfg.Coordinator.CAFile != "" {
			transport = "mTLS"
		}
		coordStatus = fmt.Sprintf("enabled (grpc://%s, %s)", cfg.Coordinator.Address, transport)
	}

	totalRoutes := 0
	secureRoutes := 0
	throttledRoutes := 0
	for _, pathCfg := range cfg.Paths {
		for method := range pathCfg {
			routeCfg := pathCfg[method]
			totalRoutes++
			if len(routeCfg.Security) > 0 {
				secureRoutes++
			}
			if routeCfg.Traffic != nil {
				throttledRoutes++
			}
		}
	}

	_ = r // router reference for future use

	logger.Info("csar startup summary",
		"profile", profile,
		"listen", cfg.ListenAddr,
		"tls", tlsStatus,
		"kms_provider", kmsProvider,
		"token_source", tokenSource,
		"coordinator", coordStatus,
		"routes", fmt.Sprintf("%d (%d with security, %d with throttle)", totalRoutes, secureRoutes, throttledRoutes),
	)
}

// ---------------------------------------------------------------------------
// Config applier for coordinator-driven hot-reload
// ---------------------------------------------------------------------------

// routerReloader implements coordclient.ConfigApplier by rebuilding the router
// from a new config and atomically swapping the HTTP handler.
type routerReloader struct {
	mu                 sync.Mutex
	logger             *slog.Logger
	routerOpts         []router.Option
	reloadHandler      *reloadableHandler
	tp                 *telemetry.Provider
	sharedTM           *throttle.ThrottleManager
	currentRouter      *router.Router
	ssrfProtection     *proxy.SSRFProtection
	redisKeyPrefix     string
	restartSnapshot    config.RestartRequiredSnapshot
	originReceivers    bool
	policyCapabilities map[string]uint32
}

var _ coordclient.ConfigApplier = (*routerReloader)(nil)

// Apply handles coordinator snapshots. Legacy coordinators omit SSRF policy,
// so retain the last successfully applied policy in that case.
func (rl *routerReloader) Apply(cfg *config.Config) error {
	return rl.apply(cfg, true)
}

// Reload applies complete YAML configuration from SIGHUP or the source watcher.
// An omitted SSRF block resets to secure defaults rather than retaining grants.
func (rl *routerReloader) Reload(cfg *config.Config) error {
	return rl.apply(cfg, false)
}

func (rl *routerReloader) apply(cfg *config.Config, coordinatorSnapshot bool) error {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	if coordinatorSnapshot {
		if err := cfg.CheckPolicySnapshot(rl.policyCapabilities); err != nil {
			return err
		}
	}
	if coordinatorSnapshot && (cfg.OriginPolicyVersion > config.OriginPolicyVersion ||
		cfg.OriginPolicyVersion == 0 && (rl.originReceivers || cfg.HasOriginReceivers())) {
		return fmt.Errorf("coordinator snapshot cannot preserve active origin receiver policies")
	}

	for _, w := range cfg.Warnings {
		rl.logger.Warn("(reload) " + w)
	}
	if !coordinatorSnapshot {
		for _, field := range rl.restartSnapshot.Changes(cfg) {
			rl.logger.Warn("configuration field changed; router restart required", "field", field)
		}
	}

	// Old coordinators omit the Redis namespace. Preserve the last successful
	// prefix without changing the caller's config or copying connection secrets.
	prefix := rl.redisKeyPrefix
	if !coordinatorSnapshot || cfg.Redis != nil {
		prefix = ""
		if cfg.Redis != nil {
			prefix = cfg.Redis.KeyPrefix
		}
	}
	effective := *cfg
	if coordinatorSnapshot && cfg.Redis == nil {
		effective.Redis = &config.RedisConfig{KeyPrefix: prefix}
	}
	cfg = &effective

	ssrfP := buildSSRFProtection(cfg.SSRF)
	if coordinatorSnapshot && cfg.SSRF == nil && rl.ssrfProtection != nil {
		ssrfP = rl.ssrfProtection
		rl.logger.Warn("coordinator snapshot omitted ssrf_protection; retaining current SSRF policy")
	}
	opts := append([]router.Option(nil), rl.routerOpts...)
	opts = append(opts, router.WithSSRFProtection(ssrfP))
	newRouter, err := router.New(cfg, rl.logger, opts...)
	if err != nil {
		return fmt.Errorf("router rebuild: %w", err)
	}

	rl.reloadHandler.swap(rl.tp.HTTPMiddleware("csar", newRouter))

	if rl.currentRouter != nil {
		rl.currentRouter.Close()
	}
	rl.currentRouter = newRouter
	rl.policyCapabilities = cfg.RequiredCapabilities()
	rl.originReceivers = cfg.HasOriginReceivers()
	rl.ssrfProtection = ssrfP
	rl.redisKeyPrefix = prefix

	pruned := rl.sharedTM.SyncKeys(newRouter.RegisteredKeys())
	if pruned > 0 {
		rl.logger.Info("pruned stale throttle keys after config reload",
			"pruned", pruned,
		)
	}

	rl.logger.Info("configuration reloaded",
		"routes", len(cfg.Paths),
		"ssrf_block_private", ssrfP.BlockPrivate,
		"ssrf_block_loopback", ssrfP.BlockLoopback,
		"ssrf_block_link_local", ssrfP.BlockLinkLocal,
		"ssrf_block_metadata", ssrfP.BlockMetadata,
		"ssrf_allowed_hosts", len(ssrfP.AllowedHosts),
	)
	return nil
}

func buildSSRFProtection(cfg *config.SSRFConfig) *proxy.SSRFProtection {
	p := proxy.DefaultSSRFProtection()
	if cfg != nil {
		p.BlockPrivate = cfg.IsBlockPrivate()
		p.BlockLoopback = cfg.IsBlockLoopback()
		p.BlockLinkLocal = cfg.IsBlockLinkLocal()
		p.BlockMetadata = cfg.IsBlockMetadata()
		for _, host := range cfg.AllowedInternalHosts {
			p.AllowedHosts[host] = true
		}
	}
	return p
}
