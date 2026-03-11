package main

import (
	"fmt"
	"log/slog"
	"net/http"
	"sync/atomic"

	"github.com/ledatu/csar/internal/config"
	"github.com/ledatu/csar/internal/router"
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
// Restart-required field detection (reload-awareness)
// ---------------------------------------------------------------------------

// restartRequiredSnapshot captures config field values that cannot be changed
// at runtime and require a full process restart.
type restartRequiredSnapshot struct {
	ListenAddr  string
	KMSProvider string
	TLSCertFile string
	TLSKeyFile  string
	Profile     string
}

// snapshotRestartRequiredFields takes a snapshot of fields that need a restart
// to take effect. Compare with the new config on SIGHUP.
func snapshotRestartRequiredFields(cfg *config.Config) restartRequiredSnapshot {
	snap := restartRequiredSnapshot{
		ListenAddr: cfg.ListenAddr,
		Profile:    cfg.Profile,
	}
	if cfg.KMS != nil {
		snap.KMSProvider = cfg.KMS.Provider
	}
	if cfg.TLS != nil {
		snap.TLSCertFile = cfg.TLS.CertFile
		snap.TLSKeyFile = cfg.TLS.KeyFile
	}
	return snap
}

// checkRestartRequiredChanges compares the snapshot with the new config and
// logs warnings for fields that changed but require a restart to take effect.
func checkRestartRequiredChanges(logger *slog.Logger, snap restartRequiredSnapshot, newCfg *config.Config) {
	if newCfg.ListenAddr != snap.ListenAddr {
		logger.Warn("field 'listen_addr' changed but requires restart to take effect",
			"old", snap.ListenAddr, "new", newCfg.ListenAddr)
	}
	if newCfg.Profile != snap.Profile {
		logger.Warn("field 'profile' changed but requires restart to take effect",
			"old", snap.Profile, "new", newCfg.Profile)
	}

	newKMS := ""
	if newCfg.KMS != nil {
		newKMS = newCfg.KMS.Provider
	}
	if newKMS != snap.KMSProvider {
		logger.Warn("field 'kms.provider' changed but requires restart to take effect",
			"old", snap.KMSProvider, "new", newKMS)
	}

	newCert, newKey := "", ""
	if newCfg.TLS != nil {
		newCert = newCfg.TLS.CertFile
		newKey = newCfg.TLS.KeyFile
	}
	if newCert != snap.TLSCertFile || newKey != snap.TLSKeyFile {
		logger.Warn("TLS certificate paths changed but require restart to take effect",
			"old_cert", snap.TLSCertFile, "new_cert", newCert)
	}
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

	// Count routes with security and throttle
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
