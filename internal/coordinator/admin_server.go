package coordinator

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/ledatu/csar/internal/authn"
	"github.com/ledatu/csar/internal/kms"
)

// AdminServer is the internal HTTPS server for token lifecycle management.
type AdminServer struct {
	cfg         AdminAPIConfig
	authSvc     *AuthServiceImpl
	coord       *Coordinator
	store       MutableTokenStore
	kmsProvider kms.Provider // nil when s3_manages_encryption=true
	logger      *slog.Logger
	metrics     *AdminMetrics
	server      *http.Server
}

// NewAdminServer creates an AdminServer wired to the coordinator's internal
// components. kmsProvider may be nil when s3_manages_encryption is true.
func NewAdminServer(
	cfg AdminAPIConfig,
	authSvc *AuthServiceImpl,
	coord *Coordinator,
	store MutableTokenStore,
	kmsProvider kms.Provider,
	logger *slog.Logger,
) *AdminServer {
	return &AdminServer{
		cfg:         cfg,
		authSvc:     authSvc,
		coord:       coord,
		store:       store,
		kmsProvider: kmsProvider,
		logger:      logger,
		metrics:     NewAdminMetrics(),
	}
}

// ListenAndServe starts the admin HTTPS server. Blocks until the server
// shuts down or returns an error.
func (s *AdminServer) ListenAndServe() error {
	mux := http.NewServeMux()
	s.registerRoutes(mux)

	var handler http.Handler = mux

	handler = s.timeoutMiddleware(handler)
	handler = s.bodySizeMiddleware(handler)

	validator := authn.NewJWTValidator(s.logger.With("component", "admin_jwt"))
	authMw := AdminAuthMiddleware(validator, s.cfg.Auth, s.logger)
	handler = authMw(handler)

	handler = s.auditMiddleware(handler)

	tlsCfg, err := s.buildTLSConfig()
	if err != nil {
		return fmt.Errorf("admin server: TLS config: %w", err)
	}

	s.server = &http.Server{
		Addr:         s.cfg.ListenAddr,
		Handler:      handler,
		TLSConfig:    tlsCfg,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	lis, err := net.Listen("tcp", s.cfg.ListenAddr)
	if err != nil {
		return fmt.Errorf("admin server: listen: %w", err)
	}

	if tlsCfg != nil {
		lis = tls.NewListener(lis, tlsCfg)
	} else {
		s.logger.Warn("INSECURE: admin API running without TLS — do NOT use in production")
	}

	s.logger.Info("admin API server starting",
		"listen", s.cfg.ListenAddr,
		"tls", tlsCfg != nil,
	)

	if s.cfg.S3ManagesEncryption != nil && *s.cfg.S3ManagesEncryption {
		s.logger.Warn("s3_manages_encryption=true: token values are stored as plaintext in S3, " +
			"relying entirely on S3 server-side encryption. " +
			"This trades away application-layer KMS wrapping. Use only if acceptable for your threat model.")
	}

	return s.server.Serve(lis)
}

// Shutdown gracefully shuts down the admin server.
func (s *AdminServer) Shutdown() error {
	if s.server == nil {
		return nil
	}
	return s.server.Close()
}

func (s *AdminServer) registerRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /admin/v1/health", s.handleHealth)
	mux.HandleFunc("PUT /admin/v1/tokens/{tokenRef...}", s.handlePutToken)
	mux.HandleFunc("DELETE /admin/v1/tokens/{tokenRef...}", s.handleDeleteToken)
	mux.HandleFunc("GET /admin/v1/tokens/{tokenRef...}", s.handleGetToken)
	mux.HandleFunc("POST /admin/v1/tokens/{tokenRef...}", s.handlePostToken)
}

// --- Health ---

func (s *AdminServer) handleHealth(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, `{"status":"ok"}`)
}

// --- PUT (create/update) ---

type putTokenRequest struct {
	Value    string            `json:"value"`
	KMSKeyID string            `json:"kms_key_id"`
	Mode     string            `json:"mode"`
	Metadata map[string]string `json:"metadata"`
}

type tokenMutationResponse struct {
	TokenRef string `json:"token_ref"`
	Version  string `json:"version,omitempty"`
	Status   string `json:"status"`
}

func (s *AdminServer) handlePutToken(w http.ResponseWriter, r *http.Request) {
	tokenRef := r.PathValue("tokenRef")
	s.upsertToken(w, r, tokenRef, "put")
}

func (s *AdminServer) upsertToken(w http.ResponseWriter, r *http.Request, tokenRef, auditOp string) {
	claims := AdminClaimsFromContext(r.Context())
	if claims == nil {
		s.metrics.FailuresTotal.WithLabelValues(auditOp, "unauthenticated").Inc()
		adminRejectJSON(w, http.StatusUnauthorized, "unauthenticated")
		return
	}

	if err := ValidateTokenRef(tokenRef); err != nil {
		s.metrics.FailuresTotal.WithLabelValues(auditOp, "validation").Inc()
		adminRejectJSON(w, http.StatusBadRequest, err.Error())
		return
	}

	var req putTokenRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.metrics.FailuresTotal.WithLabelValues(auditOp, "validation").Inc()
		adminRejectJSON(w, http.StatusBadRequest, "invalid JSON body")
		return
	}

	if req.Value == "" {
		s.metrics.FailuresTotal.WithLabelValues(auditOp, "validation").Inc()
		adminRejectJSON(w, http.StatusBadRequest, "value is required")
		return
	}

	s3Managed := s.cfg.S3ManagesEncryption != nil && *s.cfg.S3ManagesEncryption

	if !s3Managed && req.KMSKeyID == "" {
		s.metrics.FailuresTotal.WithLabelValues(auditOp, "validation").Inc()
		adminRejectJSON(w, http.StatusBadRequest, "kms_key_id is required when s3_manages_encryption is false")
		return
	}

	op := OpWrite
	if auditOp == "rotate" {
		op = OpRotate
	}

	if err := CheckAdminAuthorization(claims, s.cfg.Authorization, op, tokenRef, req.KMSKeyID); err != nil {
		s.metrics.FailuresTotal.WithLabelValues(auditOp, "authorization").Inc()
		adminRejectJSON(w, http.StatusForbidden, err.Error())
		return
	}

	var entry TokenEntry
	if s3Managed {
		entry = TokenEntry{
			EncryptedToken: []byte(req.Value),
			KMSKeyID:       "",
		}
	} else {
		if s.kmsProvider == nil {
			s.metrics.FailuresTotal.WithLabelValues(auditOp, "kms").Inc()
			adminRejectJSON(w, http.StatusInternalServerError, "KMS provider not configured")
			return
		}
		start := time.Now()
		ciphertext, err := s.kmsProvider.Encrypt(r.Context(), req.KMSKeyID, []byte(req.Value))
		s.metrics.KMSEncryptDuration.Observe(time.Since(start).Seconds())
		if err != nil {
			s.logger.Error("KMS encryption failed",
				"token_ref", tokenRef,
				"error", err,
			)
			s.metrics.FailuresTotal.WithLabelValues(auditOp, "kms").Inc()
			adminRejectJSON(w, http.StatusInternalServerError, "encryption failed")
			return
		}
		entry = TokenEntry{
			EncryptedToken: ciphertext,
			KMSKeyID:       req.KMSKeyID,
		}
	}

	meta := TokenMetadata{
		UpdatedBy: claims.Sub,
		Tenant:    claims.Tenant,
	}
	if t, ok := req.Metadata["tenant"]; ok {
		meta.Tenant = t
	}

	start := time.Now()
	version, err := s.store.UpsertToken(r.Context(), tokenRef, entry, meta)
	s.metrics.StoreWriteDuration.Observe(time.Since(start).Seconds())
	if err != nil {
		s.logger.Error("S3 write failed",
			"token_ref", tokenRef,
			"error", err,
		)
		s.metrics.FailuresTotal.WithLabelValues(auditOp, "s3_write").Inc()
		adminRejectJSON(w, http.StatusInternalServerError, "storage write failed")
		return
	}

	entry.Version = version
	s.authSvc.LoadToken(tokenRef, entry)
	s.metrics.CacheEntries.Set(float64(s.authSvc.TokenCount()))

	s.coord.BroadcastTokenInvalidation([]string{tokenRef})
	s.metrics.InvalidationBroadcasts.Inc()

	s.logger.Info("admin token upserted",
		"operation", auditOp,
		"token_ref", tokenRef,
		"version", version,
		"caller", claims.Sub,
		"source_ip", sourceIP(r),
	)

	s.metrics.RequestsTotal.WithLabelValues(auditOp, "success").Inc()
	respondJSON(w, http.StatusOK, tokenMutationResponse{
		TokenRef: tokenRef,
		Version:  version,
		Status:   "updated",
	})
}

// --- DELETE ---

func (s *AdminServer) handleDeleteToken(w http.ResponseWriter, r *http.Request) {
	tokenRef := r.PathValue("tokenRef")
	claims := AdminClaimsFromContext(r.Context())
	if claims == nil {
		s.metrics.FailuresTotal.WithLabelValues("delete", "unauthenticated").Inc()
		adminRejectJSON(w, http.StatusUnauthorized, "unauthenticated")
		return
	}

	if err := ValidateTokenRef(tokenRef); err != nil {
		s.metrics.FailuresTotal.WithLabelValues("delete", "validation").Inc()
		adminRejectJSON(w, http.StatusBadRequest, err.Error())
		return
	}

	if err := CheckAdminAuthorization(claims, s.cfg.Authorization, OpDelete, tokenRef, ""); err != nil {
		s.metrics.FailuresTotal.WithLabelValues("delete", "authorization").Inc()
		adminRejectJSON(w, http.StatusForbidden, err.Error())
		return
	}

	if err := s.store.DeleteToken(r.Context(), tokenRef); err != nil {
		s.logger.Error("S3 delete failed",
			"token_ref", tokenRef,
			"error", err,
		)
		s.metrics.FailuresTotal.WithLabelValues("delete", "s3_delete").Inc()
		adminRejectJSON(w, http.StatusInternalServerError, "storage delete failed")
		return
	}

	s.authSvc.RemoveToken(tokenRef)
	s.metrics.CacheEntries.Set(float64(s.authSvc.TokenCount()))

	s.coord.BroadcastTokenInvalidation([]string{tokenRef})
	s.metrics.InvalidationBroadcasts.Inc()

	s.logger.Info("admin token deleted",
		"token_ref", tokenRef,
		"caller", claims.Sub,
		"source_ip", sourceIP(r),
	)

	s.metrics.RequestsTotal.WithLabelValues("delete", "success").Inc()
	respondJSON(w, http.StatusOK, tokenMutationResponse{
		TokenRef: tokenRef,
		Status:   "deleted",
	})
}

// --- GET (metadata only) ---

type tokenMetadataResponse struct {
	TokenRef string `json:"token_ref"`
	KMSKeyID string `json:"kms_key_id,omitempty"`
	Version  string `json:"version,omitempty"`
	HasValue bool   `json:"has_value"`
}

func (s *AdminServer) handleGetToken(w http.ResponseWriter, r *http.Request) {
	tokenRef := r.PathValue("tokenRef")
	claims := AdminClaimsFromContext(r.Context())
	if claims == nil {
		s.metrics.FailuresTotal.WithLabelValues("read", "unauthenticated").Inc()
		adminRejectJSON(w, http.StatusUnauthorized, "unauthenticated")
		return
	}

	if err := ValidateTokenRef(tokenRef); err != nil {
		s.metrics.FailuresTotal.WithLabelValues("read", "validation").Inc()
		adminRejectJSON(w, http.StatusBadRequest, err.Error())
		return
	}

	if err := CheckAdminAuthorization(claims, s.cfg.Authorization, OpRead, tokenRef, ""); err != nil {
		s.metrics.FailuresTotal.WithLabelValues("read", "authorization").Inc()
		adminRejectJSON(w, http.StatusForbidden, err.Error())
		return
	}

	entry, err := s.store.FetchOne(r.Context(), tokenRef)
	if err != nil {
		s.metrics.FailuresTotal.WithLabelValues("read", "not_found").Inc()
		adminRejectJSON(w, http.StatusNotFound, fmt.Sprintf("token ref %q not found", tokenRef))
		return
	}

	s.metrics.RequestsTotal.WithLabelValues("read", "success").Inc()
	respondJSON(w, http.StatusOK, tokenMetadataResponse{
		TokenRef: tokenRef,
		KMSKeyID: entry.KMSKeyID,
		Version:  entry.Version,
		HasValue: len(entry.EncryptedToken) > 0,
	})
}

// --- POST (rotate or invalidate) ---

type invalidateRequest struct {
	TokenRefs []string `json:"token_refs"`
}

func (s *AdminServer) handlePostToken(w http.ResponseWriter, r *http.Request) {
	tokenRef := r.PathValue("tokenRef")

	// POST /admin/v1/tokens:invalidate
	if tokenRef == ":invalidate" || strings.HasSuffix(r.URL.Path, ":invalidate") {
		s.handleInvalidate(w, r)
		return
	}

	// POST /admin/v1/tokens/{token_ref}:rotate
	if strings.HasSuffix(tokenRef, ":rotate") {
		tokenRef = strings.TrimSuffix(tokenRef, ":rotate")
		s.upsertToken(w, r, tokenRef, "rotate")
		return
	}

	adminRejectJSON(w, http.StatusBadRequest, "unsupported POST action; use :rotate or :invalidate suffix")
}

func (s *AdminServer) handleInvalidate(w http.ResponseWriter, r *http.Request) {
	claims := AdminClaimsFromContext(r.Context())
	if claims == nil {
		s.metrics.FailuresTotal.WithLabelValues("invalidate", "unauthenticated").Inc()
		adminRejectJSON(w, http.StatusUnauthorized, "unauthenticated")
		return
	}

	var req invalidateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.metrics.FailuresTotal.WithLabelValues("invalidate", "validation").Inc()
		adminRejectJSON(w, http.StatusBadRequest, "invalid JSON body")
		return
	}

	if len(req.TokenRefs) == 0 {
		s.metrics.FailuresTotal.WithLabelValues("invalidate", "validation").Inc()
		adminRejectJSON(w, http.StatusBadRequest, "token_refs must contain at least one entry")
		return
	}

	for _, ref := range req.TokenRefs {
		if err := ValidateTokenRef(ref); err != nil {
			s.metrics.FailuresTotal.WithLabelValues("invalidate", "validation").Inc()
			adminRejectJSON(w, http.StatusBadRequest, fmt.Sprintf("invalid token_ref %q: %s", ref, err.Error()))
			return
		}
		if err := CheckAdminAuthorization(claims, s.cfg.Authorization, OpInvalidate, ref, ""); err != nil {
			s.metrics.FailuresTotal.WithLabelValues("invalidate", "authorization").Inc()
			adminRejectJSON(w, http.StatusForbidden, fmt.Sprintf("not authorized for token_ref %q: %s", ref, err.Error()))
			return
		}
	}

	s.coord.BroadcastTokenInvalidation(req.TokenRefs)
	s.metrics.InvalidationBroadcasts.Inc()

	s.logger.Info("admin forced invalidation",
		"token_refs", req.TokenRefs,
		"caller", claims.Sub,
		"source_ip", sourceIP(r),
	)

	s.metrics.RequestsTotal.WithLabelValues("invalidate", "success").Inc()
	respondJSON(w, http.StatusOK, map[string]interface{}{
		"invalidated": req.TokenRefs,
		"status":      "ok",
	})
}

// --- Middleware ---

func (s *AdminServer) timeoutMiddleware(next http.Handler) http.Handler {
	return http.TimeoutHandler(next, s.cfg.Limits.RequestTimeout, `{"error":"request timeout"}`)
}

func (s *AdminServer) bodySizeMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.Body = http.MaxBytesReader(w, r.Body, s.cfg.Limits.MaxTokenSize)
		next.ServeHTTP(w, r)
	})
}

func (s *AdminServer) auditMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		wrapped := &statusRecorder{ResponseWriter: w, statusCode: http.StatusOK}
		next.ServeHTTP(wrapped, r)
		s.logger.Info("admin API request",
			"method", r.Method,
			"path", r.URL.Path,
			"status", wrapped.statusCode,
			"duration_ms", time.Since(start).Milliseconds(),
			"source_ip", sourceIP(r),
		)
	})
}

// --- TLS ---

func (s *AdminServer) buildTLSConfig() (*tls.Config, error) {
	if s.cfg.TLS.CertFile == "" || s.cfg.TLS.KeyFile == "" {
		return nil, nil
	}

	cert, err := tls.LoadX509KeyPair(s.cfg.TLS.CertFile, s.cfg.TLS.KeyFile)
	if err != nil {
		return nil, fmt.Errorf("loading admin TLS cert/key: %w", err)
	}

	tlsCfg := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS13,
	}

	if s.cfg.TLS.ClientCAFile != "" {
		caCert, err := os.ReadFile(s.cfg.TLS.ClientCAFile)
		if err != nil {
			return nil, fmt.Errorf("reading admin client CA: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(caCert) {
			return nil, fmt.Errorf("admin client CA file contains no valid certificates")
		}
		tlsCfg.ClientCAs = pool
		tlsCfg.ClientAuth = tls.RequireAndVerifyClientCert
	}

	return tlsCfg, nil
}

// --- Helpers ---

type statusRecorder struct {
	http.ResponseWriter
	statusCode int
}

func (r *statusRecorder) WriteHeader(code int) {
	r.statusCode = code
	r.ResponseWriter.WriteHeader(code)
}

func respondJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v) //nolint:errcheck
}

func sourceIP(r *http.Request) string {
	host, _, _ := net.SplitHostPort(r.RemoteAddr)
	return host
}
