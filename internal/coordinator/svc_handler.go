package coordinator

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/ledatu/csar-core/tokenmint"
)

// handleSvcPutToken handles PUT /svc/tokens/{tokenRef...} from services
// routed through the csar router. Auth is via X-Gateway-Subject header
// (set by the router after STS JWT validation) + prefix enforcement.
func (s *AdminServer) handleSvcPutToken(w http.ResponseWriter, r *http.Request) {
	tokenRef := r.PathValue("tokenRef")

	subject, ok := s.validateSvcRequest(w, r, tokenRef, "svc_put")
	if !ok {
		return
	}

	s3Managed := s.cfg.S3ManagesEncryption != nil && *s.cfg.S3ManagesEncryption
	if !s3Managed {
		s.metrics.FailuresTotal.WithLabelValues("svc_put", "configuration").Inc()
		adminRejectJSON(w, http.StatusServiceUnavailable, "service token API requires s3_manages_encryption=true")
		return
	}

	var req putTokenRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.metrics.FailuresTotal.WithLabelValues("svc_put", "validation").Inc()
		adminRejectJSON(w, http.StatusBadRequest, "invalid JSON body")
		return
	}

	var entry TokenEntry
	switch {
	case req.Descriptor != nil && req.Value != "":
		s.metrics.FailuresTotal.WithLabelValues("svc_put", "validation").Inc()
		adminRejectJSON(w, http.StatusBadRequest, "value and descriptor are mutually exclusive")
		return

	case req.Descriptor != nil:
		if !s.validateSvcDescriptor(w, r, tokenRef, req.Descriptor) {
			return
		}
		entry = TokenEntry{Descriptor: req.Descriptor}

	case req.Value != "":
		entry = TokenEntry{
			EncryptedToken: []byte(req.Value),
			KMSKeyID:       "",
		}

	default:
		s.metrics.FailuresTotal.WithLabelValues("svc_put", "validation").Inc()
		adminRejectJSON(w, http.StatusBadRequest, "value or descriptor is required")
		return
	}

	meta := TokenMetadata{
		UpdatedBy: subject,
	}

	version, err := s.store.UpsertToken(r.Context(), tokenRef, entry, meta)
	if err != nil {
		s.logger.Error("svc token put: S3 write failed",
			"token_ref", tokenRef,
			"error", err,
		)
		s.metrics.FailuresTotal.WithLabelValues("svc_put", "s3_write").Inc()
		adminRejectJSON(w, http.StatusInternalServerError, "storage write failed")
		return
	}

	entry.Version = version
	if entry.Descriptor != nil {
		// Never cache a descriptor: it holds no token bytes, and LoadToken
		// bypasses the isValid check that would otherwise reject it. Evicting
		// instead drops any bearer minted from the previous credential and
		// forces the next request to resolve through the minting decorator.
		s.authSvc.RemoveToken(tokenRef)
	} else {
		s.authSvc.LoadToken(tokenRef, entry)
	}
	s.metrics.CacheEntries.Set(float64(s.authSvc.TokenCount()))
	s.coord.BroadcastTokenInvalidation([]string{tokenRef})
	s.metrics.InvalidationBroadcasts.Inc()

	s.logger.Info("svc token upserted",
		"token_ref", tokenRef,
		"caller", subject,
		"descriptor", entry.Descriptor != nil,
		"source_ip", sourceIP(r),
	)

	s.metrics.RequestsTotal.WithLabelValues("svc_put", "success").Inc()
	respondJSON(w, http.StatusOK, tokenMutationResponse{
		TokenRef: tokenRef,
		Version:  version,
		Status:   "updated",
	})
}

type copyTokenRequest struct {
	SourceRef string `json:"source_ref"`
}

// handleSvcCopyToken handles POST /svc/tokens/{tokenRef...} and copies an
// existing encrypted token object to a new token_ref without exposing plaintext.
func (s *AdminServer) handleSvcCopyToken(w http.ResponseWriter, r *http.Request) {
	tokenRef := r.PathValue("tokenRef")

	subject, ok := s.validateSvcRequest(w, r, tokenRef, "svc_copy")
	if !ok {
		return
	}

	var req copyTokenRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.metrics.FailuresTotal.WithLabelValues("svc_copy", "validation").Inc()
		adminRejectJSON(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	if req.SourceRef == "" {
		s.metrics.FailuresTotal.WithLabelValues("svc_copy", "validation").Inc()
		adminRejectJSON(w, http.StatusBadRequest, "source_ref is required")
		return
	}
	if _, ok := s.validateSvcRequest(w, r, req.SourceRef, "svc_copy"); !ok {
		return
	}

	entry, err := s.store.FetchOne(r.Context(), req.SourceRef)
	if err != nil {
		if errors.Is(err, ErrTokenNotFound) {
			s.metrics.FailuresTotal.WithLabelValues("svc_copy", "not_found").Inc()
			adminRejectJSON(w, http.StatusNotFound, "source token not found")
			return
		}
		s.logger.Error("svc token copy: fetch failed",
			"source_ref", req.SourceRef,
			"token_ref", tokenRef,
			"error", err,
		)
		s.metrics.FailuresTotal.WithLabelValues("svc_copy", "fetch").Inc()
		adminRejectJSON(w, http.StatusInternalServerError, "storage read failed")
		return
	}

	// Copying a descriptor would duplicate a credential reference into a ref
	// whose namespace no longer matches the credentials it points at, which
	// the read-path scope check would then reject anyway. Refuse it here so
	// the failure is a clear 400 rather than a puzzling 502 later.
	if entry.Descriptor != nil {
		s.metrics.FailuresTotal.WithLabelValues("svc_copy", "validation").Inc()
		adminRejectJSON(w, http.StatusBadRequest, "source ref is a mint descriptor; register a new descriptor instead of copying")
		return
	}

	version, err := s.store.UpsertToken(r.Context(), tokenRef, entry, TokenMetadata{UpdatedBy: subject})
	if err != nil {
		s.logger.Error("svc token copy: write failed",
			"source_ref", req.SourceRef,
			"token_ref", tokenRef,
			"error", err,
		)
		s.metrics.FailuresTotal.WithLabelValues("svc_copy", "write").Inc()
		adminRejectJSON(w, http.StatusInternalServerError, "storage write failed")
		return
	}

	entry.Version = version
	s.authSvc.LoadToken(tokenRef, entry)
	s.metrics.CacheEntries.Set(float64(s.authSvc.TokenCount()))
	s.coord.BroadcastTokenInvalidation([]string{tokenRef})
	s.metrics.InvalidationBroadcasts.Inc()

	s.logger.Info("svc token copied",
		"source_ref", req.SourceRef,
		"token_ref", tokenRef,
		"caller", subject,
		"source_ip", sourceIP(r),
	)

	s.metrics.RequestsTotal.WithLabelValues("svc_copy", "success").Inc()
	respondJSON(w, http.StatusOK, tokenMutationResponse{
		TokenRef: tokenRef,
		Version:  version,
		Status:   "updated",
	})
}

// handleSvcDeleteToken handles DELETE /svc/tokens/{tokenRef...} from services
// routed through the csar router.
func (s *AdminServer) handleSvcDeleteToken(w http.ResponseWriter, r *http.Request) {
	tokenRef := r.PathValue("tokenRef")

	subject, ok := s.validateSvcRequest(w, r, tokenRef, "svc_delete")
	if !ok {
		return
	}

	if err := s.store.DeleteToken(r.Context(), tokenRef); err != nil {
		s.logger.Error("svc token delete: S3 delete failed",
			"token_ref", tokenRef,
			"error", err,
		)
		s.metrics.FailuresTotal.WithLabelValues("svc_delete", "s3_delete").Inc()
		adminRejectJSON(w, http.StatusInternalServerError, "storage delete failed")
		return
	}

	s.authSvc.RemoveToken(tokenRef)
	s.metrics.CacheEntries.Set(float64(s.authSvc.TokenCount()))
	s.coord.BroadcastTokenInvalidation([]string{tokenRef})
	s.metrics.InvalidationBroadcasts.Inc()

	s.logger.Info("svc token deleted",
		"token_ref", tokenRef,
		"caller", subject,
		"source_ip", sourceIP(r),
	)

	s.metrics.RequestsTotal.WithLabelValues("svc_delete", "success").Inc()
	respondJSON(w, http.StatusOK, tokenMutationResponse{
		TokenRef: tokenRef,
		Status:   "deleted",
	})
}

// validateSvcRequest performs common validation for /svc/ handlers:
// 1. Extracts and validates X-Gateway-Subject (set by csar router)
// 2. Enforces prefix-scoped authorization via SvcAPIConfig.PrefixMap
// 3. Validates token ref format
//
// Returns the subject and true on success; writes an error response and
// returns false on failure.
func (s *AdminServer) validateSvcRequest(w http.ResponseWriter, r *http.Request, tokenRef, opLabel string) (string, bool) {
	subject := r.Header.Get("X-Gateway-Subject")
	if subject == "" {
		s.metrics.FailuresTotal.WithLabelValues(opLabel, "unauthenticated").Inc()
		adminRejectJSON(w, http.StatusUnauthorized, "missing X-Gateway-Subject")
		return "", false
	}

	allowedPrefix, ok := s.cfg.Svc.AllowedPrefix(subject)
	if !ok {
		s.metrics.FailuresTotal.WithLabelValues(opLabel, "authorization").Inc()
		adminRejectJSON(w, http.StatusForbidden, "service not authorized for token operations")
		return "", false
	}

	if !strings.HasPrefix(tokenRef, allowedPrefix) {
		s.metrics.FailuresTotal.WithLabelValues(opLabel, "authorization").Inc()
		adminRejectJSON(w, http.StatusForbidden, "token_ref outside allowed namespace")
		return "", false
	}

	if err := ValidateTokenRef(tokenRef); err != nil {
		s.metrics.FailuresTotal.WithLabelValues(opLabel, "validation").Inc()
		adminRejectJSON(w, http.StatusBadRequest, err.Error())
		return "", false
	}

	return subject, true
}

// validateSvcDescriptor checks a descriptor before it is written.
//
// These checks are for the caller's benefit — a clear 400 at registration
// beats a 502 at first use. They are NOT the security boundary: the same scope
// rule is enforced again in MintingTokenStore on every read, because an object
// can reach S3 without passing through this handler at all (the admin API, the
// storage console, a leaked service-account key).
func (s *AdminServer) validateSvcDescriptor(w http.ResponseWriter, r *http.Request, tokenRef string, desc *tokenmint.Descriptor) bool {
	if s.mintCfg == nil {
		s.metrics.FailuresTotal.WithLabelValues("svc_put", "configuration").Inc()
		adminRejectJSON(w, http.StatusServiceUnavailable, "token minting is not enabled on this coordinator")
		return false
	}

	if err := desc.Validate(); err != nil {
		s.metrics.FailuresTotal.WithLabelValues("svc_put", "validation").Inc()
		adminRejectJSON(w, http.StatusBadRequest, err.Error())
		return false
	}

	// Only profiles the operator configured may be named. Accepting an
	// arbitrary name would let a caller point a credential at an endpoint
	// nobody chose for it as soon as such a profile were later added.
	profile, ok := s.mintCfg.Profile(desc.GrantProfile)
	if !ok {
		s.metrics.FailuresTotal.WithLabelValues("svc_put", "validation").Inc()
		adminRejectJSON(w, http.StatusBadRequest, fmt.Sprintf("unknown grant_profile %q", desc.GrantProfile))
		return false
	}

	// Both credential refs must be inside the caller's own namespace.
	for _, ref := range []string{desc.ClientIDRef, desc.ClientSecretRef} {
		if _, ok := s.validateSvcRequest(w, r, ref, "svc_put"); !ok {
			return false
		}
	}

	scope, err := refScope(tokenRef, profile.SecretRefScopeSegments)
	if err != nil {
		s.metrics.FailuresTotal.WithLabelValues("svc_put", "validation").Inc()
		adminRejectJSON(w, http.StatusBadRequest, err.Error())
		return false
	}
	for _, ref := range []string{desc.ClientIDRef, desc.ClientSecretRef} {
		if !strings.HasPrefix(ref, scope) {
			s.metrics.FailuresTotal.WithLabelValues("svc_put", "authorization").Inc()
			adminRejectJSON(w, http.StatusBadRequest,
				fmt.Sprintf("credential ref %q must be within %q", ref, scope))
			return false
		}
	}

	return true
}
