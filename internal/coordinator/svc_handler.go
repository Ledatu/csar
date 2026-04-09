package coordinator

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"
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
	if req.Value == "" {
		s.metrics.FailuresTotal.WithLabelValues("svc_put", "validation").Inc()
		adminRejectJSON(w, http.StatusBadRequest, "value is required")
		return
	}

	entry := TokenEntry{
		EncryptedToken: []byte(req.Value),
		KMSKeyID:       "",
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
	s.authSvc.LoadToken(tokenRef, entry)
	s.metrics.CacheEntries.Set(float64(s.authSvc.TokenCount()))
	s.coord.BroadcastTokenInvalidation([]string{tokenRef})
	s.metrics.InvalidationBroadcasts.Inc()

	s.logger.Info("svc token upserted",
		"token_ref", tokenRef,
		"caller", subject,
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
