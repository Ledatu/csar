package router

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"time"

	auditcore "github.com/ledatu/csar-core/audit"
	"github.com/ledatu/csar-core/gatewayctx"
	"github.com/ledatu/csar-core/jsonredact"
	"github.com/ledatu/csar/internal/config"
)

func defaultAuditForMutatingMethod(method string) bool {
	switch strings.ToUpper(method) {
	case http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete:
		return true
	default:
		return false
	}
}

func shouldEmitAudit(mode config.AuditMode, status int) bool {
	switch mode {
	case config.AuditModeAll:
		return true
	case config.AuditModeErrors:
		return status >= http.StatusBadRequest
	default:
		return false
	}
}

const routerAuditServiceName = "csar-router"

const actorEmailHeader = "X-User-Email"

// auditResponseCapture records the HTTP status code for audit metadata.
type auditResponseCapture struct {
	http.ResponseWriter
	statusCode int
}

func (a *auditResponseCapture) WriteHeader(code int) {
	a.statusCode = code
	a.ResponseWriter.WriteHeader(code)
}

func (r *Router) wrapUpstreamWithAudit(rt *route, next http.Handler) http.Handler {
	needsWrapper := rt.auditMode.IsActive() || (rt.auditCapture != nil && rt.auditCapture.CaptureRequestEnabled())
	if r.auditClient == nil || !needsWrapper {
		return next
	}

	captureBody := rt.auditCapture != nil && rt.auditCapture.CaptureRequestEnabled() && methodMayHaveBody(rt.method)

	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		var (
			beforeState  json.RawMessage
			requestBytes int
			truncated    bool
			contentType  string
		)

		if captureBody && req.Body != nil {
			bodyBytes, ct, wasTruncated, err := readRequestBodyForAudit(req, rt.auditCapture.MaxBytes)
			if err == nil {
				contentType = ct
				requestBytes = len(bodyBytes)
				truncated = wasTruncated
				if !wasTruncated && len(bodyBytes) > 0 {
					beforeState = redactRequestBody(bodyBytes, contentType, rt.auditCapture)
				}
			}
		}

		rec := &auditResponseCapture{ResponseWriter: w, statusCode: http.StatusOK}
		next.ServeHTTP(rec, req)

		if !shouldEmitAudit(rt.auditMode, rec.statusCode) {
			return
		}

		gw := gatewayctx.FromRequest(req)
		clientIP := extractClientIP(req, rt.trustProxy, rt.trustedProxyCIDRs)

		scopeType := "platform"
		scopeID := ""
		if gw.Tenant != "" {
			scopeType = "tenant"
			scopeID = gw.Tenant
		}

		actor := gw.Subject
		if actor == "" {
			actor = "anonymous"
		}

		metaMap := map[string]any{
			"http_status": rec.statusCode,
			"route":       rt.routeKey,
			"audit_mode":  string(rt.auditMode),
		}
		if email := strings.TrimSpace(req.Header.Get(actorEmailHeader)); email != "" {
			metaMap["actor_email"] = email
		}
		if captureBody {
			metaMap["request_bytes"] = requestBytes
			metaMap["request_truncated"] = truncated
			if contentType != "" {
				metaMap["request_content_type"] = contentType
			}
		}
		if rt.auditCapture != nil && rt.auditCapture.IncludeQueryEnabled() {
			if queryMeta := captureQueryParams(req, rt.auditCapture); len(queryMeta) > 0 {
				metaMap["query"] = queryMeta
			}
		}

		meta, err := json.Marshal(metaMap)
		if err != nil {
			meta = nil
		}

		ev := &auditcore.Event{
			Service:     routerAuditServiceName,
			Actor:       actor,
			Action:      req.Method + " " + rt.originalPath,
			TargetType:  "path",
			TargetID:    req.URL.Path,
			ScopeType:   scopeType,
			ScopeID:     scopeID,
			BeforeState: beforeState,
			Metadata:    meta,
			RequestID:   r.requestID(req),
			ClientIP:    clientIP,
			CreatedAt:   time.Now().UTC(),
		}
		r.auditClient.Record(req.Context(), ev)
	})
}

func methodMayHaveBody(method string) bool {
	switch strings.ToUpper(method) {
	case http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete:
		return true
	default:
		return false
	}
}

func readRequestBodyForAudit(req *http.Request, maxBytes int64) (body []byte, contentType string, truncated bool, err error) {
	if maxBytes <= 0 {
		maxBytes = 16 * 1024
	}

	contentType = req.Header.Get("Content-Type")
	if req.ContentLength > maxBytes {
		return nil, contentType, true, nil
	}

	if req.Body == nil {
		return nil, contentType, false, nil
	}

	lr := io.LimitReader(req.Body, maxBytes+1)
	body, err = io.ReadAll(lr)
	if err != nil {
		return nil, contentType, false, err
	}

	if int64(len(body)) > maxBytes {
		req.Body = io.NopCloser(io.MultiReader(bytes.NewReader(body), req.Body))
		return body[:maxBytes], contentType, true, nil
	}

	req.Body = io.NopCloser(bytes.NewReader(body))
	req.ContentLength = int64(len(body))
	return body, contentType, false, nil
}

func redactRequestBody(raw []byte, contentType string, cfg *config.AuditCaptureConfig) json.RawMessage {
	if cfg == nil || len(raw) == 0 {
		return nil
	}

	ct := strings.ToLower(contentType)
	if strings.Contains(ct, "application/json") || strings.Contains(ct, "+json") {
		if !cfg.RedactionEnabled() {
			if !json.Valid(raw) {
				summary, _ := json.Marshal(map[string]any{
					"_content_type": contentType,
					"_size":         len(raw),
					"_parse_error":  true,
				})
				return summary
			}
			return json.RawMessage(raw)
		}

		mask := cfg.Mask
		if mask == "" {
			mask = jsonredact.DefaultMask
		}

		redacted, err := jsonredact.ParseAndRedactJSON(raw, jsonredact.Config{
			PathFields:    cfg.Fields,
			SensitiveKeys: cfg.SensitiveFields,
			Mask:          mask,
		})
		if err != nil {
			summary, _ := json.Marshal(map[string]any{
				"_content_type": contentType,
				"_size":         len(raw),
				"_parse_error":  true,
			})
			return summary
		}
		return redacted
	}

	summary, _ := json.Marshal(map[string]any{
		"_content_type": contentType,
		"_size":         len(raw),
	})
	return summary
}

func captureQueryParams(req *http.Request, cfg *config.AuditCaptureConfig) map[string]string {
	if req.URL == nil || cfg == nil {
		return nil
	}
	values := req.URL.Query()
	if len(values) == 0 {
		return nil
	}
	out := make(map[string]string, len(values))
	for k, vs := range values {
		if len(vs) == 0 {
			continue
		}
		out[k] = vs[0]
	}
	if !cfg.RedactionEnabled() {
		return out
	}
	mask := cfg.Mask
	if mask == "" {
		mask = jsonredact.DefaultMask
	}
	extraKeys := append([]string{}, cfg.Fields...)
	extraKeys = append(extraKeys, cfg.SensitiveFields...)
	jsonredact.RedactQueryMap(out, mask, extraKeys...)
	return out
}
