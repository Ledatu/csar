package router

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"slices"
	"strings"
	"time"

	auditcore "github.com/ledatu/csar-core/audit"
	"github.com/ledatu/csar-core/gatewayctx"
	"github.com/ledatu/csar-core/jsonredact"
	"github.com/ledatu/csar-core/logutil"
	"github.com/ledatu/csar/internal/config"
	"github.com/ledatu/csar/internal/proxy"
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

type auditRequestKey struct{}
type auditRequestState struct {
	identity         gatewayctx.Identity
	email            string
	verified         bool
	stage            string
	upstream         bool
	upstreamStatus   int
	transportFailure bool
	secrets          []string
}

func auditState(req *http.Request) *auditRequestState {
	state, _ := req.Context().Value(auditRequestKey{}).(*auditRequestState)
	return state
}

func auditStage(req *http.Request, stage string) {
	if state := auditState(req); state != nil {
		state.stage = stage
	}
}

func auditIdentity(req *http.Request, rt *route) {
	if state := auditState(req); state != nil {
		state.identity = gatewayctx.FromRequest(req)
		state.verified = true
		if rt.sessionConfig != nil && rt.sessionValidator != nil {
			for _, header := range rt.sessionConfig.ForwardHeaders {
				if strings.EqualFold(header, actorEmailHeader) {
					state.email = req.Header.Get(actorEmailHeader)
				}
			}
		}
		if rt.jwtConfig != nil && rt.jwtValidator != nil {
			for _, header := range rt.jwtConfig.ForwardClaims {
				if strings.EqualFold(header, actorEmailHeader) {
					state.email = req.Header.Get(actorEmailHeader)
				}
			}
		}
	}
}

func auditSecrets(req *http.Request, state *auditRequestState) {
	for name, values := range req.Header {
		if !logutil.IsSensitiveKey(name) {
			continue
		}
		for _, value := range values {
			if len(value) >= 8 && !slices.Contains(state.secrets, value) {
				state.secrets = append(state.secrets, value)
			}
			if _, token, ok := strings.Cut(value, " "); ok && len(token) >= 8 && !slices.Contains(state.secrets, token) {
				state.secrets = append(state.secrets, token)
			}
		}
	}
}

func (r *Router) wrapUpstreamWithAudit(rt *route, next http.Handler) http.Handler {
	needsWrapper := rt.auditMode.IsActive() || (rt.auditCapture != nil && rt.auditCapture.CaptureRequestEnabled())
	if r.auditClient == nil || !needsWrapper {
		return next
	}

	captureResponse := rt.auditCapture != nil && rt.auditCapture.CaptureResponseEnabled()
	captureBody := rt.auditCapture != nil && rt.auditCapture.CaptureRequestEnabled() && methodMayHaveBody(rt.method)

	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		// Preflights have always returned before the audited upstream pipeline.
		if rt.corsConfig != nil && req.Method == http.MethodOptions && req.Header.Get("Origin") != "" {
			next.ServeHTTP(w, req)
			return
		}
		start := time.Now()
		state := auditState(req)
		if state == nil {
			state = &auditRequestState{verified: true, identity: gatewayctx.FromRequest(req)}
			req = req.WithContext(context.WithValue(req.Context(), auditRequestKey{}, state))
		}
		req = req.WithContext(proxy.WithResponseObserver(req.Context(), func(status int) {
			state.transportFailure = status == 0
			state.upstreamStatus = status
		}))
		auditSecrets(req, state)
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

		rec := &auditResponseCapture{ResponseWriter: w, statusCode: http.StatusOK, capture: captureResponse && !isStreamingRequest(req)}
		next.ServeHTTP(rec, req)
		// ReverseProxy writes a successful upgrade directly to the hijacked
		// connection, bypassing WriteHeader. The trusted proxy hook saw 101.
		if rec.hijacked && !rec.written && state.upstreamStatus == http.StatusSwitchingProtocols {
			rec.statusCode = http.StatusSwitchingProtocols
		}

		if !shouldEmitAudit(rt.auditMode, rec.statusCode) {
			return
		}

		gw := state.identity
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
		if email := strings.TrimSpace(state.email); email != "" {
			metaMap["actor_email"] = email
		}
		if captureBody && state.verified {
			metaMap["request_bytes"] = requestBytes
			metaMap["request_truncated"] = truncated
			if contentType != "" {
				metaMap["request_content_type"] = contentType
			}
		}
		if state.verified && rt.auditCapture != nil && rt.auditCapture.IncludeQueryEnabled() {
			if queryMeta := captureQueryParams(req, rt.auditCapture); len(queryMeta) > 0 {
				metaMap["query"] = queryMeta
			}
		}

		var response *auditcore.HTTPResponse
		if captureResponse && rec.statusCode >= 400 {
			auditSecrets(req, state)
			diag := auditcore.CaptureHTTPResponse(&auditcore.HTTPResponseInput{
				Status: rec.statusCode, ContentType: rec.contentType, ContentEncoding: rec.contentEncoding,
				Body: rec.body, ObservedBytes: rec.observedBytes, Complete: rec.capture && !rec.failed && rec.observedBytes <= auditcore.MaxHTTPInspectBytes,
				MaxBodyBytes: int(rt.auditCapture.ResponseMaxBytes), Secrets: state.secrets,
				Redact: jsonredact.Config{PathFields: rt.auditCapture.Fields, SensitiveKeys: rt.auditCapture.SensitiveFields},
			})
			diag.DurationMS = time.Since(start).Milliseconds()
			diag.Stage = state.stage
			if !state.upstream || state.transportFailure {
				diag.Origin = "router"
			}
			if state.transportFailure {
				diag.Stage = "upstream_transport"
			}
			if !rec.capture {
				diag.OmissionReason = "streaming"
			}
			response = &diag
		}
		if !state.verified {
			beforeState = nil
		}
		meta := auditcore.EncodeHTTPMetadata(metaMap, response)

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
