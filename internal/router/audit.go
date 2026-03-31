package router

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"

	auditcore "github.com/ledatu/csar-core/audit"
	"github.com/ledatu/csar-core/gatewayctx"
)

func defaultAuditForMutatingMethod(method string) bool {
	switch strings.ToUpper(method) {
	case http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete:
		return true
	default:
		return false
	}
}

const routerAuditServiceName = "csar-router"

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
	if r.auditClient == nil || !rt.auditEnabled {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		rec := &auditResponseCapture{ResponseWriter: w, statusCode: http.StatusOK}
		next.ServeHTTP(rec, req)

		gw := gatewayctx.FromRequest(req)
		clientIP := extractClientIP(req, rt.trustProxy)

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

		meta, err := json.Marshal(map[string]any{
			"http_status": rec.statusCode,
			"route":       rt.routeKey,
		})
		if err != nil {
			meta = nil
		}

		ev := &auditcore.Event{
			Service:    routerAuditServiceName,
			Actor:      actor,
			Action:     req.Method + " " + rt.originalPath,
			TargetType: "path",
			TargetID:   req.URL.Path,
			ScopeType:  scopeType,
			ScopeID:    scopeID,
			Metadata:   meta,
			RequestID:  r.requestID(req),
			ClientIP:   clientIP,
			CreatedAt:  time.Now().UTC(),
		}
		r.auditClient.Record(req.Context(), ev)
	})
}
