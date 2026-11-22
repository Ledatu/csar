package router

import (
	"context"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	auditcore "github.com/ledatu/csar-core/audit"
	"github.com/ledatu/csar/internal/apierror"
	"github.com/ledatu/csar/internal/authn"
	"go.opentelemetry.io/otel/trace"
)

type receiptRecorder interface {
	RecordSync(context.Context, *auditcore.Event) error
}

// confirmReadRelease records authorization to attempt a protected release before
// cache/backend dispatch. It does not assert payload existence or delivery. The
// separate final event links this receipt, including when dispatch later fails.
func (r *Router) confirmReadRelease(w http.ResponseWriter, req *http.Request, rt *route) bool {
	if !rt.config.AuditRelease {
		return true
	}
	state := auditState(req)
	if state == nil || !state.verified || state.identity.Subject == "" || isStreamingRequest(req) {
		apierror.New(apierror.CodeAccessDenied, http.StatusForbidden, "protected release requires verified non-streaming access").Write(w)
		return false
	}
	// Do not publish an authorization that has already outlived its source lease.
	if !releaseContextFresh(req) {
		apierror.New(apierror.CodeAuthFailed, http.StatusUnauthorized, "protected release context expired").Write(w)
		return false
	}
	event := &auditcore.Event{ID: uuid.NewString(), CreatedAt: time.Now().UTC(), Service: routerAuditServiceName, Actor: state.identity.Subject, Action: "read.release_authorized", TargetType: "route", TargetID: rt.routeKey, ScopeType: "platform", ScopeID: state.identity.Tenant, Caller: state.identity.Caller, OriginCaller: state.originCaller, OperationID: state.operationID, ParentOperationID: state.parentOperationID, RequestID: r.requestID(req)}
	if event.ScopeID != "" {
		event.ScopeType = "tenant"
	}
	event.Metadata = auditcore.EncodeHTTPMetadata(map[string]any{"phase": "release_authorized", "route": rt.routeKey}, nil)
	if span := trace.SpanContextFromContext(req.Context()); span.IsValid() {
		event.TraceID = span.TraceID().String()
	}
	ctx, cancel := context.WithTimeout(req.Context(), time.Second)
	defer cancel()
	recorder, ok := r.auditClient.(receiptRecorder)
	if !ok {
		r.releaseUnavailable(w, req)
		return false
	}
	if err := recorder.RecordSync(ctx, event); err != nil || ctx.Err() != nil {
		r.releaseUnavailable(w, req)
		return false
	}
	state.releaseEventID = event.ID
	if !releaseContextFresh(req) {
		apierror.New(apierror.CodeAuthFailed, http.StatusUnauthorized, "protected release context expired").Write(w)
		return false
	}
	return true
}

func releaseContextFresh(req *http.Request) bool {
	source, present := authn.SourceFromContext(req.Context())
	return req.Context().Err() == nil && (!present || time.Now().Before(source.ValidUntil)) && validateOriginResource(req) == nil
}

// A confirmed authorization can expire while the cache or backend is working.
// Stage headers and check freshness at every release boundary, without buffering
// response bodies. No Unwrap/Hijack escape is exposed on protected responses.
type releaseWriter struct {
	http.ResponseWriter
	header           http.Header
	fresh            func() bool
	written, blocked bool
}

func (w *releaseWriter) Header() http.Header { return w.header }
func (w *releaseWriter) WriteHeader(status int) {
	if w.written || status < 200 {
		return
	}
	w.written = true
	if !w.fresh() {
		w.blocked = true
		clear(w.ResponseWriter.Header())
		apierror.New(apierror.CodeAuthFailed, http.StatusUnauthorized, "protected release context expired").Write(w.ResponseWriter)
		return
	}
	stripOriginResponseHeaders(w.header)
	for name, values := range w.header {
		w.ResponseWriter.Header()[name] = append([]string(nil), values...)
	}
	w.ResponseWriter.WriteHeader(status)
}
func (w *releaseWriter) Write(body []byte) (int, error) {
	if !w.written {
		w.WriteHeader(http.StatusOK)
	}
	if w.blocked || !w.fresh() {
		w.blocked = true
		return 0, context.DeadlineExceeded
	}
	return w.ResponseWriter.Write(body)
}
func (w *releaseWriter) FlushError() error {
	if !w.written {
		w.WriteHeader(http.StatusOK)
	}
	if w.blocked || !w.fresh() {
		return context.DeadlineExceeded
	}
	return http.NewResponseController(w.ResponseWriter).Flush()
}
func (w *releaseWriter) finish() {
	if !w.written {
		w.WriteHeader(http.StatusOK)
	}
	if w.blocked || !w.fresh() {
		return
	}
	stripOriginResponseHeaders(w.header)
	// Only declared trailers and the net/http late-trailer mechanism may change
	// headers after commitment. Expired requests publish no additional trailers.
	for _, value := range w.ResponseWriter.Header().Values("Trailer") {
		for _, name := range strings.Split(value, ",") {
			name = http.CanonicalHeaderKey(strings.TrimSpace(name))
			if values := w.header.Values(name); len(values) > 0 {
				w.ResponseWriter.Header()[name] = append([]string(nil), values...)
			}
		}
	}
	for name, values := range w.header {
		if strings.HasPrefix(name, http.TrailerPrefix) {
			w.ResponseWriter.Header()[name] = append([]string(nil), values...)
		}
	}
}

func (r *Router) serveProtectedRelease(w http.ResponseWriter, req *http.Request, rt *route) {
	handler := r.upstreamHandler(rt)
	if !rt.config.AuditRelease {
		handler.ServeHTTP(w, req)
		return
	}
	guard := &releaseWriter{ResponseWriter: w, header: w.Header().Clone(), fresh: func() bool { return releaseContextFresh(req) }}
	defer guard.finish()
	handler.ServeHTTP(guard, req)
}

func (r *Router) releaseUnavailable(w http.ResponseWriter, req *http.Request) {
	w.Header().Set("X-CSAR-Status", "audit_unavailable")
	w.Header().Set("Retry-After", "1")
	apierror.New("audit_unavailable", http.StatusServiceUnavailable, "audit release receipt unavailable").WithRetryAfterMS(1000).WithRequestID(r.requestID(req)).Write(w)
}
