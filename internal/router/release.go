package router

import (
	"context"
	"net/http"
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
	fresh := func() bool {
		source, present := authn.SourceFromContext(req.Context())
		return req.Context().Err() == nil && (!present || time.Now().Before(source.ValidUntil)) && validateOriginResource(req) == nil
	}
	if !fresh() {
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
	if !fresh() {
		apierror.New(apierror.CodeAuthFailed, http.StatusUnauthorized, "protected release context expired").Write(w)
		return false
	}
	return true
}

func (r *Router) releaseUnavailable(w http.ResponseWriter, req *http.Request) {
	w.Header().Set("X-CSAR-Status", "audit_unavailable")
	w.Header().Set("Retry-After", "1")
	apierror.New("audit_unavailable", http.StatusServiceUnavailable, "audit release receipt unavailable").WithRetryAfterMS(1000).WithRequestID(r.requestID(req)).Write(w)
}
