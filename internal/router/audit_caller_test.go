package router

import (
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/ledatu/csar-core/caller"
	"github.com/ledatu/csar-core/gatewayctx"
	"github.com/ledatu/csar/internal/config"
	"go.opentelemetry.io/otel/trace"
)

func TestAuditCurrentCallerOnColdCacheHitAndDeniedRequests(t *testing.T) {
	issuer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie("session")
		if err != nil || cookie.Value == "denied" {
			w.WriteHeader(401)
			return
		}
		id := &caller.Identity{Version: 1, CallerKind: caller.Human, CallerID: cookie.Value, OwnerSubject: cookie.Value, EffectiveSubject: cookie.Value, CredentialKind: caller.Session, Assurance: caller.Verified}
		w.Header().Set(gatewayctx.HeaderSubject, cookie.Value)
		w.Header().Set(gatewayctx.HeaderTenant, "tenant")
		if err := gatewayctx.SetCaller(w.Header(), id); err != nil {
			t.Error(err)
		}
	}))
	defer issuer.Close()
	var calls atomic.Int32
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{}`))
	}))
	defer backend.Close()
	cfg := newTestConfig(map[string]config.PathConfig{"/report": {"get": {
		Backend: config.BackendConfig{TargetURL: backend.URL}, AuthValidate: &config.AuthValidateConfig{Mode: "session", SessionEndpoint: issuer.URL, CookieName: "session", ForwardHeaders: []string{gatewayctx.HeaderTenant}},
		Cache: &config.CacheConfig{Key: "report:{tenant}", TTL: config.Duration{Duration: time.Minute}},
	}}})
	router, err := New(cfg, newTestLogger())
	if err != nil {
		t.Fatal(err)
	}
	recorder := &stubAuditRecorder{}
	router.auditClient = recorder
	rt, _ := router.matchRoute("GET", "/report")
	rt.auditMode = config.AuditModeAll
	span := trace.NewSpanContext(trace.SpanContextConfig{TraceID: trace.TraceID{1}, SpanID: trace.SpanID{1}})
	operations := make(map[string]bool)
	for i, subject := range []string{"first", "second", "denied"} {
		r := httptest.NewRequest("GET", "/report", nil)
		r.AddCookie(&http.Cookie{Name: "session", Value: subject})
		r.Header.Set(gatewayctx.HeaderSubject, "forged")
		r.Header.Set(gatewayctx.HeaderCaller, "forged")
		r.Header.Set(gatewayctx.HeaderOriginCaller, "forged")
		r.Header.Set("X-Gateway-Operation-ID", "forged")
		r = r.WithContext(trace.ContextWithSpanContext(r.Context(), span))
		w := httptest.NewRecorder()
		router.ServeHTTP(w, r)
		if len(recorder.events) != i+1 {
			t.Fatal("request missing audit event")
		}
		event := recorder.events[i]
		if _, err := uuid.Parse(event.OperationID); err != nil || operations[event.OperationID] || event.TraceID != span.TraceID().String() || event.OriginCaller != nil || event.ParentOperationID != "" {
			t.Fatal("forged/reused operation or trace context", err)
		}
		operations[event.OperationID] = true
		if subject == "denied" {
			if w.Code != 401 || event.Caller != nil || event.Actor != "anonymous" {
				t.Fatal("denial trusted caller headers")
			}
		} else if w.Code != 200 || event.Caller == nil || event.Caller.CallerID != subject || event.Actor != subject {
			t.Fatal("cache reused prior request caller")
		}
		if i == 1 && w.Header().Get("X-CSAR-Cache") != "HIT" {
			t.Fatal("expected warm report cache")
		}
	}
	if calls.Load() != 1 {
		t.Fatal("unexpected backend calls", calls.Load())
	}
}
