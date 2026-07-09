package router

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	auditcore "github.com/ledatu/csar-core/audit"
	"github.com/ledatu/csar/internal/config"
)

type stubAuditRecorder struct {
	events []*auditcore.Event
}

func (s *stubAuditRecorder) Record(_ context.Context, ev *auditcore.Event) {
	evCopy := *ev
	s.events = append(s.events, &evCopy)
}

func TestShouldEmitAudit(t *testing.T) {
	if !shouldEmitAudit(config.AuditModeAll, http.StatusOK) {
		t.Fatal("all should emit 200")
	}
	if shouldEmitAudit(config.AuditModeErrors, http.StatusOK) {
		t.Fatal("errors should skip 200")
	}
	if !shouldEmitAudit(config.AuditModeErrors, http.StatusInternalServerError) {
		t.Fatal("errors should emit 500")
	}
	if shouldEmitAudit(config.AuditModeOff, http.StatusInternalServerError) {
		t.Fatal("off should never emit")
	}
}

func TestWrapUpstreamWithAuditModes(t *testing.T) {
	recorder := &stubAuditRecorder{}
	r := &Router{auditClient: recorder}

	makeHandler := func(mode config.AuditMode, status int) http.Handler {
		rt := &route{
			auditMode:    mode,
			routeKey:     "GET /test",
			originalPath: "/test",
			method:       http.MethodGet,
		}
		return r.wrapUpstreamWithAudit(rt, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(status)
		}))
	}

	httptest.NewRecorder().Result()
	req := httptest.NewRequest(http.MethodGet, "/test", nil)

	w := httptest.NewRecorder()
	makeHandler(config.AuditModeAll, http.StatusOK).ServeHTTP(w, req)
	if len(recorder.events) != 1 {
		t.Fatalf("all mode: events = %d", len(recorder.events))
	}

	recorder.events = nil
	w = httptest.NewRecorder()
	makeHandler(config.AuditModeErrors, http.StatusOK).ServeHTTP(w, req)
	if len(recorder.events) != 0 {
		t.Fatalf("errors mode 200: events = %d", len(recorder.events))
	}

	w = httptest.NewRecorder()
	makeHandler(config.AuditModeErrors, http.StatusBadGateway).ServeHTTP(w, req)
	if len(recorder.events) != 1 {
		t.Fatalf("errors mode 502: events = %d", len(recorder.events))
	}

	var meta map[string]any
	if err := json.Unmarshal(recorder.events[0].Metadata, &meta); err != nil {
		t.Fatal(err)
	}
	if meta["audit_mode"] != "errors" {
		t.Fatalf("audit_mode = %v", meta["audit_mode"])
	}
}

func TestWrapUpstreamWithAuditCapture(t *testing.T) {
	recorder := &stubAuditRecorder{}
	reqTrue := true
	r := &Router{auditClient: recorder}

	rt := &route{
		auditMode: config.AuditModeErrors,
		auditCapture: &config.AuditCaptureConfig{
			Request:  &reqTrue,
			MaxBytes: 4096,
			Mask:     "[REDACTED]",
			Fields:   []string{"wbToken"},
		},
		routeKey:     "POST /test",
		originalPath: "/test",
		method:       http.MethodPost,
	}

	handler := r.wrapUpstreamWithAudit(rt, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnprocessableEntity)
	}))

	body := `{"password":"secret","name":"item"}`
	req := httptest.NewRequest(http.MethodPost, "/test?token=abc&wbToken=secret", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-User-Email", "user@example.com")

	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if len(recorder.events) != 1 {
		t.Fatalf("events = %d", len(recorder.events))
	}

	ev := recorder.events[0]
	var state map[string]any
	if err := json.Unmarshal(ev.BeforeState, &state); err != nil {
		t.Fatal(err)
	}
	if state["password"] != "[REDACTED]" {
		t.Fatalf("password = %v", state["password"])
	}

	var meta map[string]any
	if err := json.Unmarshal(ev.Metadata, &meta); err != nil {
		t.Fatal(err)
	}
	if meta["actor_email"] != "user@example.com" {
		t.Fatalf("actor_email = %v", meta["actor_email"])
	}
	query := meta["query"].(map[string]any)
	if query["token"] != "[REDACTED]" {
		t.Fatalf("query token = %v", query["token"])
	}
	if query["wbToken"] != "[REDACTED]" {
		t.Fatalf("query wbToken = %v", query["wbToken"])
	}

	recorder.events = nil
	successHandler := r.wrapUpstreamWithAudit(rt, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	req2 := httptest.NewRequest(http.MethodPost, "/test", strings.NewReader(body))
	req2.Header.Set("Content-Type", "application/json")
	w2 := httptest.NewRecorder()
	successHandler.ServeHTTP(w2, req2)
	if len(recorder.events) != 0 {
		t.Fatal("expected no event on 200 for errors mode")
	}
}

func TestWrapUpstreamWithAuditGETErrorsCapture(t *testing.T) {
	recorder := &stubAuditRecorder{}
	reqTrue := true
	r := &Router{auditClient: recorder}

	rt := &route{
		auditMode: config.AuditModeErrors,
		auditCapture: &config.AuditCaptureConfig{
			Request:  &reqTrue,
			MaxBytes: 4096,
			Mask:     "[REDACTED]",
		},
		routeKey:     "GET /test",
		originalPath: "/test",
		method:       http.MethodGet,
	}

	handler := r.wrapUpstreamWithAudit(rt, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))

	req := httptest.NewRequest(http.MethodGet, "/test?campaignId=42", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if len(recorder.events) != 1 {
		t.Fatalf("events = %d", len(recorder.events))
	}

	ev := recorder.events[0]
	if len(ev.BeforeState) != 0 {
		t.Fatalf("before_state = %s, want empty for GET", ev.BeforeState)
	}

	var meta map[string]any
	if err := json.Unmarshal(ev.Metadata, &meta); err != nil {
		t.Fatal(err)
	}
	query := meta["query"].(map[string]any)
	if query["campaignId"] != "42" {
		t.Fatalf("query campaignId = %v", query["campaignId"])
	}
}

func TestWrapUpstreamWithAuditNoRedactionCapture(t *testing.T) {
	recorder := &stubAuditRecorder{}
	reqTrue := true
	r := &Router{auditClient: recorder}

	rt := &route{
		auditMode: config.AuditModeAll,
		auditCapture: &config.AuditCaptureConfig{
			Request:  &reqTrue,
			MaxBytes: 4096,
		},
		routeKey:     "POST /test",
		originalPath: "/test",
		method:       http.MethodPost,
	}

	handler := r.wrapUpstreamWithAudit(rt, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	body := `{"password":"secret","name":"item"}`
	req := httptest.NewRequest(http.MethodPost, "/test?token=abc", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if len(recorder.events) != 1 {
		t.Fatalf("events = %d", len(recorder.events))
	}

	ev := recorder.events[0]
	var state map[string]any
	if err := json.Unmarshal(ev.BeforeState, &state); err != nil {
		t.Fatal(err)
	}
	if state["password"] != "secret" {
		t.Fatalf("password = %v", state["password"])
	}

	var meta map[string]any
	if err := json.Unmarshal(ev.Metadata, &meta); err != nil {
		t.Fatal(err)
	}
	query := meta["query"].(map[string]any)
	if query["token"] != "abc" {
		t.Fatalf("query token = %v", query["token"])
	}
}

func TestReadRequestBodyForAuditRewrapsBody(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader("hello"))
	body, _, truncated, err := readRequestBodyForAudit(req, 1024)
	if err != nil {
		t.Fatal(err)
	}
	if truncated || string(body) != "hello" {
		t.Fatalf("body=%q truncated=%v", body, truncated)
	}
	reread, err := io.ReadAll(req.Body)
	if err != nil {
		t.Fatal(err)
	}
	if string(reread) != "hello" {
		t.Fatalf("rewrapped body = %q", reread)
	}
}
