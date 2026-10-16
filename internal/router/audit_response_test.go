package router

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	auditcore "github.com/ledatu/csar-core/audit"
	"github.com/ledatu/csar-core/gatewayctx"
	"github.com/ledatu/csar/internal/config"
	"github.com/ledatu/csar/internal/resilience"
)

func TestAuditedRoutesCaptureErrorsByDefault(t *testing.T) {
	all, errorsOnly, off := config.AuditModeAll, config.AuditModeErrors, config.AuditModeOff
	for _, tc := range []struct {
		name       string
		method     string
		mode       *config.AuditMode
		capture    *config.AuditCaptureConfig
		status     int
		wantEvents int
		wantBody   bool
	}{
		{"errors without capture", "GET", &errorsOnly, nil, 403, 1, true},
		{"all without capture", "GET", &all, nil, 503, 1, true},
		{"implicit mutation audit", "POST", nil, nil, 403, 1, true},
		{"empty capture block", "GET", &errorsOnly, &config.AuditCaptureConfig{}, 403, 1, true},
		{"explicit response off", "GET", &errorsOnly, &config.AuditCaptureConfig{Response: "off"}, 403, 1, false},
		{"audit off", "POST", &off, nil, 403, 0, false},
		{"implicit read audit off", "GET", nil, nil, 403, 0, false},
		{"errors skips success", "GET", &errorsOnly, nil, 200, 0, false},
		{"all keeps success event only", "GET", &all, nil, 200, 1, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			body := `{"code":"denied","message":"Authorization: Bearer privatecredential","apiKey":"privatecredential","business_data":"must not persist"}`
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
				if tc.method == "POST" {
					b, err := io.ReadAll(req.Body)
					if err != nil || string(b) != `{"requestSecret":"must not persist"}` {
						t.Error("request body changed")
					}
				}
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(tc.status)
				_, _ = io.WriteString(w, body)
			}))
			defer upstream.Close()
			cfg := newTestConfig(map[string]config.PathConfig{"/test": {strings.ToLower(tc.method): {
				Backend: config.BackendConfig{TargetURL: upstream.URL}, Audit: tc.mode, AuditCapture: tc.capture,
			}}})
			recorder := &stubAuditRecorder{}
			r, err := New(cfg, newTestLogger(), func(r *Router) { r.auditClient = recorder })
			if err != nil {
				t.Fatal(err)
			}
			defer r.Close()
			req := httptest.NewRequest(tc.method, "/test?querySecret=must-not-persist", strings.NewReader(`{"requestSecret":"must not persist"}`))
			req.Header.Set("Authorization", "Bearer privatecredential")
			w := httptest.NewRecorder()
			r.ServeHTTP(w, req)
			if w.Code != tc.status || w.Body.String() != body || len(recorder.events) != tc.wantEvents {
				t.Fatalf("status=%d body=%s events=%d", w.Code, w.Body.String(), len(recorder.events))
			}
			if tc.wantEvents == 0 {
				return
			}
			event := recorder.events[0]
			var meta struct {
				Response *auditcore.HTTPResponse `json:"http_response"`
				Query    map[string]any          `json:"query"`
			}
			if err := json.Unmarshal(event.Metadata, &meta); err != nil {
				t.Fatal(err)
			}
			if tc.wantBody {
				if meta.Response == nil || meta.Response.Status != tc.status || meta.Response.State != "captured" || meta.Response.Code != "denied" {
					t.Fatalf("missing safe error diagnostics: %+v", meta.Response)
				}
				if strings.Contains(string(event.Metadata), "privatecredential") || strings.Contains(string(event.Metadata), "business_data") {
					t.Fatal("unsafe response fields persisted")
				}
			} else if meta.Response != nil {
				t.Fatalf("unexpected response diagnostics: %+v", meta.Response)
			}
			if len(event.BeforeState) != 0 || (tc.capture == nil && len(meta.Query) != 0) {
				t.Fatal("response defaults enabled request or query capture")
			}
		})
	}
}

func TestAuditResponseBoundedAndUnchanged(t *testing.T) {
	for _, tc := range []struct {
		name            string
		status          int
		ct, body, state string
	}{
		{"error", 503, "application/json", `{"code":"unavailable","message":"Authorization: Bearer privatecredential","password":"hidden"}`, "captured"},
		{"success", 200, "application/json", `{"secret":"success must not be copied"}`, ""},
		{"empty", 500, "application/json", "", "empty"},
		{"html", 502, "text/html", "<html>private</html>", "omitted"},
		{"large", 503, "application/json", `{"message":"` + strings.Repeat("a", auditcore.MaxHTTPInspectBytes) + `"}`, "omitted"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			recorder := &stubAuditRecorder{}
			r := &Router{auditClient: recorder}
			rt := &route{auditMode: config.AuditModeAll, auditCapture: &config.AuditCaptureConfig{Response: "errors"}, method: "GET", originalPath: "/test"}
			h := r.wrapUpstreamWithAudit(rt, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", tc.ct)
				w.WriteHeader(tc.status)
				_, _ = io.WriteString(w, tc.body)
			}))
			w := httptest.NewRecorder()
			h.ServeHTTP(w, httptest.NewRequest("GET", "/test", nil))
			if w.Code != tc.status || w.Body.String() != tc.body || len(recorder.events) != 1 {
				t.Fatal("changed client response or duplicated audit")
			}
			var meta struct {
				Response *auditcore.HTTPResponse `json:"http_response"`
			}
			if err := json.Unmarshal(recorder.events[0].Metadata, &meta); err != nil {
				t.Fatal(err)
			}
			if tc.state == "" {
				if meta.Response != nil {
					t.Fatal("captured success")
				}
				return
			}
			if meta.Response == nil || meta.Response.State != tc.state {
				t.Fatalf("response=%+v", meta.Response)
			}
			if strings.Contains(string(recorder.events[0].Metadata), "privatecredential") || strings.Contains(string(recorder.events[0].Metadata), "hidden") {
				t.Fatal("credential leak")
			}
		})
	}
}

func TestAuditResponseRecordsEarlyDenialWithoutSpoofedIdentity(t *testing.T) {
	cfg := newTestConfig(map[string]config.PathConfig{"/private": {"get": config.RouteConfig{Backend: config.BackendConfig{TargetURL: "http://127.0.0.1:1"}}}})
	r, err := New(cfg, newTestLogger())
	if err != nil {
		t.Fatal(err)
	}
	recorder := &stubAuditRecorder{}
	r.auditClient = recorder
	rt, _ := r.matchRoute("GET", "/private")
	rt.auditMode = config.AuditModeAll
	rt.auditCapture = nil
	rt.hasRouteACL = true
	_, cidr, err := net.ParseCIDR("203.0.113.0/24")
	if err != nil {
		t.Fatal(err)
	}
	rt.allowCIDRs = []*net.IPNet{cidr}
	req := httptest.NewRequest("GET", "/private", nil)
	req.Header.Set("X-Gateway-Subject", "spoofed")
	req.Header.Set("X-Gateway-Tenant", "spoofed")
	req.Header.Set("X-User-Email", "spoofed@example.com")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != 403 || len(recorder.events) != 1 {
		t.Fatalf("status=%d events=%d", w.Code, len(recorder.events))
	}
	event := recorder.events[0]
	if event.Actor != "anonymous" || event.ScopeID != "" || strings.Contains(string(event.Metadata), "spoofed") {
		t.Fatal("trusted client identity")
	}
	var meta struct {
		Response auditcore.HTTPResponse `json:"http_response"`
	}
	if err := json.Unmarshal(event.Metadata, &meta); err != nil {
		t.Fatal(err)
	}
	if meta.Response.Origin != "router" || meta.Response.Code != "access_denied" {
		t.Fatalf("%+v", meta.Response)
	}
}

func TestAuditWriterFirstFinalStatusAndReaderFrom(t *testing.T) {
	w := httptest.NewRecorder()
	capture := &auditResponseCapture{ResponseWriter: w, statusCode: 200, capture: true}
	capture.WriteHeader(503)
	capture.WriteHeader(200)
	if _, err := capture.ReadFrom(strings.NewReader(`{"message":"down"}`)); err != nil {
		t.Fatal(err)
	}
	if capture.statusCode != 503 || string(capture.body) != `{"message":"down"}` {
		t.Fatalf("status=%d body=%s", capture.statusCode, capture.body)
	}
}

func TestAuditWriterInformationalResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		capture := &auditResponseCapture{ResponseWriter: w, statusCode: 200, capture: true}
		capture.WriteHeader(103)
		capture.WriteHeader(503)
		capture.WriteHeader(200)
		if _, err := io.WriteString(capture, `{"message":"down"}`); err != nil {
			t.Error(err)
		}
		if capture.statusCode != 503 {
			t.Error("lost final status")
		}
	}))
	defer server.Close()
	response, err := http.Get(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = response.Body.Close() }()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != 503 || string(body) != `{"message":"down"}` {
		t.Fatalf("status=%d body=%s", response.StatusCode, body)
	}
}

func TestAuditValidatedSessionIdentity(t *testing.T) {
	for _, valid := range []bool{false, true} {
		t.Run(map[bool]string{false: "denied", true: "allowed"}[valid], func(t *testing.T) {
			auth := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				if !valid {
					w.WriteHeader(http.StatusUnauthorized)
					return
				}
				w.Header().Set(gatewayctx.HeaderSubject, "verified-user")
				w.Header().Set(gatewayctx.HeaderTenant, "verified-tenant")
				w.Header().Set(actorEmailHeader, "verified@example.com")
			}))
			defer auth.Close()
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusServiceUnavailable)
				_, _ = io.WriteString(w, `{"message":"down"}`)
			}))
			defer upstream.Close()
			cfg := newTestConfig(map[string]config.PathConfig{"/private": {"get": {
				Backend:      config.BackendConfig{TargetURL: upstream.URL},
				AuthValidate: &config.AuthValidateConfig{Mode: "session", SessionEndpoint: auth.URL, CookieName: "session", ForwardHeaders: []string{gatewayctx.HeaderSubject, gatewayctx.HeaderTenant, actorEmailHeader}},
			}}})
			r, err := New(cfg, newTestLogger())
			if err != nil {
				t.Fatal(err)
			}
			recorder := &stubAuditRecorder{}
			r.auditClient = recorder
			rt, _ := r.matchRoute("GET", "/private")
			rt.auditMode = config.AuditModeAll
			rt.auditCapture = &config.AuditCaptureConfig{Response: "errors"}
			req := httptest.NewRequest("GET", "/private", nil)
			req.AddCookie(&http.Cookie{Name: "session", Value: "session-token"})
			req.Header.Set(gatewayctx.HeaderSubject, "spoofed")
			req.Header.Set(gatewayctx.HeaderTenant, "spoofed")
			req.Header.Set(actorEmailHeader, "spoofed@example.com")
			w := httptest.NewRecorder()
			r.ServeHTTP(w, req)
			if len(recorder.events) != 1 {
				t.Fatalf("events=%d", len(recorder.events))
			}
			event := recorder.events[0]
			if strings.Contains(string(event.Metadata), "spoofed") {
				t.Fatal("spoofed email recorded")
			}
			if valid {
				if event.Actor != "verified-user" || event.ScopeID != "verified-tenant" || !strings.Contains(string(event.Metadata), "verified@example.com") || w.Code != 503 {
					t.Fatalf("event=%+v status=%d", event, w.Code)
				}
			} else if event.Actor != "anonymous" || event.ScopeID != "" || w.Code != 401 {
				t.Fatalf("event=%+v status=%d", event, w.Code)
			}
		})
	}
}

func TestAuditPreflightRemainsUnrecorded(t *testing.T) {
	recorder := &stubAuditRecorder{}
	r := &Router{auditClient: recorder}
	rt := &route{auditMode: config.AuditModeAll, corsConfig: &config.CORSConfig{}, auditCapture: &config.AuditCaptureConfig{Response: "errors"}}
	h := r.wrapUpstreamWithAudit(rt, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) }))
	req := httptest.NewRequest("OPTIONS", "/test", nil)
	req.Header.Set("Origin", "https://example.com")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != 204 || len(recorder.events) != 0 {
		t.Fatal("preflight changed or audited")
	}
}

func TestAuditProxyTransportFailureAndRetrySuccess(t *testing.T) {
	for _, retry := range []bool{false, true} {
		t.Run(map[bool]string{false: "transport", true: "retry-success"}[retry], func(t *testing.T) {
			var calls atomic.Int32
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				if calls.Add(1) == 1 {
					w.WriteHeader(503)
					_, _ = io.WriteString(w, `{"message":"temporary"}`)
					return
				}
				_, _ = io.WriteString(w, `{"ok":true}`)
			}))
			defer upstream.Close()
			target := upstream.URL
			if !retry {
				upstream.Close()
			}
			routeConfig := config.RouteConfig{Backend: config.BackendConfig{TargetURL: target}}
			if retry {
				routeConfig.Retry = &config.RetryConfig{MaxAttempts: 2, Backoff: config.Duration{Duration: time.Millisecond}, MaxBackoff: config.Duration{Duration: time.Millisecond}}
			}
			r, err := New(newTestConfig(map[string]config.PathConfig{"/test": {"get": routeConfig}}), newTestLogger())
			if err != nil {
				t.Fatal(err)
			}
			recorder := &stubAuditRecorder{}
			r.auditClient = recorder
			rt, _ := r.matchRoute("GET", "/test")
			rt.auditMode = config.AuditModeAll
			rt.auditCapture = &config.AuditCaptureConfig{Response: "errors"}
			w := httptest.NewRecorder()
			r.ServeHTTP(w, httptest.NewRequest("GET", "/test", nil))
			if len(recorder.events) != 1 {
				t.Fatalf("events=%d", len(recorder.events))
			}
			var meta struct {
				Response *auditcore.HTTPResponse `json:"http_response"`
			}
			if err := json.Unmarshal(recorder.events[0].Metadata, &meta); err != nil {
				t.Fatal(err)
			}
			if retry {
				if w.Code != 200 || calls.Load() != 2 || meta.Response != nil {
					t.Fatalf("status=%d calls=%d response=%+v", w.Code, calls.Load(), meta.Response)
				}
			} else if w.Code != 502 || meta.Response == nil || meta.Response.Origin != "router" || meta.Response.Stage != "upstream_transport" {
				t.Fatalf("status=%d response=%+v", w.Code, meta.Response)
			}
		})
	}
}

type auditFailWriter struct{ header http.Header }

func (w *auditFailWriter) Header() http.Header       { return w.header }
func (*auditFailWriter) WriteHeader(int)             {}
func (*auditFailWriter) Write(b []byte) (int, error) { return len(b) / 2, io.ErrUnexpectedEOF }
func (*auditFailWriter) FlushError() error           { return io.ErrClosedPipe }

func TestAuditWriterPartialWriteAndFlushError(t *testing.T) {
	underlying := &auditFailWriter{header: make(http.Header)}
	capture := &auditResponseCapture{ResponseWriter: underlying, statusCode: 200, capture: true}
	capture.WriteHeader(503)
	body := []byte(`{"message":"partial"}`)
	n, err := capture.Write(body)
	if !errors.Is(err, io.ErrUnexpectedEOF) || n != len(body)/2 || !capture.failed || capture.observedBytes != int64(n) || string(capture.body) != string(body[:n]) {
		t.Fatalf("n=%d err=%v capture=%+v", n, err, capture)
	}
	if err := http.NewResponseController(capture).Flush(); !errors.Is(err, io.ErrClosedPipe) {
		t.Fatalf("flush err=%v", err)
	}
	if capture.capture || len(capture.body) != 0 {
		t.Fatal("flushed response captured as complete JSON")
	}
}

func TestAuditAdmissionDenialsAreRecordedOnce(t *testing.T) {
	for _, circuit := range []bool{false, true} {
		t.Run(map[bool]string{false: "throttle", true: "circuit"}[circuit], func(t *testing.T) {
			var calls atomic.Int32
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { calls.Add(1); w.WriteHeader(200) }))
			defer upstream.Close()
			cfgRoute := config.RouteConfig{Backend: config.BackendConfig{TargetURL: upstream.URL}}
			if !circuit {
				cfgRoute.Traffic = &config.TrafficConfig{RPS: 1, Burst: 1, MaxWait: config.Duration{Duration: time.Millisecond}}
			}
			r, err := New(newTestConfig(map[string]config.PathConfig{"/test": {"get": cfgRoute}}), newTestLogger())
			if err != nil {
				t.Fatal(err)
			}
			rt, _ := r.matchRoute("GET", "/test")
			if circuit {
				rt.circuitBreaker = resilience.NewCircuitBreaker("test", resilience.CircuitBreakerConfig{FailureThreshold: 1, Timeout: time.Hour})
				_ = rt.circuitBreaker.Execute(func() error { return errors.New("force open") })
			} else {
				r.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("GET", "/test", nil))
				calls.Store(0)
			}
			recorder := &stubAuditRecorder{}
			r.auditClient = recorder
			rt.auditMode = config.AuditModeAll
			rt.auditCapture = &config.AuditCaptureConfig{Response: "errors"}
			w := httptest.NewRecorder()
			r.ServeHTTP(w, httptest.NewRequest("GET", "/test", nil))
			if w.Code != 503 || len(recorder.events) != 1 || calls.Load() != 0 {
				t.Fatalf("status=%d events=%d upstream=%d", w.Code, len(recorder.events), calls.Load())
			}
			var meta struct {
				Response auditcore.HTTPResponse `json:"http_response"`
			}
			if err := json.Unmarshal(recorder.events[0].Metadata, &meta); err != nil {
				t.Fatal(err)
			}
			if meta.Response.Origin != "router" || meta.Response.Stage != "admission" || meta.Response.State != "captured" {
				t.Fatalf("response=%+v", meta.Response)
			}
		})
	}
}

func TestAuditFlushOmitsResponseBody(t *testing.T) {
	recorder := &stubAuditRecorder{}
	r := &Router{auditClient: recorder}
	rt := &route{method: "GET", auditMode: config.AuditModeAll, auditCapture: &config.AuditCaptureConfig{Response: "errors"}}
	h := r.wrapUpstreamWithAudit(rt, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(503)
		_, _ = io.WriteString(w, `{"message":"streamed"}`)
		if err := http.NewResponseController(w).Flush(); err != nil {
			t.Error(err)
		}
	}))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest("GET", "/test", nil))
	if w.Body.String() != `{"message":"streamed"}` || !w.Flushed || len(recorder.events) != 1 {
		t.Fatal("changed streaming response")
	}
	var meta struct {
		Response auditcore.HTTPResponse `json:"http_response"`
	}
	if err := json.Unmarshal(recorder.events[0].Metadata, &meta); err != nil {
		t.Fatal(err)
	}
	if meta.Response.OmissionReason != "streaming" || meta.Response.State != "omitted" || meta.Response.Body != "" || meta.Response.CaptureComplete {
		t.Fatalf("response=%+v", meta.Response)
	}
}

type auditChannelRecorder chan *auditcore.Event

func (c auditChannelRecorder) Record(_ context.Context, event *auditcore.Event) { c <- event }

func TestAuditUpgradeRemainsUnbufferedAndRecords101(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		conn, rw, err := http.NewResponseController(w).Hijack()
		if err != nil {
			t.Error(err)
			return
		}
		defer func() { _ = conn.Close() }()
		_, _ = io.WriteString(rw, "HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n")
		if err := rw.Flush(); err != nil {
			t.Error(err)
		}
	}))
	defer upstream.Close()
	r, err := New(newTestConfig(map[string]config.PathConfig{"/socket": {"get": {Backend: config.BackendConfig{TargetURL: upstream.URL}}}}), newTestLogger())
	if err != nil {
		t.Fatal(err)
	}
	recorder := make(auditChannelRecorder, 1)
	r.auditClient = recorder
	rt, _ := r.matchRoute("GET", "/socket")
	rt.auditMode = config.AuditModeAll
	rt.auditCapture = &config.AuditCaptureConfig{Response: "errors"}
	server := httptest.NewServer(r)
	defer server.Close()
	req, err := http.NewRequest("GET", server.URL+"/socket", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("Upgrade", "websocket")
	response, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != 101 {
		t.Fatalf("upgrade status=%d", response.StatusCode)
	}
	_ = response.Body.Close()
	select {
	case event := <-recorder:
		var meta struct {
			Status   int                     `json:"http_status"`
			Response *auditcore.HTTPResponse `json:"http_response"`
		}
		if err := json.Unmarshal(event.Metadata, &meta); err != nil {
			t.Fatal(err)
		}
		if meta.Status != 101 || meta.Response != nil {
			t.Fatalf("metadata=%s", event.Metadata)
		}
	case <-time.After(time.Second):
		t.Fatal("upgrade audit did not complete")
	}
}
