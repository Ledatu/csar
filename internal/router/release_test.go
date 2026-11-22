package router

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	auditcore "github.com/ledatu/csar-core/audit"
	"github.com/ledatu/csar-core/authntokens"
	"github.com/ledatu/csar-core/caller"
	"github.com/ledatu/csar-core/gatewayctx"
	pb "github.com/ledatu/csar-proto/csar/authz/v1"
	"github.com/ledatu/csar/internal/authz"
	"github.com/ledatu/csar/internal/config"
	"google.golang.org/grpc"
)

type releaseRecorder struct {
	stubAuditRecorder
	release func(context.Context, *auditcore.Event) error
}

func (r *releaseRecorder) RecordSync(ctx context.Context, ev *auditcore.Event) error {
	return r.release(ctx, ev)
}

func releaseFixture(t *testing.T, recorder *releaseRecorder) (*Router, *atomic.Int32) {
	t.Helper()
	issuer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie("session")
		if err != nil || cookie.Value == "denied" {
			w.WriteHeader(401)
			return
		}
		w.Header().Set(gatewayctx.HeaderSubject, cookie.Value)
		w.Header().Set(authntokens.HeaderSessionExpiresAt, time.Now().Add(time.Minute).Format(time.RFC3339Nano))
		if err := gatewayctx.SetCaller(w.Header(), &caller.Identity{Version: 1, CallerKind: caller.Human, CallerID: cookie.Value, OwnerSubject: cookie.Value, EffectiveSubject: cookie.Value, CredentialKind: caller.Session, Assurance: caller.Verified}); err != nil {
			t.Error(err)
		}
	}))
	t.Cleanup(issuer.Close)
	calls := &atomic.Int32{}
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"protected":"report"}`))
	}))
	t.Cleanup(backend.Close)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	permissions := &forwardPermission{}
	permissions.allowed.Store(true)
	server := grpc.NewServer()
	pb.RegisterAuthzServiceServer(server, permissions)
	go func() { _ = server.Serve(listener) }()
	t.Cleanup(server.Stop)
	client, err := authz.New(&config.AuthzClientConfig{Address: listener.Addr().String(), AllowInsecure: true}, newTestLogger())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })
	mode := config.AuditModeAll
	cfg := newTestConfig(map[string]config.PathConfig{"/report": {"get": {Backend: config.BackendConfig{TargetURL: backend.URL}, AuthValidate: &config.AuthValidateConfig{Mode: "session", SessionEndpoint: issuer.URL, CookieName: "session"}, Authz: &config.AuthzRouteConfig{Subject: "{header.X-Gateway-Subject}", ScopeType: "tenant", ScopeID: "wildberries:cabinet", Resource: "report", Action: "read"}, Audit: &mode, AuditRelease: true, Cache: &config.CacheConfig{Key: "shared-authorized-report", TTL: config.Duration{Duration: time.Minute}}}}})
	router, err := New(cfg, newTestLogger(), func(r *Router) { r.auditClient = recorder }, WithAuthzClient(client))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(router.Close)
	return router, calls
}

func TestReleaseReceiptGuardsMissHitAndCurrentCaller(t *testing.T) {
	var receipts []*auditcore.Event
	fail := false
	recorder := &releaseRecorder{release: func(_ context.Context, ev *auditcore.Event) error {
		receipts = append(receipts, ev)
		if fail {
			return errors.New("uncertain receipt")
		}
		return nil
	}}
	router, calls := releaseFixture(t, recorder)
	send := func(subject string) *httptest.ResponseRecorder {
		r := httptest.NewRequest("GET", "/report", nil)
		r.AddCookie(&http.Cookie{Name: "session", Value: subject})
		w := httptest.NewRecorder()
		router.ServeHTTP(w, r)
		return w
	}
	if w := send("first"); w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	fail = true
	if w := send("second"); w.Code != 503 || w.Header().Get("X-CSAR-Status") != "audit_unavailable" || strings.Contains(w.Body.String(), "protected") {
		t.Fatal("HIT bypassed uncertain receipt", w.Code, w.Body.String())
	}
	fail = false
	if w := send("second"); w.Code != 200 || w.Header().Get("X-CSAR-Cache") != "HIT" {
		t.Fatal("warm cache unavailable after receipt", w.Code)
	}
	if w := send("denied"); w.Code != 401 {
		t.Fatal("authentication denied request passed")
	}
	if calls.Load() != 1 || len(receipts) != 3 || receipts[0].Caller.CallerID != "first" || receipts[2].Caller.CallerID != "second" || receipts[0].ID == receipts[2].ID {
		t.Fatal("receipt/cache reused actor or dispatch")
	}
	if !strings.Contains(string(recorder.events[2].Metadata), receipts[2].ID) || !strings.Contains(string(recorder.events[2].Metadata), "HIT") {
		t.Fatal("final event lost receipt/cache correlation")
	}
}

func TestReleaseWaitsAndCancellationNeverDispatches(t *testing.T) {
	started := make(chan struct{})
	recorder := &releaseRecorder{release: func(ctx context.Context, _ *auditcore.Event) error { close(started); <-ctx.Done(); return ctx.Err() }}
	router, calls := releaseFixture(t, recorder)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	req := httptest.NewRequestWithContext(ctx, "GET", "/report", nil)
	req.AddCookie(&http.Cookie{Name: "session", Value: "user"})
	done := make(chan *httptest.ResponseRecorder, 1)
	go func() { w := httptest.NewRecorder(); router.ServeHTTP(w, req); done <- w }()
	select {
	case <-started:
	case <-time.After(3 * time.Second):
		t.Fatal("receipt was not requested")
	}
	select {
	case <-done:
		t.Fatal("protected data released before receipt")
	default:
	}
	if calls.Load() != 0 {
		t.Fatal("backend dispatched before receipt")
	}
	cancel()
	select {
	case w := <-done:
		if w.Code != 503 || strings.Contains(w.Body.String(), "protected") {
			t.Fatal("cancellation released data")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("receipt cancellation unbounded")
	}
	if calls.Load() != 0 {
		t.Fatal("cancelled receipt dispatched backend")
	}
}
