package authzmw

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ledatu/csar-core/gatewayctx"
	authzv1 "github.com/ledatu/csar-proto/csar/authz/v1"
	"github.com/ledatu/csar/internal/authz"
	"github.com/ledatu/csar/internal/config"
)

func TestResolvePlaceholder_CompositePathScopeID(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/campaigns/by-account/wildberries/s1", nil)
	req = req.WithContext(WithPathVars(req.Context(), map[string]string{
		"marketplace": "wildberries",
		"external_id": "s1",
	}))

	got, err := resolvePlaceholder("{path.marketplace}:{path.external_id}", req, PathVarsFromContext(req.Context()))
	if err != nil {
		t.Fatalf("resolvePlaceholder() error: %v", err)
	}
	if got != "wildberries:s1" {
		t.Fatalf("scope_id = %q, want %q", got, "wildberries:s1")
	}
}

func TestResolvePlaceholder_MissingPathValue(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/campaigns/by-account/wildberries/s1", nil)
	req = req.WithContext(WithPathVars(req.Context(), map[string]string{
		"marketplace": "wildberries",
	}))

	_, err := resolvePlaceholder("{path.marketplace}:{path.external_id}", req, PathVarsFromContext(req.Context()))
	if err == nil {
		t.Fatal("expected error for missing external_id path variable")
	}
}

type fakeChecker struct {
	calls   []*authzv1.CheckAccessRequest
	decide  func(req *authzv1.CheckAccessRequest) *authz.CheckAccessResult
	failErr error
}

func (f *fakeChecker) CheckAccess(_ context.Context, req *authzv1.CheckAccessRequest) (*authz.CheckAccessResult, error) {
	f.calls = append(f.calls, req)
	if f.failErr != nil {
		return nil, f.failErr
	}
	return f.decide(req), nil
}

func allowScope(scopeType string) func(req *authzv1.CheckAccessRequest) *authz.CheckAccessResult {
	return func(req *authzv1.CheckAccessRequest) *authz.CheckAccessResult {
		if req.ScopeType != scopeType {
			return &authz.CheckAccessResult{Allowed: false}
		}
		return &authz.CheckAccessResult{
			Allowed:      true,
			MatchedRoles: []string{"r"},
			EnrichedHeaders: map[string]string{
				gatewayctx.HeaderAuthzResult: "allow",
				gatewayctx.HeaderAuthzScope:  scopeType,
			},
		}
	}
}

func tenantBranch() config.AuthzRouteConfig {
	return config.AuthzRouteConfig{
		PolicyName: "campaign-tenant-read",
		Subject:    "{header.X-Gateway-Subject}",
		Resource:   "campaign",
		Action:     "read",
		ScopeType:  "tenant",
		ScopeID:    "{path.marketplace}:{path.external_id}",
	}
}

func platformBranch() config.AuthzRouteConfig {
	return config.AuthzRouteConfig{
		PolicyName: "campaign-platform-read",
		Subject:    "{header.X-Gateway-Subject}",
		Resource:   "campaign",
		Action:     "read",
		ScopeType:  "platform",
	}
}

func serve(t *testing.T, checker *fakeChecker, route *config.AuthzRouteConfig, req *http.Request) (*httptest.ResponseRecorder, *http.Request) {
	t.Helper()
	var upstreamReq *http.Request
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamReq = r
		w.WriteHeader(http.StatusNoContent)
	})
	mw := New(checker, func(*http.Request) string { return "req-1" })
	rec := httptest.NewRecorder()
	mw.Wrap(Config{RouteConfig: route}, next).ServeHTTP(rec, req)
	return rec, upstreamReq
}

func tenantRequest(subject string) *http.Request {
	req := httptest.NewRequest(http.MethodGet, "/campaigns/by-account/wildberries/s1", nil)
	req.Header.Set("X-Gateway-Subject", subject)
	return req.WithContext(WithPathVars(req.Context(), map[string]string{
		"marketplace": "wildberries",
		"external_id": "s1",
	}))
}

func TestWrap_SingleAllow_InjectsHeadersAndPolicy(t *testing.T) {
	checker := &fakeChecker{decide: allowScope("tenant")}
	route := tenantBranch()

	rec, upstream := serve(t, checker, &route, tenantRequest("user-1"))

	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want 204 (body %s)", rec.Code, rec.Body.String())
	}
	if len(checker.calls) != 1 {
		t.Fatalf("CheckAccess calls = %d, want 1", len(checker.calls))
	}
	if got := checker.calls[0].ScopeId; got != "wildberries:s1" {
		t.Errorf("scope_id = %q, want wildberries:s1", got)
	}
	if got := upstream.Header.Get(gatewayctx.HeaderAuthzScope); got != "tenant" {
		t.Errorf("%s = %q, want tenant", gatewayctx.HeaderAuthzScope, got)
	}
	if got := upstream.Header.Get(gatewayctx.HeaderAuthzPolicy); got != "campaign-tenant-read" {
		t.Errorf("%s = %q, want campaign-tenant-read", gatewayctx.HeaderAuthzPolicy, got)
	}
}

func TestWrap_SingleDeny_Forbidden(t *testing.T) {
	checker := &fakeChecker{decide: allowScope("platform")}
	route := tenantBranch()

	rec, upstream := serve(t, checker, &route, tenantRequest("user-1"))

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", rec.Code)
	}
	if upstream != nil {
		t.Error("upstream must not be called on deny")
	}
}

func TestWrap_SingleUnresolvable_BadRequest(t *testing.T) {
	checker := &fakeChecker{decide: allowScope("tenant")}
	route := tenantBranch()
	req := tenantRequest("")

	rec, _ := serve(t, checker, &route, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "cannot resolve subject") {
		t.Errorf("body = %s, want subject resolution error", rec.Body.String())
	}
	if len(checker.calls) != 0 {
		t.Error("CheckAccess must not be called when the subject cannot be resolved")
	}
}

func TestWrap_AnyOf_FallsThroughToPlatformBranch(t *testing.T) {
	checker := &fakeChecker{decide: allowScope("platform")}
	route := &config.AuthzRouteConfig{
		PolicyName: "campaign-read",
		AnyOf:      []config.AuthzRouteConfig{tenantBranch(), platformBranch()},
	}

	rec, upstream := serve(t, checker, route, tenantRequest("staff-1"))

	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want 204 (body %s)", rec.Code, rec.Body.String())
	}
	if len(checker.calls) != 2 {
		t.Fatalf("CheckAccess calls = %d, want 2 (tenant deny, platform allow)", len(checker.calls))
	}
	if checker.calls[0].ScopeType != "tenant" || checker.calls[1].ScopeType != "platform" {
		t.Errorf("branches evaluated out of order: %v", checker.calls)
	}
	if got := upstream.Header.Get(gatewayctx.HeaderAuthzPolicy); got != "campaign-platform-read" {
		t.Errorf("%s = %q, want campaign-platform-read", gatewayctx.HeaderAuthzPolicy, got)
	}
	if got := upstream.Header.Get(gatewayctx.HeaderAuthzScope); got != "platform" {
		t.Errorf("%s = %q, want platform", gatewayctx.HeaderAuthzScope, got)
	}
}

func TestWrap_AnyOf_FirstAllowShortCircuits(t *testing.T) {
	checker := &fakeChecker{decide: allowScope("tenant")}
	route := &config.AuthzRouteConfig{
		AnyOf: []config.AuthzRouteConfig{tenantBranch(), platformBranch()},
	}

	rec, upstream := serve(t, checker, route, tenantRequest("member-1"))

	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want 204", rec.Code)
	}
	if len(checker.calls) != 1 {
		t.Fatalf("CheckAccess calls = %d, want 1", len(checker.calls))
	}
	if got := upstream.Header.Get(gatewayctx.HeaderAuthzPolicy); got != "campaign-tenant-read" {
		t.Errorf("%s = %q, want campaign-tenant-read", gatewayctx.HeaderAuthzPolicy, got)
	}
}

func TestWrap_AnyOf_AllDeny_Forbidden(t *testing.T) {
	checker := &fakeChecker{decide: func(*authzv1.CheckAccessRequest) *authz.CheckAccessResult {
		return &authz.CheckAccessResult{Allowed: false}
	}}
	route := &config.AuthzRouteConfig{
		AnyOf: []config.AuthzRouteConfig{tenantBranch(), platformBranch()},
	}

	rec, upstream := serve(t, checker, route, tenantRequest("nobody"))

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", rec.Code)
	}
	if upstream != nil {
		t.Error("upstream must not be called when every branch denies")
	}
	if len(checker.calls) != 2 {
		t.Errorf("CheckAccess calls = %d, want 2", len(checker.calls))
	}
}

func TestWrap_AnyOf_SkipsUnresolvableBranch(t *testing.T) {
	checker := &fakeChecker{decide: allowScope("platform")}
	headerTenant := tenantBranch()
	headerTenant.ScopeID = "{header.X-Tenant-Id}"
	route := &config.AuthzRouteConfig{
		AnyOf: []config.AuthzRouteConfig{headerTenant, platformBranch()},
	}

	rec, upstream := serve(t, checker, route, tenantRequest("staff-1"))

	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want 204 (body %s)", rec.Code, rec.Body.String())
	}
	if len(checker.calls) != 1 || checker.calls[0].ScopeType != "platform" {
		t.Fatalf("expected only the platform branch to reach csar-authz, got %v", checker.calls)
	}
	if got := upstream.Header.Get(gatewayctx.HeaderAuthzPolicy); got != "campaign-platform-read" {
		t.Errorf("%s = %q", gatewayctx.HeaderAuthzPolicy, got)
	}
}

func TestWrap_AnyOf_NoBranchResolvable_BadRequest(t *testing.T) {
	checker := &fakeChecker{decide: allowScope("platform")}
	route := &config.AuthzRouteConfig{
		AnyOf: []config.AuthzRouteConfig{tenantBranch(), platformBranch()},
	}

	rec, _ := serve(t, checker, route, tenantRequest(""))

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
	if len(checker.calls) != 0 {
		t.Error("CheckAccess must not be called when no branch resolves")
	}
}

func TestWrap_ClientError_BadGateway(t *testing.T) {
	checker := &fakeChecker{failErr: errors.New("dial tcp: connection refused")}
	route := &config.AuthzRouteConfig{
		AnyOf: []config.AuthzRouteConfig{tenantBranch(), platformBranch()},
	}

	rec, _ := serve(t, checker, route, tenantRequest("user-1"))

	if rec.Code != http.StatusBadGateway {
		t.Fatalf("status = %d, want 502", rec.Code)
	}
	if len(checker.calls) != 1 {
		t.Errorf("CheckAccess calls = %d, want 1 (fail fast on transport error)", len(checker.calls))
	}
}

func TestWrap_StripHeadersAppliedBeforeCheck(t *testing.T) {
	checker := &fakeChecker{decide: allowScope("tenant")}
	route := tenantBranch()
	route.StripHeaders = []string{"X-User-Roles"}
	req := tenantRequest("user-1")
	req.Header.Set("X-User-Roles", "platform_admin")

	_, upstream := serve(t, checker, &route, req)

	if got := upstream.Header.Get("X-User-Roles"); got != "" {
		t.Errorf("X-User-Roles = %q, want stripped", got)
	}
}
