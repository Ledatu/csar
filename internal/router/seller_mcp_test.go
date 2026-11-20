package router

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ledatu/csar-core/gatewayctx"
	pb "github.com/ledatu/csar-proto/csar/authz/v1"
	"github.com/ledatu/csar/internal/authz"
	"github.com/ledatu/csar/internal/config"
	"google.golang.org/grpc"
)

type cabinetPermission struct {
	pb.UnimplementedAuthzServiceServer
	allowed atomic.Bool
}

func (p *cabinetPermission) CheckAccess(_ context.Context, in *pb.CheckAccessRequest) (*pb.CheckAccessResponse, error) {
	allow := p.allowed.Load() && in.Subject == "seller-user" && in.Resource == "campaign_module" && in.Action == "analytics.read" && in.ScopeId == "wildberries:cabinet"
	return &pb.CheckAccessResponse{Allowed: allow, EnrichedHeaders: map[string]string{gatewayctx.HeaderAuthzResult: "allow"}}, nil
}

// Exercise both opaque-token routes through the production router, including a warm report cache.
func TestSellerMCPGateway(t *testing.T) {
	permission := &cabinetPermission{}
	permission.allowed.Store(true)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	pdp := grpc.NewServer()
	pb.RegisterAuthzServiceServer(pdp, permission)
	go func() { _ = pdp.Serve(listener) }()
	defer pdp.Stop()
	logger := newTestLogger()
	client, err := authz.New(&config.AuthzClientConfig{Address: listener.Addr().String(), AllowInsecure: true}, logger)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	var issued atomic.Int32
	var revoked atomic.Bool
	access := "aurum_mcp_" + strings.Repeat("a", 43)
	proof := func(n int32) string { return fmt.Sprintf("aurum_dlg_%043d", n) }
	identity := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var in struct{ Token string }
		if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
			t.Error(err)
			return
		}
		grant := map[string]any{"active": false}
		if !revoked.Load() {
			switch {
			case r.URL.Path == "/delegate" && in.Token == access:
				grant["active"] = true
				grant["delegated_token"] = proof(issued.Add(1))
			case r.URL.Path == "/consume" && in.Token == proof(issued.Load()):
				grant["active"] = true
			}
		}
		grant["subject"] = "seller-user"
		grant["credential_id"] = "grant"
		grant["seller_id"] = "cabinet"
		grant["scopes"] = []string{"analytics:read"}
		grant["expires_at"] = time.Now().Add(time.Minute)
		_ = json.NewEncoder(w).Encode(grant)
	}))
	defer identity.Close()
	ca := filepath.Join(t.TempDir(), "authn-ca.pem")
	if err = os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: identity.Certificate().Raw}), 0600); err != nil {
		t.Fatal(err)
	}
	var reportCalls atomic.Int32
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Cookie") != "" || r.Header.Get(gatewayctx.HeaderCsarAuthorization) != "" || r.Header.Get(gatewayctx.HeaderScopes) != "analytics:read" || r.Header.Get(gatewayctx.HeaderAuthzResult) != "allow" {
			t.Error("wrong credentials or grant at backend")
		}
		if r.Header.Get(gatewayctx.HeaderAuthzPolicy) == "seller-mcp-read" {
			if r.Header.Get("Authorization") != "Bearer "+proof(issued.Load()) {
				t.Error("incorrect request-scoped delegation")
			}
		} else {
			if r.Header.Get("Authorization") != "" {
				t.Error("unexpected report credential at API")
			}
			reportCalls.Add(1)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte("{}"))
	}))
	defer backend.Close()
	opaque := func(mode, path string) config.AuthValidateConfig {
		return config.AuthValidateConfig{Mode: mode, RequiredScope: "analytics:read", IntrospectionEndpoint: identity.URL + path, IntrospectionTLS: "identity"}
	}
	ingress := opaque("mcp", "/delegate")
	permissionFor := func(name, scope string) *config.AuthzRouteConfig {
		return &config.AuthzRouteConfig{PolicyName: name, Subject: "{header.X-Gateway-Subject}", ScopeType: "tenant", ScopeID: scope, Resource: "campaign_module", Action: "analytics.read"}
	}
	upstream := config.BackendConfig{TargetURL: backend.URL}
	cfg := newTestConfig(map[string]config.PathConfig{
		"/seller-mcp/rpc":     {"post": {Backend: upstream, AuthValidate: &ingress, Authz: permissionFor("seller-mcp-read", "{header.X-Gateway-Tenant}")}},
		"/report/{seller_id}": {"get": {Backend: upstream, AuthValidate: &config.AuthValidateConfig{Mode: "select", Methods: []config.AuthValidateConfig{opaque("token", "/pat"), opaque("delegated", "/consume")}}, Authz: permissionFor("analytics-report-read", "wildberries:{path.seller_id}"), Cache: &config.CacheConfig{Key: "report:{subject}:{path.seller_id}", TTL: config.Duration{Duration: time.Minute}}}},
	})
	cfg.BackendTLSPolicies = map[string]config.BackendTLSPolicy{"identity": {CAFile: ca}}
	router, err := New(cfg, logger, WithAuthzClient(client))
	if err != nil {
		t.Fatal(err)
	}
	send := func(method, path, header, value string, want int) {
		t.Helper()
		req := httptest.NewRequest(method, path, nil)
		req.AddCookie(&http.Cookie{Name: "session", Value: "ignored"})
		if value != "" {
			req.Header.Set(header, "Bearer "+value)
		}
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
		if w.Code != want {
			t.Fatalf("%s %s: got %d, want %d: %s", method, path, w.Code, want, w.Body.String())
		}
	}
	send("POST", "/seller-mcp/rpc", "Authorization", "", 401)
	for i := int32(1); i <= 2; i++ {
		send("POST", "/seller-mcp/rpc", "Authorization", access, 200)
		if issued.Load() != i {
			t.Fatal("ingress reused a delegation")
		}
		send("GET", "/report/cabinet", gatewayctx.HeaderCsarAuthorization, proof(i), 200)
	}
	if reportCalls.Load() != 1 {
		t.Fatalf("expected warm cache, upstream calls %d", reportCalls.Load())
	}
	send("GET", "/report/other", gatewayctx.HeaderCsarAuthorization, proof(2), 403)
	permission.allowed.Store(false)
	send("GET", "/report/cabinet", gatewayctx.HeaderCsarAuthorization, proof(2), 403)
	permission.allowed.Store(true)
	revoked.Store(true)
	send("GET", "/report/cabinet", gatewayctx.HeaderCsarAuthorization, proof(2), 401)
	send("POST", "/seller-mcp/rpc", "Authorization", access, 401)
	if reportCalls.Load() != 1 {
		t.Fatal("a denied request reached the API")
	}
}
