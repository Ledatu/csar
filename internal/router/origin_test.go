package router

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/ledatu/csar-core/caller"
	"github.com/ledatu/csar-core/gatewayctx"
	"github.com/ledatu/csar-core/jwtx"
	"github.com/ledatu/csar-core/origincontext"
	pb "github.com/ledatu/csar-proto/csar/authz/v1"
	"github.com/ledatu/csar/internal/authz"
	"github.com/ledatu/csar/internal/config"
	"google.golang.org/grpc"
)

type originPermission struct {
	pb.UnimplementedAuthzServiceServer
	allowed atomic.Bool
}

func (p *originPermission) CheckAccess(_ context.Context, in *pb.CheckAccessRequest) (*pb.CheckAccessResponse, error) {
	return &pb.CheckAccessResponse{Allowed: p.allowed.Load() && in.Subject == "reporting", EnrichedHeaders: map[string]string{gatewayctx.HeaderAuthzResult: "allow"}}, nil
}

func TestOriginRequiresServiceRequestAndAuthorizedResourceBeforeCache(t *testing.T) {
	keys, err := jwtx.GenerateKeyPair("EdDSA")
	if err != nil {
		t.Fatal(err)
	}
	jwk, err := jwtx.NewJWKFromPublicKey(keys.PublicKey, keys.KID)
	if err != nil {
		t.Fatal(err)
	}
	issuer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := json.NewEncoder(w).Encode(jwtx.JWKS{Keys: []jwtx.JWK{*jwk}}); err != nil {
			t.Error(err)
		}
	}))
	defer issuer.Close()
	permission := &originPermission{}
	permission.allowed.Store(true)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	pdp := grpc.NewServer()
	pb.RegisterAuthzServiceServer(pdp, permission)
	go func() { _ = pdp.Serve(listener) }()
	defer pdp.Stop()
	client, err := authz.New(&config.AuthzClientConfig{Address: listener.Addr().String(), AllowInsecure: true}, newTestLogger())
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	var calls atomic.Int32
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.Header.Get(origincontext.HeaderAuthorization) != "" {
			t.Error("origin credential forwarded")
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{}`))
	}))
	defer backend.Close()
	cfg := newTestConfig(map[string]config.PathConfig{"/report/{seller_id}": {"get": {
		Backend: config.BackendConfig{TargetURL: backend.URL}, AuthValidate: &config.AuthValidateConfig{Mode: "jwt", JWKSURL: issuer.URL, Issuer: "issuer", Audiences: []string{"analytics"}},
		Authz: &config.AuthzRouteConfig{Subject: "{header.X-Gateway-Subject}", ScopeType: "tenant", ScopeID: "wildberries:{path.seller_id}", Resource: "campaign_module", Action: "analytics.read"},
		Cache: &config.CacheConfig{Key: "report:{path.seller_id}", TTL: config.Duration{Duration: time.Minute}},
	}}})
	router, err := New(cfg, newTestLogger(), WithAuthzClient(client))
	if err != nil {
		t.Fatal(err)
	}
	service := &caller.Identity{Version: 1, CallerKind: caller.Service, CallerID: "reporting", EffectiveSubject: "reporting", CredentialKind: caller.STS, Assurance: caller.Verified}
	access, err := jwtx.Sign(keys, jwt.MapClaims{"sub": "reporting", "caller": service, "iss": "issuer", "aud": "analytics", "exp": time.Now().Add(time.Minute).Unix()})
	if err != nil {
		t.Fatal(err)
	}
	makeProof := func(resource, path, sender string) string {
		t.Helper()
		hash, err := origincontext.RequestHash(httptest.NewRequest(http.MethodGet, path, nil))
		if err != nil {
			t.Fatal(err)
		}
		origin := &caller.Identity{Version: 1, CallerKind: caller.Agent, CallerID: "agent", OwnerSubject: "owner", EffectiveSubject: "owner", CredentialKind: caller.APIKey, CredentialID: "key", Assurance: caller.Verified}
		root, err := origincontext.IssueRoot(keys, "issuer", &origincontext.RootRequest{Caller: origin, Receiver: sender, Resource: resource, RequestHash: hash, SourceExpiresAt: time.Now().Add(time.Minute)})
		if err != nil {
			t.Fatal(err)
		}
		proof, err := origincontext.Delegate(keys, "issuer", sender, &origincontext.DelegateRequest{ParentToken: root.Token, Receiver: "analytics", Resource: resource, RequestHash: hash})
		if err != nil {
			t.Fatal(err)
		}
		return proof.Token
	}
	proof := makeProof("wildberries:cabinet", "/report/cabinet", "reporting")
	send := func(proof string, want int) {
		t.Helper()
		r := httptest.NewRequest("GET", "/report/cabinet", nil)
		r.Header.Set(gatewayctx.HeaderCsarAuthorization, "Bearer "+access)
		r.Header.Set(origincontext.HeaderAuthorization, "Bearer "+proof)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, r)
		if w.Code != want {
			t.Fatalf("got=%d want=%d: %s", w.Code, want, w.Body.String())
		}
	}
	send(proof, 200)
	send(proof, 200)
	if calls.Load() != 1 {
		t.Fatal("cache did not warm")
	}
	send(makeProof("wildberries:foreign", "/report/cabinet", "reporting"), 403)
	send(makeProof("wildberries:cabinet", "/report/other", "reporting"), 401)
	send(makeProof("wildberries:cabinet", "/report/cabinet", "foreign"), 401)
	send(proof+"x", 401)
	permission.allowed.Store(false)
	send(proof, 403)
	if calls.Load() != 1 {
		t.Fatal("invalid proof or denied service reached backend")
	}
}
