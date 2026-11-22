package router

import (
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/ledatu/csar-core/authntokens"
	"github.com/ledatu/csar-core/caller"
	"github.com/ledatu/csar-core/gatewayctx"
	"github.com/ledatu/csar-core/jwtx"
	"github.com/ledatu/csar-core/origincontext"
	pb "github.com/ledatu/csar-proto/csar/authz/v1"
	"github.com/ledatu/csar/internal/authz"
	"github.com/ledatu/csar/internal/config"
	"google.golang.org/grpc"
)

type testRootIssuer struct {
	keys  *jwtx.KeyPair
	calls atomic.Int32
	fail  atomic.Bool
}

func (i *testRootIssuer) Issue(_ context.Context, in *origincontext.RootRequest) (*origincontext.Proof, error) {
	i.calls.Add(1)
	if i.fail.Load() {
		return nil, errors.New("private issuer diagnostic")
	}
	response, err := origincontext.IssueRoot(i.keys, "issuer", in)
	if err != nil {
		return nil, err
	}
	claims, err := origincontext.Verify(response.Token, func(_, _ string) (crypto.PublicKey, error) { return i.keys.PublicKey, nil }, "issuer", in.Receiver)
	return &origincontext.Proof{Token: response.Token, Claims: claims}, err
}

type forwardPermission struct {
	pb.UnimplementedAuthzServiceServer
	allowed atomic.Bool
}

func (p *forwardPermission) CheckAccess(_ context.Context, in *pb.CheckAccessRequest) (*pb.CheckAccessResponse, error) {
	return &pb.CheckAccessResponse{Allowed: p.allowed.Load(), EnrichedHeaders: map[string]string{gatewayctx.HeaderSubject: in.Subject, gatewayctx.HeaderAuthzResult: "allow"}}, nil
}

func forwardingTLSFixture(t *testing.T, handler http.Handler) (*httptest.Server, *config.BackendTLSConfig) {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cert := &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}}
	der, err := x509.CreateCertificate(rand.Reader, cert, cert, public, private)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(parsed)
	key, err := x509.MarshalPKCS8PrivateKey(private)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	certFile := filepath.Join(dir, "cert.pem")
	keyFile := filepath.Join(dir, "key.pem")
	if err := os.WriteFile(certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: key}), 0600); err != nil {
		t.Fatal(err)
	}
	server := httptest.NewUnstartedServer(handler)
	server.TLS = &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: private}}, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: pool}
	server.StartTLS()
	t.Cleanup(server.Close)
	return server, &config.BackendTLSConfig{CAFile: certFile, CertFile: certFile, KeyFile: keyFile}
}

func TestRootAndServiceOriginForwardingDoesNotMintOnCacheHit(t *testing.T) {
	keys, err := jwtx.GenerateKeyPair("EdDSA")
	if err != nil {
		t.Fatal(err)
	}
	issuer := &testRootIssuer{keys: keys}
	jwk, err := jwtx.NewJWKFromPublicKey(keys.PublicKey, keys.KID)
	if err != nil {
		t.Fatal(err)
	}
	identity := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/jwks" {
			if err := json.NewEncoder(w).Encode(jwtx.JWKS{Keys: []jwtx.JWK{*jwk}}); err != nil {
				t.Error(err)
			}
			return
		}
		cookie, err := r.Cookie("session")
		if err != nil {
			w.WriteHeader(401)
			return
		}
		id := &caller.Identity{Version: 1, CallerKind: caller.Human, CallerID: cookie.Value, OwnerSubject: cookie.Value, EffectiveSubject: cookie.Value, CredentialKind: caller.Session, Assurance: caller.Verified}
		w.Header().Set(gatewayctx.HeaderSubject, cookie.Value)
		if err := gatewayctx.SetCaller(w.Header(), id); err != nil {
			t.Error(err)
		}
		if cookie.Value != "legacy" {
			w.Header().Set(authntokens.HeaderSessionExpiresAt, time.Now().Add(time.Hour).Format(time.RFC3339Nano))
		}
	}))
	defer identity.Close()
	permission := &forwardPermission{}
	permission.allowed.Store(true)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	pdp := grpc.NewServer()
	pb.RegisterAuthzServiceServer(pdp, permission)
	go func() { _ = pdp.Serve(listener) }()
	defer pdp.Stop()
	authzClient, err := authz.New(&config.AuthzClientConfig{Address: listener.Addr().String(), AllowInsecure: true}, newTestLogger())
	if err != nil {
		t.Fatal(err)
	}
	defer authzClient.Close()
	var backendCalls atomic.Int32
	type observation struct {
		id    gatewayctx.Identity
		token string
	}
	observations := make(chan observation, 4)
	backend, backendTLS := forwardingTLSFixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		backendCalls.Add(1)
		id, err := gatewayctx.FromRequestChecked(r)
		if err != nil || id.Origin == nil || len(r.TLS.VerifiedChains) == 0 {
			t.Error("origin or trusted ingress missing", err)
			w.WriteHeader(500)
			return
		}
		observations <- observation{id: id, token: strings.TrimPrefix(r.Header.Get(origincontext.HeaderForwardedAuthorization), "Bearer ")}
		w.Header().Set(origincontext.HeaderForwardedAuthorization, r.Header.Get(origincontext.HeaderForwardedAuthorization))
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{}`))
	}))
	cfg := newTestConfig(map[string]config.PathConfig{"/report/{seller_id}": {"get": {
		Backend: config.BackendConfig{TargetURL: backend.URL, TLS: backendTLS}, AuthValidate: &config.AuthValidateConfig{Mode: "select", Methods: []config.AuthValidateConfig{{Mode: "session", SessionEndpoint: identity.URL + "/session", CookieName: "session"}, {Mode: "jwt", JWKSURL: identity.URL + "/jwks", Issuer: "issuer", Audiences: []string{"analytics-access"}}}},
		Authz: &config.AuthzRouteConfig{Subject: "{header.X-Gateway-Subject}", ScopeType: "tenant", ScopeID: "wildberries:{path.seller_id}", Resource: "report", Action: "read"}, Cache: &config.CacheConfig{Key: "report:{path.seller_id}", TTL: config.Duration{Duration: time.Minute}},
	}}})
	router, err := New(cfg, newTestLogger(), WithAuthzClient(authzClient), WithOriginForwarding(issuer, map[string]string{"GET:/report/{seller_id}": "svc:analytics"}))
	if err != nil {
		t.Fatal(err)
	}
	defer router.Close()
	recorder := &stubAuditRecorder{}
	router.auditClient = recorder
	rt, _ := router.matchRoute("GET", "/report/cabinet")
	rt.auditMode = config.AuditModeAll
	send := func(subject, path, access, proof string, want int) {
		t.Helper()
		r := httptest.NewRequest("GET", path, nil)
		if subject != "" {
			r.AddCookie(&http.Cookie{Name: "session", Value: subject})
		}
		if access != "" {
			r.Header.Set(gatewayctx.HeaderCsarAuthorization, "Bearer "+access)
		}
		if proof != "" {
			r.Header.Set(origincontext.HeaderAuthorization, "Bearer "+proof)
		}
		w := httptest.NewRecorder()
		router.ServeHTTP(w, r)
		if w.Code != want {
			t.Fatalf("got=%d want=%d: %s", w.Code, want, w.Body.String())
		}
		if w.Header().Get(origincontext.HeaderForwardedAuthorization) != "" {
			t.Fatal("forwarding credential reached public/cache response")
		}
	}
	send("one", "/report/cabinet", "", "", 200)
	send("two", "/report/cabinet", "", "", 200)
	first := <-observations
	if issuer.calls.Load() != 1 || backendCalls.Load() != 1 || first.id.Origin.Caller.CallerID != "one" || recorder.events[1].Caller.CallerID != "two" || recorder.events[1].OriginCaller != nil {
		t.Fatal("cache reused origin or minted another root")
	}
	service := &caller.Identity{Version: 1, CallerKind: caller.Service, CallerID: "svc:reporting", EffectiveSubject: "svc:reporting", CredentialKind: caller.STS, Assurance: caller.Verified}
	access, err := jwtx.Sign(keys, jwt.MapClaims{"caller": service, "sub": "svc:reporting", "iss": "issuer", "aud": "analytics-access", "exp": time.Now().Add(time.Minute).Unix()})
	if err != nil {
		t.Fatal(err)
	}
	hash, err := origincontext.RequestHash(httptest.NewRequest("GET", "/report/other", nil))
	if err != nil {
		t.Fatal(err)
	}
	root, err := origincontext.IssueRoot(keys, "issuer", &origincontext.RootRequest{Caller: &caller.Identity{Version: 1, CallerKind: caller.Agent, CallerID: "agent", OwnerSubject: "owner", EffectiveSubject: "owner", CredentialKind: caller.APIKey, CredentialID: "key", Assurance: caller.Verified}, Receiver: "svc:reporting", Resource: "wildberries:other", RequestHash: hash, SourceExpiresAt: time.Now().Add(time.Minute)})
	if err != nil {
		t.Fatal(err)
	}
	child, err := origincontext.Delegate(keys, "issuer", "svc:reporting", &origincontext.DelegateRequest{ParentToken: root.Token, Receiver: "svc:analytics", Resource: "wildberries:other", RequestHash: hash})
	if err != nil {
		t.Fatal(err)
	}
	send("", "/report/other", access, child.Token, 200)
	second := <-observations
	if issuer.calls.Load() != 1 || backendCalls.Load() != 2 || second.token != child.Token || second.id.Subject != "svc:reporting" || second.id.Origin.Caller.CallerID != "agent" {
		t.Fatal("service origin was reminted, misaddressed or lost")
	}
	permission.allowed.Store(false)
	send("one", "/report/cabinet", "", "", 403)
	permission.allowed.Store(true)
	send("legacy", "/report/cabinet", "", "", 401)
	issuer.fail.Store(true)
	send("one", "/report/failure", "", "", 502)
	if backendCalls.Load() != 2 || issuer.calls.Load() != 2 {
		t.Fatal("denial/legacy/issuer failure reached backend")
	}
	if _, err := New(cfg, newTestLogger(), WithAuthzClient(authzClient), WithOriginForwarding(issuer, map[string]string{"GET:/missing": "svc:analytics"})); err == nil {
		t.Fatal("unknown forwarding route ignored")
	}
	unsafeRoute := cfg.Paths["/report/{seller_id}"]["get"]
	unsafeRoute.Backend.TLS = nil
	cfg.Paths["/report/{seller_id}"]["get"] = unsafeRoute
	if _, err := New(cfg, newTestLogger(), WithAuthzClient(authzClient), WithOriginForwarding(issuer, map[string]string{"GET:/report/{seller_id}": "svc:analytics"})); err == nil {
		t.Fatal("untrusted backend accepted")
	}
}
