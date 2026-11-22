package main

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"io"
	"log/slog"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ledatu/csar-core/caller"
	"github.com/ledatu/csar-core/jwtx"
	"github.com/ledatu/csar-core/origincontext"
	"github.com/ledatu/csar/internal/authz"
	"github.com/ledatu/csar/internal/config"
	"github.com/ledatu/csar/internal/router"
)

func TestStartupRootIssuerMTLSAndReload(t *testing.T) {
	keys, err := jwtx.GenerateKeyPair("EdDSA")
	if err != nil {
		t.Fatal(err)
	}
	jwk, err := jwtx.NewJWKFromPublicKey(keys.PublicKey, keys.KID)
	if err != nil {
		t.Fatal(err)
	}
	var requests, lookups atomic.Int32
	var redirect atomic.Bool
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if len(r.TLS.VerifiedChains) == 0 {
			t.Error("issuer received unauthenticated request")
		}
		if r.URL.Path == "/jwks" {
			lookups.Add(1)
			if redirect.Load() {
				http.Redirect(w, r, "/unexpected", http.StatusFound)
				return
			}
			if err := json.NewEncoder(w).Encode(jwtx.JWKS{Keys: []jwtx.JWK{*jwk}}); err != nil {
				t.Error(err)
			}
			return
		}
		if r.URL.Path != "/root" {
			t.Error("unexpected request", r.URL.Path)
			w.WriteHeader(500)
			return
		}
		requests.Add(1)
		var in origincontext.RootRequest
		if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
			t.Error(err)
			return
		}
		out, err := origincontext.IssueRoot(keys, "issuer", &in)
		if err != nil {
			t.Error(err)
			w.WriteHeader(400)
			return
		}
		if err := json.NewEncoder(w).Encode(out); err != nil {
			t.Error(err)
		}
	}))
	// An ephemeral client CA exercises loading actual PEM files at startup.
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
	der, err := x509.CreateCertificate(rand.Reader, ca, ca, keys.PublicKey, keys.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(cert)
	server.TLS = &tls.Config{MinVersion: tls.VersionTLS12, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: pool}
	server.StartTLS()
	defer server.Close()
	key, err := x509.MarshalPKCS8PrivateKey(keys.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	write := func(name, kind string, bytes []byte) string {
		file := filepath.Join(dir, name)
		if err := os.WriteFile(file, pem.EncodeToMemory(&pem.Block{Type: kind, Bytes: bytes}), 0600); err != nil {
			t.Fatal(err)
		}
		return file
	}
	settings := &config.OriginIssuerConfig{Endpoint: server.URL + "/root", Issuer: "issuer", JWKSURL: server.URL + "/jwks", TLS: config.BackendTLSPolicy{
		CAFile: write("ca.pem", "CERTIFICATE", server.Certificate().Raw), CertFile: write("client.pem", "CERTIFICATE", der), KeyFile: write("client.key", "PRIVATE KEY", key),
	}}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	issuer, closeIssuer, err := buildRootIssuer(settings, logger)
	if err != nil {
		t.Fatal(err)
	}
	defer closeIssuer()
	input := &origincontext.RootRequest{Caller: &caller.Identity{Version: 1, CallerKind: caller.Human, CallerID: "user", EffectiveSubject: "user", OwnerSubject: "user", CredentialKind: caller.Session, Assurance: caller.Verified}, Receiver: "svc:reports", Resource: "wildberries:cabinet", RequestHash: strings.Repeat("a", 64), SourceExpiresAt: time.Now().Add(time.Minute)}
	if _, err := issuer.Issue(context.Background(), input); err != nil {
		t.Fatal(err)
	}
	permissions, err := authz.New(&config.AuthzClientConfig{Address: "127.0.0.1:1", AllowInsecure: true}, logger)
	if err != nil {
		t.Fatal(err)
	}
	defer permissions.Close()
	cfg := reloadTestConfig(server.URL, nil)
	cfg.OriginIssuer = settings
	route := cfg.Paths["/preferences"]["get"]
	route.OriginReceiver = "svc:reports"
	route.Backend.TLS = &config.BackendTLSConfig{CAFile: settings.TLS.CAFile, CertFile: settings.TLS.CertFile, KeyFile: settings.TLS.KeyFile}
	route.AuthValidate = &config.AuthValidateConfig{Mode: "jwt", Issuer: "issuer", JWKSURL: settings.JWKSURL, Audiences: []string{"access-audience"}}
	route.Authz = &config.AuthzRouteConfig{Subject: "{header.X-Gateway-Subject}", ScopeType: "tenant", ScopeID: "wildberries:cabinet", Resource: "reports", Action: "read"}
	cfg.Paths["/preferences"]["get"] = route
	rl := newTestReloader(t, cfg, router.WithRootIssuer(issuer), router.WithAuthzClient(permissions))
	// Coordinator snapshots omit all local issuer settings. Rebuild must retain
	// the startup provider while allowing the receiver policy to change.
	cfg.OriginIssuer = nil
	cfg.OriginPolicyVersion = config.OriginPolicyVersion
	route.OriginReceiver = "svc:reports-v2"
	cfg.Paths["/preferences"]["get"] = route
	if err := rl.Apply(cfg); err != nil {
		t.Fatal(err)
	}
	// A YAML reload changing startup settings warns but reuses the original client.
	changed := *settings
	changed.Endpoint = "https://other.example/root"
	cfg.OriginIssuer = &changed
	if err := rl.Reload(cfg); err != nil {
		t.Fatal(err)
	}
	if _, err := issuer.Issue(context.Background(), input); err != nil {
		t.Fatal(err)
	}
	if requests.Load() != 2 || lookups.Load() != 1 {
		t.Fatal("issuer was replaced or JWKS cache lost across reloads")
	}
	// A cold JWKS redirect is never followed to another credential-bearing target.
	redirect.Store(true)
	second, closeSecond, err := buildRootIssuer(settings, logger)
	if err != nil {
		t.Fatal(err)
	}
	defer closeSecond()
	if _, err := second.Issue(context.Background(), input); err == nil {
		t.Fatal("redirected JWKS accepted")
	}
}

func TestStartupRootIssuerDisabledAndMissingFiles(t *testing.T) {
	issuer, closeIssuer, err := buildRootIssuer(nil, slog.Default())
	if err != nil || issuer != nil {
		t.Fatal("disabled issuer changed startup", err)
	}
	closeIssuer()
	_, _, err = buildRootIssuer(&config.OriginIssuerConfig{Endpoint: "https://authn/root", Issuer: "issuer", JWKSURL: "https://authn/jwks", TLS: config.BackendTLSPolicy{CertFile: "/missing/cert.pem", KeyFile: "/missing/key.pem"}}, slog.Default())
	if err == nil {
		t.Fatal("missing mTLS files did not fail startup")
	}
}
