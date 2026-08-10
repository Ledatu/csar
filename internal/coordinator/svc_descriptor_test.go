package coordinator

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/ledatu/csar-core/tokenmint"
)

// descriptorTestServer builds a svc server with minting enabled and campaigns
// scoped to the accounts/ prefix, mirroring prod's --svc-token-prefix-map.
func descriptorTestServer(t *testing.T) (*AdminServer, *mockMutableStore) {
	t.Helper()

	srv, store := newTestSvcServer(true, map[string]string{
		"svc:aurumskynet-campaigns": "accounts/",
	})

	cfg := &tokenmint.Config{
		AllowedHosts: []string{"api-performance.ozon.ru"},
		Profiles: map[string]tokenmint.Profile{
			"ozon-performance": {
				TokenURL:               "https://api-performance.ozon.ru/api/client/token",
				SecretRefScopeSegments: 3,
			},
		},
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("validate mint config: %v", err)
	}
	srv.SetMintConfig(cfg)

	return srv, store
}

const campaignsSubject = "svc:aurumskynet-campaigns"

// serveSvc routes through the real mux so PathValue("tokenRef") resolves the
// same way it does in production.
func serveSvc(srv *AdminServer, method, path, body string) *httptest.ResponseRecorder {
	mux := http.NewServeMux()
	srv.registerRoutes(mux)

	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, svcRequest(method, path, body, campaignsSubject))
	return rec
}

func descriptorBody(t *testing.T, clientIDRef, clientSecretRef, profile string) string {
	t.Helper()
	body, err := json.Marshal(putTokenRequest{
		Descriptor: &tokenmint.Descriptor{
			Kind:            tokenmint.KindOAuth2ClientCredentials,
			GrantProfile:    profile,
			ClientIDRef:     clientIDRef,
			ClientSecretRef: clientSecretRef,
		},
	})
	if err != nil {
		t.Fatalf("marshal body: %v", err)
	}
	return string(body)
}

func TestSvcPutDescriptor_HappyPath(t *testing.T) {
	srv, store := descriptorTestServer(t)

	body := descriptorBody(t,
		"accounts/ozon/123/performance/client_id",
		"accounts/ozon/123/performance/client_secret",
		"ozon-performance")

	w := serveSvc(srv, http.MethodPut, "/svc/tokens/accounts/ozon/123/performance/read", body)

	if w.Code != 200 {
		t.Fatalf("status = %d, body = %s", w.Code, w.Body.String())
	}

	stored, ok := store.entries["accounts/ozon/123/performance/read"]
	if !ok {
		t.Fatal("descriptor was not written")
	}
	if stored.Descriptor == nil {
		t.Fatal("stored entry is not a descriptor")
	}
	if len(stored.EncryptedToken) != 0 {
		t.Error("a descriptor must not be stored with token bytes")
	}
}

func TestSvcPutDescriptor_RejectsCrossNamespaceRefs(t *testing.T) {
	tests := []struct {
		name            string
		clientIDRef     string
		clientSecretRef string
	}{
		{
			name:            "other tenant",
			clientIDRef:     "accounts/ozon/999/performance/client_id",
			clientSecretRef: "accounts/ozon/999/performance/client_secret",
		},
		{
			name:            "outside the service prefix entirely",
			clientIDRef:     "accounts/ozon/123/performance/client_id",
			clientSecretRef: "shared/wildberries/client_secret",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			srv, store := descriptorTestServer(t)
			body := descriptorBody(t, tc.clientIDRef, tc.clientSecretRef, "ozon-performance")

			w := serveSvc(srv, http.MethodPut, "/svc/tokens/accounts/ozon/123/performance/read", body)

			if w.Code == 200 {
				t.Fatalf("descriptor with ref %q was accepted", tc.clientSecretRef)
			}
			if len(store.entries) != 0 {
				t.Error("a rejected descriptor was still written")
			}
		})
	}
}

func TestSvcPutDescriptor_RejectsUnknownProfile(t *testing.T) {
	srv, _ := descriptorTestServer(t)

	body := descriptorBody(t,
		"accounts/ozon/123/performance/client_id",
		"accounts/ozon/123/performance/client_secret",
		"profile-nobody-configured")

	w := serveSvc(srv, http.MethodPut, "/svc/tokens/accounts/ozon/123/performance/read", body)

	if w.Code != 400 {
		t.Fatalf("status = %d, want 400; body = %s", w.Code, w.Body.String())
	}
}

func TestSvcPutDescriptor_RejectedWhenMintingDisabled(t *testing.T) {
	srv, _ := newTestSvcServer(true, map[string]string{campaignsSubject: "accounts/"})

	body := descriptorBody(t,
		"accounts/ozon/123/performance/client_id",
		"accounts/ozon/123/performance/client_secret",
		"ozon-performance")

	w := serveSvc(srv, http.MethodPut, "/svc/tokens/accounts/ozon/123/performance/read", body)

	if w.Code != 503 {
		t.Fatalf("status = %d, want 503 when minting is off; body = %s", w.Code, w.Body.String())
	}
}

func TestSvcPutDescriptor_RejectsValueAndDescriptorTogether(t *testing.T) {
	srv, _ := descriptorTestServer(t)

	body, err := json.Marshal(putTokenRequest{
		Value: "a-real-secret",
		Descriptor: &tokenmint.Descriptor{
			Kind:            tokenmint.KindOAuth2ClientCredentials,
			GrantProfile:    "ozon-performance",
			ClientIDRef:     "accounts/ozon/123/performance/client_id",
			ClientSecretRef: "accounts/ozon/123/performance/client_secret",
		},
	})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	w := serveSvc(srv, http.MethodPut, "/svc/tokens/accounts/ozon/123/performance/read", string(body))

	if w.Code != 400 {
		t.Fatalf("status = %d, want 400; body = %s", w.Code, w.Body.String())
	}
}

func TestSvcPutDescriptor_IsNotCached(t *testing.T) {
	srv, _ := descriptorTestServer(t)

	// Seed a stale minted bearer at the ref, as if one had been minted from
	// the previous credential.
	srv.authSvc.LoadToken("accounts/ozon/123/performance/read", TokenEntry{
		EncryptedToken: []byte("stale-bearer"),
		Passthrough:    true,
		Mint:           &MintInfo{},
	})

	body := descriptorBody(t,
		"accounts/ozon/123/performance/client_id",
		"accounts/ozon/123/performance/client_secret",
		"ozon-performance")

	w := serveSvc(srv, http.MethodPut, "/svc/tokens/accounts/ozon/123/performance/read", body)

	if w.Code != 200 {
		t.Fatalf("status = %d, body = %s", w.Code, w.Body.String())
	}

	// Registering a descriptor must evict any bearer minted from the old
	// credential, and must not cache the descriptor itself.
	if _, cached := srv.authSvc.Entry("accounts/ozon/123/performance/read"); cached {
		t.Error("descriptor registration left an entry in the cache")
	}
}

// TestSvcCopyToken_RefusesDescriptor is the secret-lifetime regression: a copy
// must never turn a minted credential reference into a stored value.
func TestSvcCopyToken_RefusesDescriptor(t *testing.T) {
	srv, store := descriptorTestServer(t)

	store.entries["accounts/ozon/123/performance/read"] = TokenEntry{
		Descriptor: &tokenmint.Descriptor{
			Kind:            tokenmint.KindOAuth2ClientCredentials,
			GrantProfile:    "ozon-performance",
			ClientIDRef:     "accounts/ozon/123/performance/client_id",
			ClientSecretRef: "accounts/ozon/123/performance/client_secret",
		},
		Version: "v1",
	}

	body := `{"source_ref":"accounts/ozon/123/performance/read"}`
	w := serveSvc(srv, http.MethodPost, "/svc/tokens/accounts/ozon/456/performance/read", body)

	if w.Code != 400 {
		t.Fatalf("status = %d, want 400; body = %s", w.Code, w.Body.String())
	}
	if _, copied := store.entries["accounts/ozon/456/performance/read"]; copied {
		t.Fatal("copying a descriptor produced a second entry")
	}
}

// The minting decorator is a read-side wrapper only.
var _ TokenStore = (*MintingTokenStore)(nil)

// TestMintingStoreIsNotMutable pins the wiring invariant that keeps a minted
// bearer from ever becoming a stored secret.
//
// AdminServer.store is a MutableTokenStore, and MintingTokenStore deliberately
// implements no write methods — so passing the decorator to NewAdminServer is
// a compile error, not a runtime bug. (The compiler will reject
// `srv.store.(*MintingTokenStore)` outright as an impossible assertion, which
// is why this checks the interface rather than the field.) Adding UpsertToken
// or DeleteToken to the decorator would silently re-open the hole: the admin
// copy endpoint would then be able to fetch a descriptor ref, receive a live
// minted bearer, and write it to a new ref as a permanent plaintext token.
func TestMintingStoreIsNotMutable(t *testing.T) {
	var decorator any = (*MintingTokenStore)(nil)
	if _, mutable := decorator.(MutableTokenStore); mutable {
		t.Fatal("MintingTokenStore implements MutableTokenStore; a token copy could then materialize a minted bearer as a stored secret")
	}
}
