package coordinator

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/ledatu/csar-core/apierror"
	"github.com/ledatu/csar-core/tokenmint"
	"github.com/ledatu/csar/pkg/middleware"
	csarv1 "github.com/ledatu/csar/proto/csar/v1"
	"google.golang.org/grpc"
)

type credentialAuthClient struct {
	csarv1.AuthServiceClient
	server *AuthServiceImpl
}

func (c credentialAuthClient) GetEncryptedToken(ctx context.Context, req *csarv1.TokenRequest, _ ...grpc.CallOption) (*csarv1.TokenResponse, error) {
	return c.server.GetEncryptedToken(ctx, req)
}

func TestCredentialFailureSurvivesCoordinatorAndRouter(t *testing.T) {
	for _, tc := range []struct {
		name       string
		status     int
		body, code string
		slow       bool
	}{
		{name: "invalid secret", status: 401, body: `{"error":"invalid_client","client_secret":"synthetic-secret"}`, code: apierror.CodeCredentialInvalid},
		{name: "quota", status: 429, body: `{"error":"quota"}`, code: apierror.CodeCredentialThrottled},
		{name: "malformed", status: 200, body: `{"unexpected":"synthetic-secret"}`, code: apierror.CodeCredentialMalformed},
		{name: "timeout", slow: true, code: apierror.CodeCredentialUnavailable},
	} {
		t.Run(tc.name, func(t *testing.T) {
			endpoint := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				_, _ = io.Copy(io.Discard, r.Body)
				if tc.slow {
					select {
					case <-r.Context().Done():
					case <-time.After(100 * time.Millisecond):
					}
					return
				}
				w.WriteHeader(tc.status)
				_, _ = io.WriteString(w, tc.body)
			}))
			defer endpoint.Close()
			parsed, err := url.Parse(endpoint.URL)
			if err != nil {
				t.Fatal(err)
			}
			cfg := &tokenmint.Config{AllowedHosts: []string{parsed.Hostname()}, AllowPrivate: true, Profiles: map[string]tokenmint.Profile{"ozon-performance": {TokenURL: endpoint.URL, BodyStyle: tokenmint.BodyStyleJSON, SecretRefScopeSegments: 3, Timeout: 20 * time.Millisecond}}}
			if err = cfg.Validate(); err != nil {
				t.Fatal(err)
			}
			minter, err := tokenmint.New(cfg, quietLogger())
			if err != nil {
				t.Fatal(err)
			}
			store := newFakeStore()
			store.putDescriptor("accounts/ozon/123/performance/read", okDescriptor())
			store.putPlaintext("accounts/ozon/123/performance/client_id", "synthetic-client")
			store.putPlaintext("accounts/ozon/123/performance/client_secret", "synthetic-secret")
			coordinator := NewAuthService(quietLogger())
			coordinator.SetBackend(NewMintingTokenStore(store, minter, cfg, quietLogger()))
			fetcher := middleware.NewCoordinatorTokenFetcher(credentialAuthClient{server: coordinator})
			injector := middleware.NewAuthInjector(fetcher, nil, quietLogger())
			called := false
			handler := injector.Wrap(middleware.AuthInjectorConfig{TokenRef: "accounts/ozon/123/performance/read", InjectHeader: "Authorization", OnKMSError: "fail_closed"}, http.HandlerFunc(func(http.ResponseWriter, *http.Request) { called = true }))
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "http://router/staged-performance", nil))
			if called || response.Code != 502 || apierror.CredentialFailureCode(response.Body.Bytes()) != tc.code {
				t.Fatalf("unsafe or unclassified failure: %d %s", response.Code, response.Body.String())
			}
			if strings.Contains(response.Body.String(), "synthetic-secret") || strings.Contains(response.Body.String(), "accounts/") {
				t.Fatal("credential material escaped the token plane")
			}
		})
	}
}
