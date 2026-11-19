package coordinator

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ledatu/csar/internal/config"
	"github.com/ledatu/csar/internal/router"
	"github.com/ledatu/csar/pkg/middleware"
)

func TestUniversalOwnerRouterAndRejectionPolicy(t *testing.T) {
	cases := []struct {
		name, header, format, value string
		knownExpiry                 bool
	}{
		{"opaque API key", "X-Remote-Key", "{token}", "opaque-service-key", false},
		// This deliberately JWT-looking value claims exp=1. CSAR must not infer
		// expiry from its shape: only explicit owner metadata controls lifetime.
		{"opaque bearer value", "Authorization", "Bearer {token}", "eyJhbGciOiJub25lIn0.eyJleHAiOjF9.not-a-signature", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := newLifetimeEnv(t)
			const subject = "svc:external-credential-owner"
			const ref = "apps/reporting/customer_a/remote_key"
			const clientRef = "apps/reporting/customer_a/client_id"
			owner, _ := newTestSvcServer(true, map[string]string{subject: "apps/reporting/"})
			owner.authSvc = e.auth[0]
			owner.coord = e.reports.coord
			owner.store = e.store
			mux := http.NewServeMux()
			owner.registerRoutes(mux)
			put := func(target, value string, expiry *time.Time) string {
				t.Helper()
				body, err := json.Marshal(struct {
					Value     string     `json:"value"`
					ExpiresAt *time.Time `json:"expires_at,omitempty"`
				}{value, expiry})
				if err != nil {
					t.Fatal(err)
				}
				rec := httptest.NewRecorder()
				mux.ServeHTTP(rec, svcRequest(http.MethodPut, "/svc/tokens/"+target, string(body), subject))
				if rec.Code != http.StatusOK {
					t.Fatalf("generic owner write failed: %d", rec.Code)
				}
				var receipt tokenMutationResponse
				if err = json.Unmarshal(rec.Body.Bytes(), &receipt); err != nil {
					t.Fatal(err)
				}
				return receipt.Version
			}
			var expiry *time.Time
			if tc.knownExpiry {
				deadline := time.Now().UTC().Add(24 * time.Hour)
				expiry = &deadline
			}
			oldVersion := put(ref, tc.value, expiry)
			put(clientRef, "client-a", nil)
			var revoked atomic.Bool
			var expected atomic.Value
			expected.Store(tc.value)
			var vendorCalls atomic.Int32
			vendor := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				vendorCalls.Add(1)
				if revoked.Load() || r.Header.Get(tc.header) != middleware.FormatToken(tc.format, expected.Load().(string)) {
					w.WriteHeader(http.StatusUnauthorized)
					return
				}
				w.WriteHeader(http.StatusOK)
			}))
			defer vendor.Close()
			security := config.SecurityConfigs{{TokenRef: ref, InjectHeader: tc.header, InjectFormat: tc.format}}
			dual := append(append(config.SecurityConfigs(nil), security...), config.SecurityConfig{TokenRef: clientRef, InjectHeader: "X-Client-ID"})
			cfg := &config.Config{ListenAddr: ":0", Paths: map[string]config.PathConfig{
				"/submit":     {"POST": {Backend: config.BackendConfig{TargetURL: vendor.URL}, Security: dual}},
				"/unselected": {"GET": {Backend: config.BackendConfig{TargetURL: vendor.URL}, Security: dual}},
			}}
			injector := middleware.NewAuthInjector(newCredentialRPCFetcher(t, e), &mockKMSProvider{}, quietLogger())
			gateway, err := router.New(cfg, quietLogger(), router.WithAuthInjector(injector), router.WithCredentialRejectionRoutes("POST:/submit#"+tc.header))
			if err != nil {
				t.Fatal(err)
			}
			defer gateway.Close()
			request := func(method, path string) int {
				t.Helper()
				rec := httptest.NewRecorder()
				gateway.ServeHTTP(rec, httptest.NewRequest(method, path, strings.NewReader(`{"job":1}`)))
				return rec.Code
			}
			revoked.Store(true)
			for range 2 {
				if code := request(http.MethodGet, "/unselected"); code != http.StatusUnauthorized {
					t.Fatalf("unselected 401 poisoned injection: %d", code)
				}
			}
			for _, target := range []string{ref, clientRef} {
				state, stateErr := e.states.GetTokenState(context.Background(), target)
				if stateErr != nil || state.RejectedID != "" {
					t.Fatal("unselected multi-credential route quarantined a ref")
				}
			}
			revoked.Store(false)
			if code := request(http.MethodPost, "/submit"); code != http.StatusOK {
				t.Fatalf("ordinary application token not usable: %d", code)
			}
			revoked.Store(true)
			before := vendorCalls.Load()
			if code := request(http.MethodPost, "/submit"); code != http.StatusUnauthorized || vendorCalls.Load() != before+1 {
				t.Fatal("selected rejection replayed external POST")
			}
			if code := request(http.MethodPost, "/submit"); code != http.StatusBadGateway || vendorCalls.Load() != before+1 {
				t.Fatal("selected rejected value reused")
			}
			clientState, clientErr := e.states.GetTokenState(context.Background(), clientRef)
			if clientErr != nil || clientState.RejectedID != "" {
				t.Fatal("explicit target quarantined auxiliary credential")
			}
			replacement := tc.value + "-replacement"
			put(ref, replacement, expiry)
			expected.Store(replacement)
			revoked.Store(false)
			if code := request(http.MethodPost, "/submit"); code != http.StatusOK {
				t.Fatalf("owner rotation did not recover generic route: %d", code)
			}
			e.report(t, ref, oldVersion, tc.value)
			if code := request(http.MethodPost, "/submit"); code != http.StatusOK {
				t.Fatal("late old 401 poisoned generic replacement")
			}
		})
	}
}
