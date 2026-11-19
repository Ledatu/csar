package coordinator

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/ledatu/csar-core/s3store"
	"github.com/ledatu/csar-core/secret"
	"github.com/ledatu/csar-core/ycloud"
)

func TestS3LifetimeRoundTripBothEncryptionModes(t *testing.T) {
	for _, mode := range []string{"passthrough", "kms"} {
		t.Run(mode, func(t *testing.T) {
			var mu sync.Mutex
			var object []byte
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				mu.Lock()
				defer mu.Unlock()
				w.Header().Set("ETag", `"opaque-version"`)
				switch r.Method {
				case http.MethodPut:
					var err error
					object, err = io.ReadAll(r.Body)
					if err != nil {
						t.Error(err)
					}
				case http.MethodGet:
					_, _ = w.Write(object)
				default:
					t.Error("unexpected object listing/operation", r.Method)
				}
			}))
			defer server.Close()
			client, err := s3store.NewClient(&s3store.Config{Bucket: "fixture", Endpoint: server.URL, Auth: ycloud.AuthConfig{AuthMode: "static", AccessKeyID: secret.NewSecret("fixture"), SecretAccessKey: secret.NewSecret("fixture")}}, quietLogger())
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = client.Close() }()
			store := NewS3TokenStore(client, mode, quietLogger())
			deadline := time.Now().UTC().Add(24 * time.Hour).Truncate(time.Second)
			entry := lifetimeEntry("fixture", &deadline)
			if mode == "kms" {
				entry.KMSKeyID = "fixture-key"
				entry.Passthrough = false
				entry.EncryptedToken = []byte("ciphertext")
			}
			if _, err = store.UpsertToken(context.Background(), "seller/a", entry, TokenMetadata{}); err != nil {
				t.Fatal(err)
			}
			fetched, err := store.FetchOne(context.Background(), "seller/a")
			if err != nil {
				t.Fatal(err)
			}
			if fetched.ExpiresAt == nil || !fetched.ExpiresAt.Equal(deadline) || fetched.CredentialID != entry.CredentialID {
				t.Fatal("stored lifetime or value identity lost")
			}
		})
	}
}

func TestServiceCopyPreservesLifetimeAndIdentity(t *testing.T) {
	server, store := newTestSvcServer(true, map[string]string{"svc:aurumskynet-campaigns": "accounts/"})
	deadline := time.Now().UTC().Add(24 * time.Hour)
	source := "accounts/wildberries/a/preadds/stage/promotion/read"
	target := "accounts/wildberries/a/promotion/read"
	store.entries[source] = lifetimeEntry("fixture", &deadline)
	mux := http.NewServeMux()
	server.registerRoutes(mux)
	request := svcRequest(http.MethodPost, "/svc/tokens/"+target, `{"source_ref":"`+source+`"}`, "svc:aurumskynet-campaigns")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, request)
	copied := store.entries[target]
	if rec.Code != http.StatusOK || copied.ExpiresAt == nil || !copied.ExpiresAt.Equal(deadline) || copied.CredentialID != store.entries[source].CredentialID {
		t.Fatalf("copy lost lifetime/identity: HTTP %d", rec.Code)
	}
}
