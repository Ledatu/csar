package coordinator

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ledatu/csar-core/tokenmint"
)

// fakeStore is an in-memory TokenStore for decorator tests.
type fakeStore struct {
	entries map[string]TokenEntry
	fetches atomic.Int64
}

func newFakeStore() *fakeStore {
	return &fakeStore{entries: make(map[string]TokenEntry)}
}

func (f *fakeStore) putPlaintext(ref, value string) {
	f.entries[ref] = TokenEntry{
		EncryptedToken: []byte(value),
		Passthrough:    true,
		Version:        "v1",
	}
}

func (f *fakeStore) putDescriptor(ref string, d tokenmint.Descriptor) {
	f.entries[ref] = TokenEntry{Descriptor: &d, Version: "v1"}
}

func (f *fakeStore) LoadAll(context.Context) (map[string]TokenEntry, error) {
	out := make(map[string]TokenEntry, len(f.entries))
	for k := range f.entries {
		out[k] = f.entries[k]
	}
	return out, nil
}

func (f *fakeStore) FetchOne(_ context.Context, ref string) (TokenEntry, error) {
	f.fetches.Add(1)
	entry, ok := f.entries[ref]
	if !ok {
		return TokenEntry{}, fmt.Errorf("ref %q: %w", ref, ErrTokenNotFound)
	}
	return entry, nil
}

func (f *fakeStore) Close() error { return nil }

func quietLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// mintTestEnv wires a fake store and a real minter against a stub token
// endpoint.
type mintTestEnv struct {
	store  *fakeStore
	minter *MintingTokenStore
	calls  *atomic.Int64
}

func newMintTestEnv(t *testing.T, scopeSegments int) *mintTestEnv {
	t.Helper()

	var calls atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		n := calls.Add(1)
		fmt.Fprintf(w, `{"access_token":"minted-%d","expires_in":1800,"token_type":"Bearer"}`, n)
	}))
	t.Cleanup(srv.Close)

	u, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatalf("parse url: %v", err)
	}

	cfg := &tokenmint.Config{
		AllowedHosts: []string{u.Hostname()},
		AllowPrivate: true,
		Profiles: map[string]tokenmint.Profile{
			"ozon-performance": {
				TokenURL:               srv.URL,
				BodyStyle:              tokenmint.BodyStyleJSON,
				StaticParams:           map[string]string{"grant_type": "client_credentials"},
				ExpectedTokenType:      "Bearer",
				SecretRefScopeSegments: scopeSegments,
			},
		},
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("validate: %v", err)
	}

	minter, err := tokenmint.New(cfg, quietLogger())
	if err != nil {
		t.Fatalf("new minter: %v", err)
	}

	store := newFakeStore()
	return &mintTestEnv{
		store:  store,
		minter: NewMintingTokenStore(store, minter, cfg, quietLogger()),
		calls:  &calls,
	}
}

func okDescriptor() tokenmint.Descriptor {
	return tokenmint.Descriptor{
		Kind:            tokenmint.KindOAuth2ClientCredentials,
		GrantProfile:    "ozon-performance",
		ClientIDRef:     "accounts/ozon/123/performance/client_id",
		ClientSecretRef: "accounts/ozon/123/performance/client_secret",
	}
}

func TestMintingStore_PassesThroughStaticTokens(t *testing.T) {
	env := newMintTestEnv(t, 3)
	env.store.putPlaintext("accounts/wb/999/content/read", "wb-token")

	got, err := env.minter.FetchOne(context.Background(), "accounts/wb/999/content/read")
	if err != nil {
		t.Fatalf("FetchOne: %v", err)
	}

	want := env.store.entries["accounts/wb/999/content/read"]
	if string(got.EncryptedToken) != string(want.EncryptedToken) ||
		got.Passthrough != want.Passthrough ||
		got.Version != want.Version ||
		got.Minted() {
		t.Errorf("static entry was altered: got %+v, want %+v", got, want)
	}
	if env.calls.Load() != 0 {
		t.Errorf("a static token triggered %d upstream mints, want 0", env.calls.Load())
	}
}

func TestMintingStore_MintsDescriptor(t *testing.T) {
	env := newMintTestEnv(t, 3)
	env.store.putDescriptor("accounts/ozon/123/performance/read", okDescriptor())
	env.store.putPlaintext("accounts/ozon/123/performance/client_id", "cid")
	env.store.putPlaintext("accounts/ozon/123/performance/client_secret", "sec")

	got, err := env.minter.FetchOne(context.Background(), "accounts/ozon/123/performance/read")
	if err != nil {
		t.Fatalf("FetchOne: %v", err)
	}

	if string(got.EncryptedToken) != "minted-1" {
		t.Errorf("EncryptedToken = %q, want minted-1", got.EncryptedToken)
	}
	if !got.Minted() {
		t.Error("Minted should be true")
	}
	if !got.Passthrough {
		t.Error("Passthrough must be true — a minted bearer has no ciphertext to decrypt")
	}
	if got.KMSKeyID != "" {
		t.Errorf("KMSKeyID = %q, want empty for a minted token", got.KMSKeyID)
	}
	if got.Mint == nil || got.Mint.RefreshAfter.IsZero() || got.Mint.HardExpiry.IsZero() {
		t.Fatal("minted entries must carry both lifetime boundaries")
	}
	if !got.Mint.RefreshAfter.Before(got.Mint.HardExpiry) {
		t.Error("RefreshAfter must precede HardExpiry")
	}
}

// TestMintingStore_RejectsCrossNamespaceRefs is the confused-deputy regression.
// A descriptor must not be usable to read a credential belonging to anyone
// else, because doing so would hand it back as an injectable Bearer header.
func TestMintingStore_RejectsCrossNamespaceRefs(t *testing.T) {
	tests := []struct {
		name       string
		clientID   string
		clientSec  string
		alsoStored map[string]string
	}{
		{
			name:       "another tenant of the same marketplace",
			clientID:   "accounts/ozon/999/performance/client_id",
			clientSec:  "accounts/ozon/999/performance/client_secret",
			alsoStored: map[string]string{"accounts/ozon/999/performance/client_secret": "victim-secret"},
		},
		{
			name:       "another marketplace entirely",
			clientID:   "accounts/wb/123/performance/client_id",
			clientSec:  "accounts/wb/123/performance/client_secret",
			alsoStored: map[string]string{"accounts/wb/123/performance/client_secret": "victim-secret"},
		},
		{
			name:       "a shared platform credential",
			clientID:   "accounts/ozon/123/performance/client_id",
			clientSec:  "shared/wildberries/client_secret",
			alsoStored: map[string]string{"shared/wildberries/client_secret": "platform-secret"},
		},
		{
			name:      "path traversal out of the namespace",
			clientID:  "accounts/ozon/123/performance/client_id",
			clientSec: "accounts/ozon/123/../999/performance/client_secret",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			env := newMintTestEnv(t, 3)

			d := okDescriptor()
			d.ClientIDRef = tc.clientID
			d.ClientSecretRef = tc.clientSec
			env.store.putDescriptor("accounts/ozon/123/performance/read", d)
			env.store.putPlaintext("accounts/ozon/123/performance/client_id", "cid")
			env.store.putPlaintext("accounts/ozon/123/performance/client_secret", "sec")
			for ref, val := range tc.alsoStored {
				env.store.putPlaintext(ref, val)
			}

			_, err := env.minter.FetchOne(context.Background(), "accounts/ozon/123/performance/read")
			if err == nil {
				t.Fatal("FetchOne accepted a descriptor pointing outside its namespace")
			}
			if env.calls.Load() != 0 {
				t.Errorf("the credential was sent upstream despite the scope violation (%d calls)", env.calls.Load())
			}
		})
	}
}

func TestMintingStore_ScopeViolationIsIdentifiable(t *testing.T) {
	env := newMintTestEnv(t, 3)

	d := okDescriptor()
	d.ClientSecretRef = "shared/wildberries/client_secret"
	env.store.putDescriptor("accounts/ozon/123/performance/read", d)
	env.store.putPlaintext("accounts/ozon/123/performance/client_id", "cid")
	env.store.putPlaintext("shared/wildberries/client_secret", "platform-secret")

	_, err := env.minter.FetchOne(context.Background(), "accounts/ozon/123/performance/read")
	if !errors.Is(err, ErrDescriptorScopeViolation) {
		t.Fatalf("err = %v, want ErrDescriptorScopeViolation", err)
	}
	if statusForFetchError("ref", err) == nil {
		t.Fatal("expected a gRPC status for the violation")
	}
}

func TestMintingStore_RejectsNestedDescriptor(t *testing.T) {
	env := newMintTestEnv(t, 3)

	env.store.putDescriptor("accounts/ozon/123/performance/read", okDescriptor())
	env.store.putPlaintext("accounts/ozon/123/performance/client_id", "cid")
	// The secret ref resolves to another descriptor rather than a value.
	env.store.putDescriptor("accounts/ozon/123/performance/client_secret", okDescriptor())

	_, err := env.minter.FetchOne(context.Background(), "accounts/ozon/123/performance/read")
	if !errors.Is(err, ErrNestedDescriptor) {
		t.Fatalf("err = %v, want ErrNestedDescriptor", err)
	}
}

func TestMintingStore_RejectsUnknownProfile(t *testing.T) {
	env := newMintTestEnv(t, 3)

	d := okDescriptor()
	d.GrantProfile = "not-configured"
	env.store.putDescriptor("accounts/ozon/123/performance/read", d)
	env.store.putPlaintext("accounts/ozon/123/performance/client_id", "cid")
	env.store.putPlaintext("accounts/ozon/123/performance/client_secret", "sec")

	_, err := env.minter.FetchOne(context.Background(), "accounts/ozon/123/performance/read")
	if !errors.Is(err, tokenmint.ErrUnknownProfile) {
		t.Fatalf("err = %v, want ErrUnknownProfile", err)
	}
	if env.calls.Load() != 0 {
		t.Errorf("an unknown profile reached the network (%d calls)", env.calls.Load())
	}
}

func TestMintingStore_ReportsMissingCredential(t *testing.T) {
	env := newMintTestEnv(t, 3)
	env.store.putDescriptor("accounts/ozon/123/performance/read", okDescriptor())
	env.store.putPlaintext("accounts/ozon/123/performance/client_id", "cid")
	// client_secret is absent.

	_, err := env.minter.FetchOne(context.Background(), "accounts/ozon/123/performance/read")
	if !errors.Is(err, ErrTokenNotFound) {
		t.Fatalf("err = %v, want ErrTokenNotFound", err)
	}
}

func TestMintingStore_LoadAllDropsDescriptors(t *testing.T) {
	env := newMintTestEnv(t, 3)
	env.store.putDescriptor("accounts/ozon/123/performance/read", okDescriptor())
	env.store.putPlaintext("accounts/wb/1/content/read", "wb")

	all, err := env.minter.LoadAll(context.Background())
	if err != nil {
		t.Fatalf("LoadAll: %v", err)
	}
	if _, present := all["accounts/ozon/123/performance/read"]; present {
		t.Error("LoadAll returned a descriptor entry")
	}
	if _, present := all["accounts/wb/1/content/read"]; !present {
		t.Error("LoadAll dropped a static token")
	}
	if env.calls.Load() != 0 {
		t.Errorf("LoadAll triggered %d mints, want 0", env.calls.Load())
	}
}

// TestDescriptorIsNeverServedAsAToken is the failsafe: even if the minting
// decorator were bypassed, the raw entry has no token bytes and isValid must
// refuse it.
func TestDescriptorIsNeverServedAsAToken(t *testing.T) {
	svc := NewAuthService(quietLogger())
	d := okDescriptor()
	entry := TokenEntry{Descriptor: &d, Version: "v1"}

	if svc.isValid("accounts/ozon/123/performance/read", entry) {
		t.Fatal("isValid accepted a descriptor entry — it could be served to a router as a credential")
	}
}

func TestRefScope(t *testing.T) {
	tests := []struct {
		ref     string
		n       int
		want    string
		wantErr bool
	}{
		{ref: "accounts/ozon/123/performance/read", n: 3, want: "accounts/ozon/123/"},
		{ref: "accounts/ozon/123/performance/read", n: 1, want: "accounts/"},
		{ref: "accounts/ozon/123", n: 3, wantErr: true},
		{ref: "single", n: 1, wantErr: true},
	}

	for _, tc := range tests {
		got, err := refScope(tc.ref, tc.n)
		if tc.wantErr {
			if err == nil {
				t.Errorf("refScope(%q, %d) = %q, want error", tc.ref, tc.n, got)
			}
			continue
		}
		if err != nil {
			t.Errorf("refScope(%q, %d): %v", tc.ref, tc.n, err)
			continue
		}
		if got != tc.want {
			t.Errorf("refScope(%q, %d) = %q, want %q", tc.ref, tc.n, got, tc.want)
		}
	}
}

// TestRefScopeRejectsSiblingPrefix guards the trailing separator: without it,
// "accounts/ozon/12" would prefix-match "accounts/ozon/1234/...".
func TestRefScopeRejectsSiblingPrefix(t *testing.T) {
	env := newMintTestEnv(t, 3)

	d := okDescriptor()
	d.ClientIDRef = "accounts/ozon/1234/performance/client_id"
	d.ClientSecretRef = "accounts/ozon/1234/performance/client_secret"
	env.store.putDescriptor("accounts/ozon/123/performance/read", d)
	env.store.putPlaintext("accounts/ozon/1234/performance/client_id", "other-cid")
	env.store.putPlaintext("accounts/ozon/1234/performance/client_secret", "other-secret")

	_, err := env.minter.FetchOne(context.Background(), "accounts/ozon/123/performance/read")
	if !errors.Is(err, ErrDescriptorScopeViolation) {
		t.Fatalf("err = %v, want ErrDescriptorScopeViolation for a sibling-prefix ref", err)
	}
}

func TestAuthServiceServesMintedTokenAcrossFailedRefresh(t *testing.T) {
	env := newMintTestEnv(t, 3)
	env.store.putDescriptor("accounts/ozon/123/performance/read", okDescriptor())
	env.store.putPlaintext("accounts/ozon/123/performance/client_id", "cid")
	env.store.putPlaintext("accounts/ozon/123/performance/client_secret", "sec")

	svc := NewAuthService(quietLogger())
	svc.SetBackend(env.minter)

	base := time.Now()
	svc.SetClock(func() time.Time { return base })

	entry, err := env.minter.FetchOne(context.Background(), "accounts/ozon/123/performance/read")
	if err != nil {
		t.Fatalf("initial mint: %v", err)
	}
	svc.LoadToken("accounts/ozon/123/performance/read", entry)

	// Inside the usable window the cached token is served without a fetch.
	before := env.store.fetches.Load()
	svc.SetClock(func() time.Time { return base.Add(time.Minute) })
	if _, err := svc.GetEncryptedToken(context.Background(), tokenReq("accounts/ozon/123/performance/read")); err != nil {
		t.Fatalf("GetEncryptedToken: %v", err)
	}
	if env.store.fetches.Load() != before {
		t.Error("a fresh minted token triggered a backend fetch")
	}

	// Past hard expiry it must not be served from cache any more.
	svc.SetClock(func() time.Time { return base.Add(2 * time.Hour) })
	if _, err := svc.GetEncryptedToken(context.Background(), tokenReq("accounts/ozon/123/performance/read")); err != nil {
		t.Fatalf("GetEncryptedToken after expiry: %v", err)
	}
	if env.store.fetches.Load() == before {
		t.Error("an expired minted token was served from cache without re-fetching")
	}
}

func TestStaticTokensNeverExpire(t *testing.T) {
	env := newMintTestEnv(t, 3)
	env.store.putPlaintext("accounts/wb/1/content/read", "wb-token")

	svc := NewAuthService(quietLogger())
	svc.SetBackend(env.minter)

	base := time.Now()
	svc.SetClock(func() time.Time { return base })
	if _, err := svc.GetEncryptedToken(context.Background(), tokenReq("accounts/wb/1/content/read")); err != nil {
		t.Fatalf("GetEncryptedToken: %v", err)
	}

	after := env.store.fetches.Load()
	svc.SetClock(func() time.Time { return base.Add(30 * 24 * time.Hour) })
	if _, err := svc.GetEncryptedToken(context.Background(), tokenReq("accounts/wb/1/content/read")); err != nil {
		t.Fatalf("GetEncryptedToken a month later: %v", err)
	}
	if env.store.fetches.Load() != after {
		t.Error("a stored token was re-fetched — static refs must keep their pre-minting behavior")
	}
}
