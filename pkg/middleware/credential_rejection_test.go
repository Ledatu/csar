package middleware

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ledatu/csar-core/s3store"
	"github.com/ledatu/csar/internal/proxy"
)

type unavailableReporter struct{ calls atomic.Int32 }

func (f *unavailableReporter) GetEncryptedToken(context.Context, string) ([]byte, string, string, error) {
	return []byte("fixture"), "", "v1", nil
}
func (f *unavailableReporter) ReportCredentialRejection(context.Context, string, string, string) error {
	f.calls.Add(1)
	return errors.New("report transport unavailable")
}

func TestEarly401BlocksLocalReuseWhenReportUnavailable(t *testing.T) {
	fetcher := &unavailableReporter{}
	a := NewAuthInjector(fetcher, nil, newTestLogger())
	var calls atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { calls.Add(1); w.WriteHeader(http.StatusUnauthorized) }))
	defer upstream.Close()
	rp, err := proxy.New(upstream.URL)
	if err != nil {
		t.Fatal(err)
	}
	handler := a.Wrap(AuthInjectorConfig{RejectOnUnauthorized: true, TokenRef: "seller/a", InjectHeader: "Authorization"}, rp)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/", nil))
	if rec.Code != http.StatusUnauthorized || fetcher.calls.Load() != 1 {
		t.Fatalf("first rejection code=%d reports=%d", rec.Code, fetcher.calls.Load())
	}
	var wg sync.WaitGroup
	for range 64 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/", nil))
			if w.Code != http.StatusBadGateway {
				t.Errorf("unreported rejection reused: %d", w.Code)
			}
		}()
	}
	wg.Wait()
	if calls.Load() != 1 || fetcher.calls.Load() != 1 {
		t.Fatalf("vendor/report storm: vendor=%d reports=%d", calls.Load(), fetcher.calls.Load())
	}
	key := "seller/a\x00" + s3store.CredentialFingerprint([]byte("fixture"))
	a.rejections.mu.Lock()
	entry := a.rejections.entries[key]
	entry.retryAt = time.Now().Add(-time.Second)
	a.rejections.entries[key] = entry
	a.rejections.mu.Unlock()
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/", nil))
	if calls.Load() != 1 || fetcher.calls.Load() != 2 {
		t.Fatal("demand retry did not retry only the rejection report")
	}
}

func TestDelayedOld401CannotEraseNewLocalQuarantine(t *testing.T) {
	fetcher := &unavailableReporter{}
	a := NewAuthInjector(fetcher, nil, newTestLogger())
	ctx := context.Background()
	newer, older := s3store.CredentialFingerprint([]byte("new")), s3store.CredentialFingerprint([]byte("old"))
	a.rejectCredential(ctx, fetcher, "seller/a", "v2", newer)
	a.rejectCredential(ctx, fetcher, "seller/a", "v1", older)
	if a.credentialAllowed(ctx, fetcher, "seller/a", "v2", newer) || a.credentialAllowed(ctx, fetcher, "seller/a", "v1", older) {
		t.Fatal("late old report revived rejected credential")
	}
	if !a.credentialAllowed(ctx, fetcher, "seller/a", "v3", s3store.CredentialFingerprint([]byte("replacement"))) {
		t.Fatal("old 401 blocked replacement")
	}
}

func TestUnselected401DoesNotConsultOrCreateLocalQuarantine(t *testing.T) {
	fetcher := &unavailableReporter{}
	injector := NewAuthInjector(fetcher, nil, newTestLogger())
	var calls atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { calls.Add(1); w.WriteHeader(http.StatusUnauthorized) }))
	defer upstream.Close()
	rp, err := proxy.New(upstream.URL)
	if err != nil {
		t.Fatal(err)
	}
	ordinary := injector.Wrap(AuthInjectorConfig{TokenRef: "apps/mail/service_key", InjectHeader: "X-API-Key"}, rp)
	for range 2 {
		rec := httptest.NewRecorder()
		ordinary.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/", nil))
		if rec.Code != http.StatusUnauthorized {
			t.Fatal("unselected 401 changed ordinary response behavior")
		}
	}
	if fetcher.calls.Load() != 0 || calls.Load() != 2 {
		t.Fatal("unselected 401 created rejection feedback")
	}
	optedIn := injector.Wrap(AuthInjectorConfig{RejectOnUnauthorized: true, TokenRef: "apps/mail/service_key", InjectHeader: "X-API-Key"}, rp)
	rec := httptest.NewRecorder()
	optedIn.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/", nil))
	if fetcher.calls.Load() != 1 {
		t.Fatal("explicit policy did not report")
	}
	rec = httptest.NewRecorder()
	ordinary.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/", nil))
	if rec.Code != http.StatusUnauthorized || calls.Load() != 4 || fetcher.calls.Load() != 1 {
		t.Fatal("unselected route consulted local quarantine")
	}
}

func TestDirectOptInWithoutReportingFailsClosed(t *testing.T) {
	fetcher := NewStaticTokenFetcher()
	fetcher.Add("apps/mail/service_key", []byte("fixture"), "")
	injector := NewAuthInjector(fetcher, nil, newTestLogger())
	called := false
	handler := injector.Wrap(AuthInjectorConfig{RejectOnUnauthorized: true, TokenRef: "apps/mail/service_key", InjectHeader: "X-API-Key"}, http.HandlerFunc(func(http.ResponseWriter, *http.Request) { called = true }))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/", nil))
	if called || rec.Code != http.StatusBadGateway {
		t.Fatal("unsupported explicit policy silently reached upstream")
	}
}
