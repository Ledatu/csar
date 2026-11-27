package router

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ledatu/csar/internal/config"
)

func TestRetryMiddlewareRequiresExplicitBudget(t *testing.T) {
	for _, tc := range []struct {
		name           string
		retry          *config.RetryConfig
		wantCalls      int
		wantMiddleware bool
	}{
		{name: "absent", wantCalls: 1},
		{name: "empty", retry: &config.RetryConfig{}, wantCalls: 1},
		{name: "backoff-only", retry: &config.RetryConfig{Backoff: config.Duration{Duration: time.Nanosecond}}, wantCalls: 1},
		{name: "legacy-one-attempt", retry: &config.RetryConfig{MaxAttempts: 1}, wantCalls: 1},
		{name: "explicit-retry", retry: &config.RetryConfig{MaxAttempts: 2, Backoff: config.Duration{Duration: time.Nanosecond}}, wantCalls: 2, wantMiddleware: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var calls atomic.Int32
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls.Add(1); w.WriteHeader(502) }))
			defer upstream.Close()
			cfg := newTestConfig(map[string]config.PathConfig{"/x": {"get": {Backend: config.BackendConfig{TargetURL: upstream.URL}, Retry: tc.retry}}})
			r, err := New(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)))
			if err != nil {
				t.Fatal(err)
			}
			defer r.Close()
			if got := r.routes["GET:/x"].retryHandler != nil; got != tc.wantMiddleware {
				t.Fatalf("retry middleware=%v", got)
			}
			rec := httptest.NewRecorder()
			r.ServeHTTP(rec, httptest.NewRequest("GET", "/x", nil))
			if int(calls.Load()) != tc.wantCalls || rec.Code != 502 {
				t.Fatalf("calls=%d status=%d", calls.Load(), rec.Code)
			}
		})
	}
}
