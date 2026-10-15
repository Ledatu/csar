package router

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/ledatu/csar/internal/config"
)

func TestPolicyBackpressureNeverReplaysWhenRetriesDisabled(t *testing.T) {
	for _, method := range []string{http.MethodGet, http.MethodPost} {
		for _, status := range []int{429, 502, 503, 504} {
			t.Run(fmt.Sprintf("%s/%d", method, status), func(t *testing.T) {
				var hits atomic.Int32
				upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
					hits.Add(1)
					w.Header().Set("X-Ratelimit-Retry", "0.001")
					w.WriteHeader(status)
				}))
				defer upstream.Close()
				cfg, err := config.ParseBytes([]byte(fmt.Sprintf(`
listen_addr: ":8080"
throttling_policies:
  wb:
    rate: 100
    burst: 10
    adaptive_backpressure:
      enabled: true
      respect_headers: [X-Ratelimit-Retry, Retry-After, X-Ratelimit-Reset]
      suspend_bucket: true
paths:
  /report:
    %s:
      x-csar-backend: {target_url: %q}
      x-csar-traffic: wb
      x-csar-retry: {max_attempts: 1, auto_retry_429: false}
      x-csar-protocol: {transparent_retry: false}
`, method, upstream.URL)))
				if err != nil {
					t.Fatal(err)
				}
				router, err := New(cfg, newTestLogger())
				if err != nil {
					t.Fatal(err)
				}
				rec := httptest.NewRecorder()
				router.ServeHTTP(rec, httptest.NewRequest(method, "/report", nil))
				wantStatus := status
				if status == http.StatusTooManyRequests {
					wantStatus = http.StatusServiceUnavailable
					if rec.Header().Get("X-CSAR-Status") != "throttled" {
						t.Fatal("policy backpressure was not enabled")
					}
				}
				if hits.Load() != 1 || rec.Code != wantStatus {
					t.Fatalf("upstream hits=%d response=%d, want one attempt and status %d", hits.Load(), rec.Code, wantStatus)
				}
			})
		}
	}
}
