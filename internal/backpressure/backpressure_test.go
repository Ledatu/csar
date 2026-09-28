package backpressure

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/ledatu/csar/internal/throttle"
)

func quietLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func TestExtractWaitTime(t *testing.T) {
	m := New(nil, Config{Enabled: true, RespectHeaders: []string{
		"X-Ratelimit-Retry", "Retry-After", "X-RateLimit-Reset",
	}}, nil, quietLogger())

	future := time.Now().Add(90 * time.Second).Unix()
	cases := []struct {
		name    string
		headers http.Header
		min     time.Duration
		max     time.Duration
	}{
		{"wildberries retry", http.Header{"X-Ratelimit-Retry": {"20"}}, 20 * time.Second, 20 * time.Second},
		{"fractional seconds", http.Header{"Retry-After": {"1.5"}}, 1500 * time.Millisecond, 1500 * time.Millisecond},
		{"reset as seconds from now", http.Header{"X-Ratelimit-Reset": {"45"}}, 45 * time.Second, 45 * time.Second},
		{"reset as epoch", http.Header{"X-Ratelimit-Reset": {strconv.FormatInt(future, 10)}}, 85 * time.Second, 90 * time.Second},
		{"header order wins", http.Header{"X-Ratelimit-Retry": {"3"}, "Retry-After": {"60"}}, 3 * time.Second, 3 * time.Second},
		{"garbage falls through", http.Header{"X-Ratelimit-Retry": {"soon"}, "Retry-After": {"4"}}, 4 * time.Second, 4 * time.Second},
		{"nothing usable", http.Header{"X-Ratelimit-Reset": {"0"}}, 0, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := m.extractWaitTime(tc.headers)
			if got < tc.min || got > tc.max {
				t.Errorf("extractWaitTime() = %s, want within [%s, %s]", got, tc.min, tc.max)
			}
		})
	}
}

type recordingThrottler struct {
	paths []string
	waits []time.Duration
}

func (r *recordingThrottler) Wait(context.Context) error { return nil }
func (r *recordingThrottler) Waiting() int64             { return 0 }
func (r *recordingThrottler) UpdateLimit(float64, int)   {}
func (r *recordingThrottler) SuspendRequestFor(req *http.Request, d time.Duration) error {
	r.paths = append(r.paths, req.URL.Path)
	r.waits = append(r.waits, d)
	return nil
}

func upstream429(retry string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Ratelimit-Retry", retry)
		w.WriteHeader(http.StatusTooManyRequests)
		_, _ = w.Write([]byte(`{"title":"too many requests"}`))
	})
}

func TestSuspendsTheRequestsBucketAndAnswersThrottled(t *testing.T) {
	rec := &recordingThrottler{}
	m := New(upstream429("7"), Config{
		Enabled:        true,
		RespectHeaders: []string{"X-Ratelimit-Retry"},
		SuspendBucket:  true,
	}, rec, quietLogger())

	w := httptest.NewRecorder()
	m.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/ext/s777/items", nil))

	if len(rec.paths) != 1 || rec.paths[0] != "/ext/s777/items" || rec.waits[0] != 7*time.Second {
		t.Fatalf("suspensions = %v %v, want one 7s suspension for the request", rec.paths, rec.waits)
	}
	if w.Code != http.StatusServiceUnavailable || w.Header().Get("X-CSAR-Status") != "throttled" {
		t.Fatalf("got %d %q, want 503 throttled", w.Code, w.Header().Get("X-CSAR-Status"))
	}
	if w.Header().Get("Retry-After") != "7" || w.Header().Get("X-CSAR-Wait-MS") != "7000" {
		t.Errorf("Retry-After=%q X-CSAR-Wait-MS=%q, want 7 / 7000",
			w.Header().Get("Retry-After"), w.Header().Get("X-CSAR-Wait-MS"))
	}
}

func TestLocalThrottlerStillSuspendsRouteWide(t *testing.T) {
	local := throttle.New(100, 10, time.Second)
	m := New(upstream429("12"), Config{
		Enabled:        true,
		RespectHeaders: []string{"X-Ratelimit-Retry"},
		SuspendBucket:  true,
	}, local, quietLogger())

	m.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/x", nil))

	if got := local.EstimateRetryAfter(); got < 11 || got > 12 {
		t.Errorf("EstimateRetryAfter() = %d, want the 12s suspension", got)
	}
}

func TestNoSuspensionWithoutSuspendBucket(t *testing.T) {
	rec := &recordingThrottler{}
	m := New(upstream429("7"), Config{
		Enabled:        true,
		RespectHeaders: []string{"X-Ratelimit-Retry"},
	}, rec, quietLogger())

	m.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/x", nil))

	if len(rec.paths) != 0 {
		t.Errorf("suspended %v without suspend_bucket", rec.paths)
	}
}
