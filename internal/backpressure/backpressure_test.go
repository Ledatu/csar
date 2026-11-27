package backpressure

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/ledatu/csar/internal/throttle"
)

func quietLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

type trackedRequestBody struct {
	io.Reader
	closed bool
}

func (b *trackedRequestBody) Close() error { b.closed = true; return nil }

type brokenRequestBody struct{ closed bool }

func (*brokenRequestBody) Read(p []byte) (int, error) {
	return copy(p, "partial sensitive body"), io.ErrUnexpectedEOF
}

func (b *brokenRequestBody) Close() error { b.closed = true; return nil }

func TestMiddlewareRejectsPartialRequestBody(t *testing.T) {
	var calls int
	m := New(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { calls++ }), Config{Enabled: true, AutoRetry: true}, nil, quietLogger())
	req := httptest.NewRequest(http.MethodPost, "/test", nil)
	body := &brokenRequestBody{}
	req.Body = body
	rr := httptest.NewRecorder()
	m.ServeHTTP(rr, req)
	if rr.Code != http.StatusBadRequest || calls != 0 || !body.closed {
		t.Fatalf("status=%d upstream calls=%d body closed=%v", rr.Code, calls, body.closed)
	}
	if strings.Contains(rr.Body.String(), "sensitive") {
		t.Fatal("request content leaked into the error response")
	}
}

func TestOversizedBodyBypassPreservesBodyAndCloser(t *testing.T) {
	want := strings.Repeat("payload", 20)
	body := &trackedRequestBody{Reader: strings.NewReader(want)}
	m := New(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got, err := io.ReadAll(r.Body)
		if err != nil || string(got) != want {
			t.Errorf("forwarded body differs: %v", err)
		}
		if err := r.Body.Close(); err != nil {
			t.Error(err)
		}
		w.WriteHeader(http.StatusNoContent)
	}), Config{Enabled: true, AutoRetry: true, MaxBodyBuffer: 4}, nil, quietLogger())
	req := httptest.NewRequest(http.MethodPost, "/test", nil)
	req.Body, req.ContentLength = body, -1
	rr := httptest.NewRecorder()
	m.ServeHTTP(rr, req)
	if rr.Code != http.StatusNoContent || !body.closed {
		t.Fatalf("status=%d original body closed=%v", rr.Code, body.closed)
	}
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
		{"absurd seconds are clamped", http.Header{"Retry-After": {"1e300"}}, maxUpstreamWait, maxUpstreamWait},
		{"far epoch is clamped", http.Header{"X-Ratelimit-Reset": {"99999999999"}}, maxUpstreamWait, maxUpstreamWait},
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

func TestObservationWithoutRetryPreservesRequestBody(t *testing.T) {
	for _, length := range []int64{-1, 4, 1000} {
		body := &brokenRequestBody{}
		calls := 0
		req := httptest.NewRequest("POST", "/", nil)
		req.Body = body
		req.ContentLength = length
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			calls++
			if r.Body != body || body.closed || r.ContentLength != length {
				t.Fatal("observation-only backpressure changed body")
			}
			w.Header().Set("Retry-After", "10")
			w.WriteHeader(429)
		})
		m := New(handler, Config{Enabled: true, MaxBodyBuffer: 4}, nil, quietLogger())
		rec := httptest.NewRecorder()
		m.ServeHTTP(rec, req)
		wantStatus := http.StatusServiceUnavailable
		if length > 4 {
			wantStatus = http.StatusTooManyRequests // existing oversized-request bypass
		}
		if calls != 1 || rec.Code != wantStatus || body.closed {
			t.Fatalf("length=%d calls=%d status=%d want=%d closed=%v", length, calls, rec.Code, wantStatus, body.closed)
		}
	}
}
