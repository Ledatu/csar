package retry

import (
	"bytes"
	"compress/gzip"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestMiddlewareStreamsBeforeHandlerReturns(t *testing.T) {
	for _, attempts := range []int{1, 3} {
		for _, code := range []int{http.StatusOK, http.StatusNotFound} {
			t.Run(fmt.Sprintf("attempts%d-status%d", attempts, code), func(t *testing.T) {
				rec := httptest.NewRecorder()
				next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					w.Header().Set("Trailer", "X-Final")
					w.WriteHeader(code)
					_, _ = io.WriteString(w, "first")
					if err := http.NewResponseController(w).Flush(); err != nil {
						t.Fatal(err)
					}
					if rec.Body.String() != "first" || !rec.Flushed {
						t.Fatal("response was buffered until handler completion")
					}
					w.Header().Set("X-Final", "complete")
					_, _ = io.WriteString(w, "last")
				})
				New(next, Config{MaxAttempts: attempts}, testLogger()).ServeHTTP(rec, httptest.NewRequest("GET", "/", nil))
				resp := rec.Result()
				defer resp.Body.Close()
				if rec.Code != code || rec.Body.String() != "firstlast" || resp.Trailer.Get("X-Final") != "complete" {
					t.Fatalf("status=%d body=%s trailer=%v", rec.Code, rec.Body.String(), resp.Trailer)
				}
			})
		}
	}
}

func TestMiddlewareSingleAttemptDoesNotReadOrReplaceRequestBody(t *testing.T) {
	body := &brokenRequestBody{}
	req := httptest.NewRequest("GET", "/", nil)
	req.Body = body
	req.ContentLength = -1
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r != req || r.Body != body || body.closed || r.ContentLength != -1 {
			t.Fatal("single attempt changed request body")
		}
		w.WriteHeader(http.StatusNoContent)
	})
	rec := httptest.NewRecorder()
	New(next, Config{MaxAttempts: 1}, testLogger()).ServeHTTP(rec, req)
	if rec.Code != http.StatusNoContent {
		t.Fatal(rec.Code)
	}
}

func TestMiddlewareFinalFailureStreamsAndClearsPreviousHeaders(t *testing.T) {
	rec := httptest.NewRecorder()
	calls := 0
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if calls == 1 {
			w.Header().Set("Content-Encoding", "gzip")
			w.Header().Set("Set-Cookie", "failed=1")
			w.Header().Set("Content-Length", "500")
			w.WriteHeader(http.StatusBadGateway)
			_, _ = io.WriteString(w, "discard this")
			return
		}
		w.WriteHeader(http.StatusBadGateway)
		_, _ = io.WriteString(w, "final")
		if rec.Body.String() != "final" {
			t.Fatal("final attempt is buffered")
		}
	})
	New(next, Config{MaxAttempts: 2, Backoff: time.Nanosecond}, testLogger()).ServeHTTP(rec, httptest.NewRequest("GET", "/", nil))
	if calls != 2 || rec.Code != 502 || rec.Body.String() != "final" {
		t.Fatalf("calls=%d status=%d body=%s", calls, rec.Code, rec.Body.String())
	}
	for _, key := range []string{"Content-Encoding", "Set-Cookie", "Content-Length"} {
		if rec.Header().Get(key) != "" {
			t.Fatalf("failed response header leaked: %s", key)
		}
	}
}

func TestMiddlewareCancellationReturnsLastFailure(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	calls := 0
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.Header().Set("X-Error", "original")
		w.WriteHeader(503)
		_, _ = io.WriteString(w, "original error")
		cancel()
	})
	rec := httptest.NewRecorder()
	New(next, Config{MaxAttempts: 3, Backoff: time.Hour}, testLogger()).ServeHTTP(rec, httptest.NewRequest("GET", "/", nil).WithContext(ctx))
	if calls != 1 || rec.Code != 503 || rec.Body.String() != "original error" || rec.Header().Get("X-Error") != "original" {
		t.Fatalf("calls=%d status=%d body=%s", calls, rec.Code, rec.Body.String())
	}
}

func TestMiddlewarePreservesGzipBytes(t *testing.T) {
	var encoded bytes.Buffer
	zw := gzip.NewWriter(&encoded)
	_, _ = io.WriteString(zw, strings.Repeat("JSON data", 100))
	_ = zw.Close()
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Encoding", "gzip")
		_, _ = w.Write(encoded.Bytes())
	})
	rec := httptest.NewRecorder()
	New(next, Config{MaxAttempts: 3}, testLogger()).ServeHTTP(rec, httptest.NewRequest("GET", "/", nil))
	if rec.Header().Get("Content-Encoding") != "gzip" || !bytes.Equal(rec.Body.Bytes(), encoded.Bytes()) {
		t.Fatal("compressed representation changed")
	}
}

type discardWriter struct{ h http.Header }

func (w *discardWriter) Header() http.Header       { return w.h }
func (*discardWriter) WriteHeader(int)             {}
func (*discardWriter) Write(p []byte) (int, error) { return len(p), nil }

func BenchmarkSuccessfulResponse(b *testing.B) {
	for _, size := range []int{1 << 20, 10 << 20} {
		for _, attempts := range []int{1, 3} {
			b.Run(fmt.Sprintf("bytes%d-attempts%d", size, attempts), func(b *testing.B) {
				payload := bytes.Repeat([]byte("x"), size)
				h := New(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write(payload) }), Config{MaxAttempts: attempts}, testLogger())
				req := httptest.NewRequest("GET", "/", nil)
				w := &discardWriter{h: make(http.Header)}
				b.SetBytes(int64(size))
				b.ReportAllocs()
				b.ResetTimer()
				for b.Loop() {
					h.ServeHTTP(w, req)
				}
			})
		}
	}
}

func TestMiddlewareRetriesAreDisabledByDefault(t *testing.T) {
	for _, cfg := range []Config{{}, {Backoff: time.Nanosecond}, {RetryableStatusCodes: map[int]struct{}{503: {}}}} {
		calls := 0
		req := httptest.NewRequest("GET", "/", nil)
		body := &brokenRequestBody{}
		req.Body = body
		rec := httptest.NewRecorder()
		next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			calls++
			if r.Body != body || body.closed {
				t.Fatal("default retry policy touched body")
			}
			w.WriteHeader(503)
			_, _ = io.WriteString(w, "single attempt")
			if rec.Body.String() != "single attempt" {
				t.Fatal("default policy buffered response")
			}
		})
		New(next, cfg, testLogger()).ServeHTTP(rec, req)
		if calls != 1 || rec.Code != 503 {
			t.Fatalf("calls=%d status=%d", calls, rec.Code)
		}
	}
}
