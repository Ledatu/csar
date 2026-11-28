package router

import (
	"bytes"
	"compress/gzip"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/ledatu/csar/internal/config"
	"github.com/redis/go-redis/v9"
)

func TestResponseCompressionUsesOnlyExplicitPolicy(t *testing.T) {
	plain := []byte(`{"items":"` + strings.Repeat("example", 2048) + `"}`)
	var encoded bytes.Buffer
	zw := gzip.NewWriter(&encoded)
	if _, err := zw.Write(plain); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"/", "/custom/installation/data", "/api/v2/items", "/svc/example"} {
		for _, tc := range []struct {
			name         string
			global       bool
			policy       *config.ResponseCompressionConfig
			accept       string
			upstreamGzip bool
			status       int
			wantGzip     bool
		}{
			{"default", false, nil, "gzip", false, 200, false},
			{"route opt-in", false, &config.ResponseCompressionConfig{Mode: "gzip"}, "gzip", false, 200, true},
			{"client refuses", false, &config.ResponseCompressionConfig{Mode: "gzip"}, "identity", false, 200, false},
			{"legacy global opt-in", true, nil, "gzip", false, 200, true},
			{"route override", true, &config.ResponseCompressionConfig{Mode: "passthrough"}, "gzip", false, 200, false},
			{"upstream pass-through", false, nil, "gzip", true, 200, true},
			{"no recompression", false, &config.ResponseCompressionConfig{Mode: "gzip"}, "gzip", true, 200, true},
			{"v1 error", false, &config.ResponseCompressionConfig{Mode: "gzip"}, "gzip", false, 503, false},
		} {
			t.Run(path+"/"+tc.name, func(t *testing.T) {
				var calls atomic.Int32
				upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
					calls.Add(1)
					if req.Header.Get("Accept-Encoding") != tc.accept {
						t.Error("upstream negotiation changed")
					}
					w.Header().Set("Content-Type", "application/json")
					if tc.upstreamGzip {
						w.Header().Set("Content-Encoding", "gzip")
					}
					w.WriteHeader(tc.status)
					if tc.upstreamGzip {
						_, _ = w.Write(encoded.Bytes())
					} else {
						_, _ = w.Write(plain)
					}
				}))
				defer upstream.Close()
				cfg := newTestConfig(map[string]config.PathConfig{path: {"get": {Backend: config.BackendConfig{TargetURL: upstream.URL}, ResponseCompression: tc.policy}}})
				r, err := New(cfg, newTestLogger(), WithResponseGzipDefault(tc.global))
				if err != nil {
					t.Fatal(err)
				}
				defer r.Close()
				req := httptest.NewRequest(http.MethodGet, path, nil)
				req.Header.Set("Accept-Encoding", tc.accept)
				rec := httptest.NewRecorder()
				r.ServeHTTP(rec, req)
				if calls.Load() != 1 || rec.Code != tc.status || rec.Header().Get("X-CSAR-Protocol-Version") != "1" {
					t.Fatal("attempts/status/protocol changed")
				}
				if (rec.Header().Get("Content-Encoding") == "gzip") != tc.wantGzip {
					t.Fatalf("unexpected encoding: %v", rec.Header())
				}
				body := rec.Body.Bytes()
				if tc.upstreamGzip {
					if !bytes.Equal(body, encoded.Bytes()) {
						t.Fatal("upstream gzip bytes changed")
					}
				} else if tc.wantGzip {
					zr, err := gzip.NewReader(bytes.NewReader(body))
					if err != nil {
						t.Fatal(err)
					}
					body, err = io.ReadAll(zr)
					if err != nil {
						t.Fatal(err)
					}
					if err := zr.Close(); err != nil {
						t.Fatal(err)
					}
				}
				if !tc.upstreamGzip && !bytes.Equal(body, plain) {
					t.Fatal("response contents changed")
				}
			})
		}
	}
}

func TestCachedResponsesKeepUpstreamRepresentationAcrossPolicyChanges(t *testing.T) {
	redisServer := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: redisServer.Addr()})
	t.Cleanup(func() { _ = rdb.Close() })
	plain := []byte(`{"data":"` + strings.Repeat("cache", 2048) + `"}`)
	var calls atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(plain)
	}))
	defer upstream.Close()
	for _, mode := range []string{"gzip", "passthrough"} {
		cfg := newTestConfig(map[string]config.PathConfig{"/cached": {"get": {Backend: config.BackendConfig{TargetURL: upstream.URL}, ResponseCompression: &config.ResponseCompressionConfig{Mode: mode}, Cache: &config.CacheConfig{Store: "redis", TTL: config.Duration{Duration: time.Minute}}}}})
		r, err := New(cfg, newTestLogger(), WithRedisClient(rdb))
		if err != nil {
			t.Fatal(err)
		}
		req := httptest.NewRequest(http.MethodGet, "/cached", nil)
		req.Header.Set("Accept-Encoding", "gzip")
		rec := httptest.NewRecorder()
		r.ServeHTTP(rec, req)
		if rec.Code != 200 || (rec.Header().Get("Content-Encoding") == "gzip") != (mode == "gzip") {
			t.Fatal("policy did not apply", rec.Header())
		}
		if mode == "passthrough" && !bytes.Equal(rec.Body.Bytes(), plain) {
			t.Fatal("generated gzip leaked into the cached representation")
		}
		r.Close()
	}
	if calls.Load() != 1 {
		t.Fatalf("expected the second policy to use the upstream cache entry; calls=%d", calls.Load())
	}
}
