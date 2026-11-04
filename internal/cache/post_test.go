package cache

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/ledatu/csar-core/gatewayctx"
	"github.com/redis/go-redis/v9"
)

func postCacheRequest(body string) *http.Request {
	req := httptest.NewRequest(http.MethodPost, "/stocks?limit=10", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(gatewayctx.HeaderSubject, "subject-1")
	return req
}

func TestBuildCacheKey_GETHEADCompatibility(t *testing.T) {
	for method, want := range map[string]string{
		"GET":  "b0df1bf4f11e10e49ebd5f10b2004b7cb9b5623dbd867d62b4720d2428b25386",
		"HEAD": "9de0fb81ff80aca6d6de7aaf437df154f60f66ad5e834c482adac01a47a20e8a",
	} {
		req := httptest.NewRequest(method, "/stocks?limit=10", nil)
		got, err := BuildCacheKey(method+":/stocks", "", nil, nil, nil, req, "")
		if err != nil || got != want {
			t.Fatalf("%s key=%q error=%v", method, got, err)
		}
	}
}

func TestResponseCache_POSTRequiresMethodOptIn(t *testing.T) {
	rc := NewResponseCache(slog.Default())
	calls := 0
	handler := rc.Wrap(Config{}, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		io.Copy(w, r.Body)
	}))
	for range 2 {
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, postCacheRequest("a"))
		if rec.Body.String() != "a" || rec.Header().Get("X-CSAR-Cache") != "BYPASS" {
			t.Fatalf("response=%q cache=%s", rec.Body.String(), rec.Header().Get("X-CSAR-Cache"))
		}
	}
	if calls != 2 {
		t.Fatalf("POST cached without method opt-in, calls=%d", calls)
	}
}

func TestResponseCache_POSTBodyIsolation(t *testing.T) {
	for _, store := range []string{"memory", "redis"} {
		t.Run(store, func(t *testing.T) {
			mr := miniredis.RunT(t)
			client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
			defer client.Close()
			rc := NewResponseCache(slog.Default(), WithRedisStore(NewRedisStore(client, "csar:")))
			calls := 0
			cfg := Config{
				RouteKey: "POST:/stocks", Store: store, KeyTemplate: "stocks:{subject}",
				KeyQuery: &KeyQueryConfig{Sort: true}, Methods: map[string]struct{}{http.MethodPost: {}},
			}
			upstream := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls++
				body, err := io.ReadAll(r.Body)
				if err != nil {
					t.Error(err)
				}
				w.Write(body)
			})
			handler := rc.Wrap(cfg, upstream)
			for i, body := range []string{`{"nmIds":[101],"period":"week"}`, `{"nmIds":[202],"period":"week"}`, `{"nmIds":[101],"period":"week"}`, `{"nmIds":[101],"period":"month"}`} {
				if store == "redis" && i == 2 {
					// A different coordinator shares the distributed key format.
					peer := NewResponseCache(slog.Default(), WithRedisStore(NewRedisStore(client, "csar:")))
					handler = peer.Wrap(cfg, upstream)
				}
				rec := httptest.NewRecorder()
				handler.ServeHTTP(rec, postCacheRequest(body))
				wantStatus := "MISS"
				if i == 2 {
					wantStatus = "HIT"
				}
				if rec.Body.String() != body || rec.Header().Get("X-CSAR-Cache") != wantStatus {
					t.Fatalf("request %d: %q %s", i, rec.Body.String(), rec.Header().Get("X-CSAR-Cache"))
				}
			}
			if calls != 3 {
				t.Fatalf("upstream calls = %d, want 3", calls)
			}
		})
	}
}

func TestBuildCacheKey_POSTDimensions(t *testing.T) {
	key := func(r *http.Request, digest string) string {
		t.Helper()
		got, err := BuildCacheKey("POST:/stocks", "{subject}:{header.X-Seller}", []string{"Accept"}, &KeyQueryConfig{Sort: true}, map[string]int64{"stocks": 1}, r, digest)
		if err != nil {
			t.Fatal(err)
		}
		return got
	}
	req := postCacheRequest("a")
	req.Header.Set("X-Seller", strings.Repeat("s", 300)+":a")
	base := key(req, "digest-a")
	changes := map[string]func(*http.Request){
		"subject":                func(r *http.Request) { r.Header.Set(gatewayctx.HeaderSubject, "subject-2") },
		"seller suffix":          func(r *http.Request) { r.Header.Set("X-Seller", strings.Repeat("s", 300)+":b") },
		"punctuation":            func(r *http.Request) { r.Header.Set("X-Seller", strings.Repeat("s", 300)+"@a") },
		"query":                  func(r *http.Request) { r.URL.RawQuery = "limit=20" },
		"path":                   func(r *http.Request) { r.URL.Path = "/stocks/archive" },
		"vary header":            func(r *http.Request) { r.Header.Set("Accept", "text/csv") },
		"content type":           func(r *http.Request) { r.Header.Set("Content-Type", "text/plain") },
		"encoding":               func(r *http.Request) { r.Header.Set("Content-Encoding", "gzip") },
		"multiple header values": func(r *http.Request) { r.Header.Add("Content-Type", "text/plain") },
	}
	for name, change := range changes {
		t.Run(name, func(t *testing.T) {
			variant := req.Clone(req.Context())
			change(variant)
			if key(variant, "digest-a") == base {
				t.Fatal("distinct request shared a key")
			}
		})
	}
	if key(req, "digest-b") == base {
		t.Fatal("distinct body shared a key")
	}
	if _, err := BuildCacheKey("POST:/stocks", "", nil, nil, nil, req, ""); err == nil {
		t.Fatal("POST without a digest was accepted")
	}
	// Invalid UTF-8 must not be collapsed by structured encoding.
	req.Header.Set("X-Seller", string([]byte{0xff}))
	first := key(req, "digest-a")
	req.Header.Set("X-Seller", string([]byte{0xfe}))
	if first == key(req, "digest-a") {
		t.Fatal("distinct non-UTF-8 header bytes shared a key")
	}
	req.Header.Set(gatewayctx.HeaderSubject, "a:b")
	req.Header.Set("X-Seller", "c")
	first = key(req, "digest-a")
	req.Header.Set(gatewayctx.HeaderSubject, "a")
	req.Header.Set("X-Seller", "b:c")
	if first == key(req, "digest-a") {
		t.Fatal("placeholder boundaries shared a key")
	}
	req.URL.Path = "/stocks/item"
	req.URL.RawPath = "/stocks%2Fitem"
	first = key(req, "digest-a")
	req.URL.RawPath = ""
	if first == key(req, "digest-a") {
		t.Fatal("distinct escaped paths shared a key")
	}
}

type trackedPOSTBody struct {
	io.Reader
	closed bool
}

func (b *trackedPOSTBody) Close() error {
	b.closed = true
	return nil
}

func TestResponseCache_POSTReplayAndBypass(t *testing.T) {
	for _, tc := range []struct {
		name      string
		body      string
		length    int64
		trailer   bool
		storeDown bool
		want      string
	}{
		{name: "at cap", body: "1234", length: 4, want: "MISS"},
		{name: "empty", length: 0, want: "MISS"},
		{name: "known oversize", body: "12345", length: 5, want: "BYPASS"},
		{name: "chunked oversize", body: "12345", length: -1, want: "BYPASS"},
		{name: "chunked admitted", body: "123", length: -1, want: "MISS"},
		{name: "trailers", body: "123", length: -1, trailer: true, want: "BYPASS"},
		{name: "store down", body: "123", length: 3, storeDown: true, want: "BYPASS"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rc := NewResponseCache(slog.Default())
			store := "memory"
			if tc.storeDown {
				mr := miniredis.RunT(t)
				client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
				client.Close()
				rc = NewResponseCache(slog.Default(), WithRedisStore(NewRedisStore(client, "csar:")))
				store = "redis"
			}
			req := postCacheRequest(tc.body)
			original := &trackedPOSTBody{Reader: strings.NewReader(tc.body)}
			req.Body = original
			req.ContentLength = tc.length
			if tc.trailer {
				req.Trailer = http.Header{"X-Checksum": nil}
			}
			calls := 0
			handler := rc.Wrap(Config{
				RouteKey: "POST:/stocks", Store: store, MaxRequestBodySize: 4,
				Methods: map[string]struct{}{http.MethodPost: {}},
			}, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls++
				got, err := io.ReadAll(r.Body)
				if err != nil || string(got) != tc.body || r.ContentLength != tc.length {
					t.Errorf("upstream body=%q length=%d error=%v", got, r.ContentLength, err)
				}
				r.Body.Close()
				if tc.want == "MISS" {
					replay, replayErr := r.GetBody()
					if replayErr != nil {
						t.Fatal(replayErr)
					}
					defer replay.Close()
					data, readErr := io.ReadAll(replay)
					if readErr != nil || string(data) != tc.body {
						t.Errorf("replay=%q error=%v", data, readErr)
					}
				}
				w.Write(got)
			}))
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)
			if calls != 1 || !original.closed || rec.Header().Get("X-CSAR-Cache") != tc.want {
				t.Fatalf("calls=%d closed=%v cache=%s", calls, original.closed, rec.Header().Get("X-CSAR-Cache"))
			}
		})
	}
}

type failingPOSTBody struct{}

func (failingPOSTBody) Read(p []byte) (int, error) {
	return copy(p, "partial"), errors.New("broken stream")
}

func TestResponseCache_POSTReadFailure(t *testing.T) {
	req := postCacheRequest("")
	body := &trackedPOSTBody{Reader: failingPOSTBody{}}
	req.Body = body
	handler := NewResponseCache(slog.Default()).Wrap(Config{
		Methods: map[string]struct{}{http.MethodPost: {}},
	}, http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Error("incomplete request reached upstream")
	}))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest || !body.closed || rec.Header().Get("X-CSAR-Cache") != "BYPASS" {
		t.Fatalf("status=%d closed=%v cache=%s", rec.Code, body.closed, rec.Header().Get("X-CSAR-Cache"))
	}
}

func TestResponseCache_POSTCoalesce(t *testing.T) {
	rc := NewResponseCache(slog.Default())
	var calls atomic.Int64
	started := make(chan struct{}, 2)
	release := make(chan struct{})
	handler := rc.Wrap(Config{
		RouteKey: "POST:/stocks", Methods: map[string]struct{}{http.MethodPost: {}},
		Coalesce: &CoalesceConfig{Enabled: true, Wait: time.Second},
	}, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		started <- struct{}{}
		<-release
		io.Copy(w, r.Body)
	}))
	var wg sync.WaitGroup
	for _, body := range []string{"a", "a", "b", "b"} {
		wg.Add(1)
		go func() {
			defer wg.Done()
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, postCacheRequest(body))
			if rec.Body.String() != body || rec.Code != http.StatusOK {
				t.Errorf("body=%q status=%d, want %q", rec.Body.String(), rec.Code, body)
			}
		}()
	}
	for range 2 {
		select {
		case <-started:
		case <-time.After(time.Second):
			close(release)
			wg.Wait()
			t.Fatal("different bodies were coalesced")
		}
	}
	close(release)
	wg.Wait()
	if calls.Load() != 2 {
		t.Fatalf("upstream calls=%d, want 2", calls.Load())
	}
}

func TestResponseCache_POSTStaleRefresh(t *testing.T) {
	mr := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	defer client.Close()
	rc := NewResponseCache(slog.Default(), WithRedisStore(NewRedisStore(client, "csar:")))
	type contextKey struct{}
	refresh := make(chan string, 1)
	allowRefresh := make(chan struct{})
	var calls atomic.Int64
	handler := rc.Wrap(Config{
		RouteKey: "POST:/stocks", Store: "redis", TTL: 5 * time.Millisecond, StaleWhileRevalidate: time.Minute,
		Methods: map[string]struct{}{http.MethodPost: {}},
	}, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		call := calls.Add(1)
		if call == 2 {
			<-allowRefresh
			if err := r.Context().Err(); err != nil {
				t.Errorf("refresh canceled with original request: %v", err)
			}
		}
		body, err := io.ReadAll(r.Body)
		if err != nil || string(body) != "a" || r.Context().Value(contextKey{}) != "kept" {
			t.Errorf("body=%q error=%v context=%v", body, err, r.Context().Value(contextKey{}))
		}
		if call == 2 {
			deadline, ok := r.Context().Deadline()
			if !ok || time.Until(deadline) > DefaultRefreshTimeout {
				t.Error("refresh deadline missing")
			}
			refresh <- string(body)
		}
		w.Write(body)
	}))
	serve := func() *httptest.ResponseRecorder {
		ctx, cancel := context.WithCancel(context.WithValue(context.Background(), contextKey{}, "kept"))
		defer cancel()
		req := postCacheRequest("a").WithContext(ctx)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		req.Body.Close()
		return rec
	}
	serve()
	time.Sleep(10 * time.Millisecond)
	rec := serve()
	if rec.Header().Get("X-CSAR-Cache") != "STALE" || rec.Body.String() != "a" {
		t.Fatalf("response=%q cache=%s", rec.Body.String(), rec.Header().Get("X-CSAR-Cache"))
	}
	key := strings.TrimPrefix(mr.Keys()[0], "csar:cache:response:")
	leader, pending, release, err := rc.coalescer.Begin(key)
	if err != nil || leader {
		close(allowRefresh)
		t.Fatalf("refresh ticket unavailable: leader=%v error=%v", leader, err)
	}
	defer release()
	close(allowRefresh)
	select {
	case <-refresh:
	case <-time.After(time.Second):
		t.Fatal("refresh did not replay the POST body")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if _, err := pending.Wait(ctx); err != nil {
		t.Fatalf("refresh did not finish: %v", err)
	}
}

func TestResponseCache_POSTStaleIfErrorDoesNotCrossBodies(t *testing.T) {
	rc := NewResponseCache(slog.Default())
	fail := false
	handler := rc.Wrap(Config{
		RouteKey: "POST:/stocks", TTL: time.Millisecond, StaleIfError: time.Minute,
		Methods: map[string]struct{}{http.MethodPost: {}},
	}, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if fail {
			w.WriteHeader(http.StatusBadGateway)
			return
		}
		fmt.Fprint(w, "a")
	}))
	handler.ServeHTTP(httptest.NewRecorder(), postCacheRequest("a"))
	time.Sleep(5 * time.Millisecond)
	fail = true
	for _, body := range []string{"b", "a"} {
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, postCacheRequest(body))
		if body == "b" && rec.Code != http.StatusBadGateway {
			t.Fatalf("body b received stale a: %d %q", rec.Code, rec.Body.String())
		}
		if body == "a" && (rec.Body.String() != "a" || rec.Header().Get("X-CSAR-Cache") != "STALE") {
			t.Fatalf("body a did not receive its stale entry: %d %q", rec.Code, rec.Body.String())
		}
	}
}

func TestResponseCache_POSTUnannouncedTrailersBypass(t *testing.T) {
	handler := NewResponseCache(slog.Default()).Wrap(Config{
		RouteKey: "POST:/stocks", Methods: map[string]struct{}{http.MethodPost: {}},
	}, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatal(err)
		}
		fmt.Fprintf(w, "%s:%s", body, r.Trailer.Get("X-Selector"))
	}))
	for _, selector := range []string{"one", "two"} {
		wire := "POST /stocks HTTP/1.1\r\nHost: local\r\nTransfer-Encoding: chunked\r\n\r\n1\r\na\r\n0\r\nX-Selector: " + selector + "\r\n\r\n"
		req, err := http.ReadRequest(bufio.NewReader(strings.NewReader(wire)))
		if err != nil {
			t.Fatal(err)
		}
		if len(req.Trailer) != 0 {
			t.Fatal("test request announced its trailer")
		}
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		req.Body.Close()
		if rec.Header().Get("X-CSAR-Cache") != "BYPASS" || rec.Body.String() != "a:"+selector {
			t.Fatalf("cache=%s body=%q, want bypass and a:%s", rec.Header().Get("X-CSAR-Cache"), rec.Body.String(), selector)
		}
	}
}
