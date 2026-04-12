package cache

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/ledatu/csar-core/gatewayctx"
	"github.com/ledatu/csar/pkg/middleware/authzmw"
	"github.com/redis/go-redis/v9"
)

func TestBuildCacheKey_RendersRequestPlaceholders(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/analytics/skus?marketplace=wb&date_from=2026-04-10", nil)
	req.Header.Set(gatewayctx.HeaderTenant, "tenant-1")
	req.Header.Set(gatewayctx.HeaderSubject, "subject-1")
	req.Header.Set("Accept", "application/json")
	req = req.WithContext(authzmw.WithPathVars(req.Context(), map[string]string{"sku_id": "sku-123"}))

	key1, err := BuildCacheKey("GET:/analytics/skus", "analytics:{tenant}:{subject}:{path.sku_id}:{query.marketplace}", []string{"Accept"}, nil, nil, req)
	if err != nil {
		t.Fatalf("BuildCacheKey: %v", err)
	}
	key2, err := BuildCacheKey("GET:/analytics/skus", "analytics:{tenant}:{subject}:{path.sku_id}:{query.marketplace}", []string{"Accept"}, nil, nil, req)
	if err != nil {
		t.Fatalf("BuildCacheKey second call: %v", err)
	}
	if key1 == "" || key1 != key2 {
		t.Fatalf("cache key not stable: %q vs %q", key1, key2)
	}

	req.Header.Set("Accept", "text/csv")
	key3, err := BuildCacheKey("GET:/analytics/skus", "analytics:{tenant}:{subject}:{path.sku_id}:{query.marketplace}", []string{"Accept"}, nil, nil, req)
	if err != nil {
		t.Fatalf("BuildCacheKey after vary change: %v", err)
	}
	if key3 == key1 {
		t.Fatal("cache key did not vary by configured header")
	}
}

func TestBuildCacheKey_MissingPlaceholderFails(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/analytics/skus", nil)
	_, err := BuildCacheKey("GET:/analytics/skus", "analytics:{query.marketplace}", nil, nil, nil, req)
	if err == nil {
		t.Fatal("BuildCacheKey should fail on missing placeholder")
	}
}

func TestBuildCacheKey_NormalizesQuery(t *testing.T) {
	cfg := &KeyQueryConfig{
		Include:   []string{"marketplace", "date_from", "date_to", "page", "limit", "limit"},
		Exclude:   []string{"utm_source", "cache_bust"},
		Sort:      true,
		DropEmpty: true,
	}
	req1 := httptest.NewRequest(http.MethodGet, "/analytics/skus?utm_source=x&limit=50&page=&date_to=2026-04-12&marketplace=wb&date_from=2026-04-10", nil)
	req2 := httptest.NewRequest(http.MethodGet, "/analytics/skus?date_from=2026-04-10&marketplace=wb&cache_bust=1&date_to=2026-04-12&limit=50", nil)

	key1, err := BuildCacheKey("GET:/analytics/skus", "", nil, cfg, nil, req1)
	if err != nil {
		t.Fatalf("BuildCacheKey req1: %v", err)
	}
	key2, err := BuildCacheKey("GET:/analytics/skus", "", nil, cfg, nil, req2)
	if err != nil {
		t.Fatalf("BuildCacheKey req2: %v", err)
	}
	if key1 != key2 {
		t.Fatalf("normalized query keys differ: %q vs %q", key1, key2)
	}
}

func TestNormalizeQuery_RepeatedValues(t *testing.T) {
	values := url.Values{
		"tag":        []string{"b", "a", ""},
		"utm_source": []string{"tracker"},
	}
	got := normalizeQuery(values, KeyQueryConfig{
		Include:   []string{"tag", "tag", "utm_source"},
		Exclude:   []string{"utm_source"},
		Sort:      true,
		DropEmpty: true,
	})
	if got != "tag=a&tag=b" {
		t.Fatalf("normalizeQuery = %q, want tag=a&tag=b", got)
	}
}

func TestTTLRule_DateRangeContainsToday(t *testing.T) {
	now := time.Date(2026, 4, 13, 12, 0, 0, 0, time.UTC)
	rule := TTLRule{
		When: "query.date_range_contains_today",
		From: "date_from",
		To:   "date_to",
		TTL:  20 * time.Minute,
	}

	tests := []struct {
		name string
		url  string
		want bool
	}{
		{"previous days", "/analytics?date_from=2026-04-10&date_to=2026-04-12", false},
		{"today only", "/analytics?date_from=2026-04-13&date_to=2026-04-13", true},
		{"spans today", "/analytics?date_from=2026-04-10&date_to=2026-04-13", true},
		{"invalid date", "/analytics?date_from=bad&date_to=2026-04-13", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, tt.url, nil)
			if got := ttlRuleMatches(rule, req, now); got != tt.want {
				t.Fatalf("ttlRuleMatches() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestApplyTTLJitter_NeverExtendsTTL(t *testing.T) {
	ttl := time.Hour
	for i := 0; i < 100; i++ {
		got := applyTTLJitter(ttl, "10%", "key")
		if got > ttl {
			t.Fatalf("jittered TTL = %s, exceeds %s", got, ttl)
		}
		if got < 54*time.Minute {
			t.Fatalf("jittered TTL = %s, below 10%% reduction bound", got)
		}
	}
	if got := applyTTLJitter(ttl, "90m", "key"); got < 0 || got > ttl {
		t.Fatalf("duration jitter = %s, want within [0,%s]", got, ttl)
	}
}

func TestRedisStore_SetGetDeleteByTag(t *testing.T) {
	mr := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	defer client.Close()

	store := NewRedisStore(client, "csar:")
	entry := &Entry{
		StatusCode: http.StatusOK,
		Headers:    http.Header{"Content-Type": []string{"application/json"}},
		Body:       []byte(`{"ok":true}`),
		ETag:       "abc",
	}

	err := store.Set(context.Background(), "key-1", entry, SetOptions{
		TTL:  time.Minute,
		Tags: []string{"analytics:skus:tenant-1"},
	})
	if err != nil {
		t.Fatalf("Set: %v", err)
	}

	got, err := store.GetFresh(context.Background(), "key-1", nil)
	if err != nil {
		t.Fatalf("GetFresh: %v", err)
	}
	if string(got.Body) != string(entry.Body) || got.StatusCode != http.StatusOK {
		t.Fatalf("unexpected entry: %+v", got)
	}

	if err := store.DeleteByTag(context.Background(), "analytics:skus:tenant-1"); err != nil {
		t.Fatalf("DeleteByTag: %v", err)
	}
	_, err = store.GetFresh(context.Background(), "key-1", nil)
	if !errors.Is(err, ErrCacheMiss) {
		t.Fatalf("GetFresh after delete err = %v, want ErrCacheMiss", err)
	}
}

func TestMemoryStore_StaleAndNamespaceVersioning(t *testing.T) {
	store := NewMemoryStore()
	versions, err := store.GetNamespaceVersions(context.Background(), []string{"analytics:skus:tenant-1"})
	if err != nil {
		t.Fatalf("GetNamespaceVersions: %v", err)
	}
	if err := store.Set(context.Background(), "key-1", &Entry{StatusCode: http.StatusOK, Body: []byte("v1")}, SetOptions{
		TTL:               10 * time.Millisecond,
		StaleTTL:          time.Hour,
		NamespaceVersions: versions,
	}); err != nil {
		t.Fatalf("Set: %v", err)
	}

	time.Sleep(25 * time.Millisecond)
	if _, err := store.GetFresh(context.Background(), "key-1", versions); !errors.Is(err, ErrCacheMiss) {
		t.Fatalf("GetFresh expired err = %v, want ErrCacheMiss", err)
	}
	stale, err := store.GetStale(context.Background(), "key-1", versions)
	if err != nil {
		t.Fatalf("GetStale: %v", err)
	}
	if string(stale.Body) != "v1" {
		t.Fatalf("stale body = %q, want v1", stale.Body)
	}

	if err := store.BumpNamespace(context.Background(), "analytics:skus:tenant-1"); err != nil {
		t.Fatalf("BumpNamespace: %v", err)
	}
	bumped, err := store.GetNamespaceVersions(context.Background(), []string{"analytics:skus:tenant-1"})
	if err != nil {
		t.Fatalf("GetNamespaceVersions after bump: %v", err)
	}
	if bumped["analytics:skus:tenant-1"] != versions["analytics:skus:tenant-1"]+1 {
		t.Fatalf("namespace version = %d, want %d", bumped["analytics:skus:tenant-1"], versions["analytics:skus:tenant-1"]+1)
	}
	if _, err := store.GetStale(context.Background(), "key-1", bumped); !errors.Is(err, ErrCacheMiss) {
		t.Fatalf("GetStale after namespace bump err = %v, want ErrCacheMiss", err)
	}
}

func TestResponseCache_FailOpenWhenRedisDown(t *testing.T) {
	mr := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	defer client.Close()
	store := NewRedisStore(client, "csar:")
	rc := NewResponseCache(slog.Default(), WithRedisStore(store))
	mr.Close()

	upstreamCalls := 0
	handler := rc.Wrap(Config{
		RouteKey:         "GET:/analytics/skus",
		Store:            "redis",
		KeyTemplate:      "analytics:{query.marketplace}",
		OperationTimeout: 10 * time.Millisecond,
	}, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamCalls++
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("fresh"))
	}))

	req := httptest.NewRequest(http.MethodGet, "/analytics/skus?marketplace=wb", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if rec.Body.String() != "fresh" {
		t.Fatalf("body = %q, want fresh", rec.Body.String())
	}
	if rec.Header().Get("X-CSAR-Cache") != "BYPASS" {
		t.Fatalf("X-CSAR-Cache = %q, want BYPASS", rec.Header().Get("X-CSAR-Cache"))
	}
	if upstreamCalls != 1 {
		t.Fatalf("upstreamCalls = %d, want 1", upstreamCalls)
	}
}

func TestResponseCache_DoesNotCacheSetCookiePrivateOrNoStore(t *testing.T) {
	tests := []struct {
		name    string
		headers http.Header
	}{
		{"set cookie", http.Header{"Set-Cookie": []string{"sid=1"}}},
		{"private", http.Header{"Cache-Control": []string{"private"}}},
		{"no store", http.Header{"Cache-Control": []string{"no-store"}}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rc := NewResponseCache(slog.Default())
			upstreamCalls := 0
			handler := rc.Wrap(Config{RouteKey: "GET:/data"}, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				upstreamCalls++
				for k, vv := range tt.headers {
					for _, v := range vv {
						w.Header().Add(k, v)
					}
				}
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte("fresh"))
			}))

			for i := 0; i < 2; i++ {
				req := httptest.NewRequest(http.MethodGet, "/data", nil)
				rec := httptest.NewRecorder()
				handler.ServeHTTP(rec, req)
				if rec.Header().Get("X-CSAR-Cache") != "BYPASS" {
					t.Fatalf("request %d X-CSAR-Cache = %q, want BYPASS", i, rec.Header().Get("X-CSAR-Cache"))
				}
			}
			if upstreamCalls != 2 {
				t.Fatalf("upstreamCalls = %d, want 2", upstreamCalls)
			}
		})
	}
}

func TestResponseCache_StaleIfError(t *testing.T) {
	rc := NewResponseCache(slog.Default())
	var fail atomic.Bool
	handler := rc.Wrap(Config{
		RouteKey:      "GET:/data",
		TTL:           10 * time.Millisecond,
		StaleIfError:  time.Hour,
		CacheStatuses: []string{"200"},
	}, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if fail.Load() {
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte("broken"))
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("fresh"))
	}))

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/data", nil))
	if rec.Header().Get("X-CSAR-Cache") != "MISS" {
		t.Fatalf("first cache status = %q, want MISS", rec.Header().Get("X-CSAR-Cache"))
	}

	fail.Store(true)
	time.Sleep(25 * time.Millisecond)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/data", nil))
	if rec.Code != http.StatusOK || rec.Body.String() != "fresh" {
		t.Fatalf("stale response = %d %q, want 200 fresh", rec.Code, rec.Body.String())
	}
	if rec.Header().Get("X-CSAR-Cache") != "STALE" {
		t.Fatalf("cache status = %q, want STALE", rec.Header().Get("X-CSAR-Cache"))
	}
}

func TestRenderResponseTags_TenantPrefix(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/analytics/skus?marketplace=wb", nil)
	req.Header.Set(gatewayctx.HeaderTenant, "tenant-1")
	headers := http.Header{}
	headers.Set("X-CSAR-Cache-Tags", "sku-1, sku 2, !!!")
	tags, err := RenderResponseTags([]ResponseTag{{
		Header: "X-CSAR-Cache-Tags",
		Prefix: "analytics:{tenant}:",
	}}, req, headers)
	if err != nil {
		t.Fatalf("RenderResponseTags: %v", err)
	}
	want := []string{"analytics:tenant-1:sku-1", "analytics:tenant-1:sku2"}
	if len(tags) != len(want) {
		t.Fatalf("tags = %#v, want %#v", tags, want)
	}
	for i := range want {
		if tags[i] != want[i] {
			t.Fatalf("tags[%d] = %q, want %q", i, tags[i], want[i])
		}
	}
}

func TestResponseCache_BypassRequiresGatewayScope(t *testing.T) {
	rc := NewResponseCache(slog.Default())
	var calls atomic.Int64
	handler := rc.Wrap(Config{
		RouteKey: "GET:/data",
		Bypass: &BypassConfig{Headers: []BypassHeader{{
			Name:                "X-CSAR-Cache-Bypass",
			Value:               "true",
			RequireGatewayScope: "cache:bypass",
		}}},
	}, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		call := calls.Add(1)
		w.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprintf(w, "fresh-%d", call)
	}))

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/data", nil))
	if rec.Header().Get("X-CSAR-Cache") != "MISS" {
		t.Fatalf("first cache status = %q, want MISS", rec.Header().Get("X-CSAR-Cache"))
	}

	req := httptest.NewRequest(http.MethodGet, "/data", nil)
	req.Header.Set("X-CSAR-Cache-Bypass", "true")
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Header().Get("X-CSAR-Cache") != "HIT" {
		t.Fatalf("unauthorized bypass cache status = %q, want HIT", rec.Header().Get("X-CSAR-Cache"))
	}

	req = httptest.NewRequest(http.MethodGet, "/data", nil)
	req.Header.Set("X-CSAR-Cache-Bypass", "true")
	req.Header.Set(gatewayctx.HeaderScopes, "cache:bypass")
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Header().Get("X-CSAR-Cache") != "BYPASS" {
		t.Fatalf("authorized bypass cache status = %q, want BYPASS", rec.Header().Get("X-CSAR-Cache"))
	}
	if calls.Load() != 2 {
		t.Fatalf("upstream calls = %d, want 2", calls.Load())
	}
}

func TestResponseCache_CoalesceConcurrentMiss(t *testing.T) {
	rc := NewResponseCache(slog.Default())
	var calls atomic.Int64
	release := make(chan struct{})
	handler := rc.Wrap(Config{
		RouteKey: "GET:/data",
		Coalesce: &CoalesceConfig{
			Enabled: true,
			Wait:    time.Second,
		},
	}, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		<-release
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("fresh"))
	}))

	var wg sync.WaitGroup
	statuses := make([]int, 2)
	bodies := make([]string, 2)
	cacheStatuses := make([]string, 2)
	for i := range statuses {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/data", nil))
			statuses[i] = rec.Code
			bodies[i] = rec.Body.String()
			cacheStatuses[i] = rec.Header().Get("X-CSAR-Cache")
		}(i)
	}

	for deadline := time.Now().Add(time.Second); calls.Load() == 0 && time.Now().Before(deadline); {
		time.Sleep(time.Millisecond)
	}
	close(release)
	wg.Wait()

	if calls.Load() != 1 {
		t.Fatalf("upstream calls = %d, want 1", calls.Load())
	}
	for i := range statuses {
		if statuses[i] != http.StatusOK || bodies[i] != "fresh" {
			t.Fatalf("response %d = %d %q, want 200 fresh", i, statuses[i], bodies[i])
		}
		if cacheStatuses[i] != "MISS" {
			t.Fatalf("cache status %d = %q, want MISS", i, cacheStatuses[i])
		}
	}
}

func TestResponseCache_CoalesceTimeout(t *testing.T) {
	rc := NewResponseCache(slog.Default())
	started := make(chan struct{})
	release := make(chan struct{})
	handler := rc.Wrap(Config{
		RouteKey: "GET:/data",
		Coalesce: &CoalesceConfig{
			Enabled:           true,
			Wait:              10 * time.Millisecond,
			WaitTimeoutStatus: http.StatusServiceUnavailable,
		},
	}, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-started:
		default:
			close(started)
		}
		<-release
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("fresh"))
	}))

	var leaderWG sync.WaitGroup
	leaderWG.Add(1)
	go func() {
		defer leaderWG.Done()
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/data", nil))
	}()

	<-started
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/data", nil))
	close(release)
	leaderWG.Wait()

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("follower status = %d, want 503", rec.Code)
	}
	if rec.Header().Get("X-CSAR-Status") != "cache_coalesce_wait_timeout" {
		t.Fatalf("X-CSAR-Status = %q, want cache_coalesce_wait_timeout", rec.Header().Get("X-CSAR-Status"))
	}
}
