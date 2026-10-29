package cache

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/ledatu/csar-core/readcache"
)

func TestCoalesceCapacityDoesNotBypassToUpstream(t *testing.T) {
	rc := NewResponseCache(slog.Default())
	group, err := readcache.NewGroup[capturedResponse](readcache.Limits{MaxKeys: 1, MaxFollowers: 1, MaxKeyBytes: 64})
	if err != nil {
		t.Fatal(err)
	}
	rc.coalescer = group
	_, call, release, err := group.Begin("occupied")
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	defer group.Finish("occupied", call, capturedResponse{}, nil)
	handler := rc.Wrap(Config{RouteKey: "GET:/data", Coalesce: &CoalesceConfig{Enabled: true, Wait: time.Second}}, http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Fatal("overload bypassed admission") }))
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/data", nil))
	if response.Code != http.StatusServiceUnavailable || response.Header().Get("Retry-After") != "1" || response.Header().Get("X-CSAR-Status") != "cache_coalesce_capacity" {
		t.Fatal(response.Code, response.Header())
	}
}

func TestCoalesceLeaderPanicCompletesTicket(t *testing.T) {
	rc := NewResponseCache(slog.Default())
	request := httptest.NewRequest(http.MethodGet, "/data", nil)
	cfg := Config{RouteKey: "GET:/data", Coalesce: &CoalesceConfig{Enabled: true, Wait: time.Second}}
	var follower *readcache.Call[capturedResponse]
	var release func()
	next := http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		leader, call, leave, err := rc.coalescer.Begin("test-key")
		if err != nil || leader {
			t.Fatal("cannot join active leader", err)
		}
		follower, release = call, leave
		panic("upstream panic")
	})
	func() {
		defer func() {
			if recover() == nil {
				t.Error("panic swallowed")
			}
		}()
		rc.serveCoalesced(httptest.NewRecorder(), request, cfg, "test-key", nil, nil, NewMemoryStore(), next)
	}()
	if follower == nil {
		t.Fatal("no follower")
	}
	defer release()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if _, err := follower.Wait(ctx); !errors.Is(err, readcache.ErrAborted) {
		t.Fatal(err)
	}
	leader, call, leave, err := rc.coalescer.Begin("test-key")
	if err != nil || !leader {
		t.Fatal("leaked flight", err)
	}
	defer leave()
	rc.coalescer.Finish("test-key", call, capturedResponse{}, nil)
}
