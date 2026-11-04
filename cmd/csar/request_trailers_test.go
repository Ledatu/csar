package main

import (
	"bufio"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ledatu/csar/internal/config"
	"github.com/ledatu/csar/internal/router"
)

func TestPOSTTrailersSurviveRouterContextCopies(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Error(err)
		}
		w.Write(append(body, []byte(":"+r.Trailer.Get("X-Selector"))...))
	}))
	defer upstream.Close()
	gateway, err := router.New(&config.Config{
		ListenAddr: ":0",
		Paths: map[string]config.PathConfig{
			"/stocks": {"post": {
				Backend: config.BackendConfig{TargetURL: upstream.URL},
				Cache:   &config.CacheConfig{Methods: []string{"POST"}},
			}},
		},
	}, slog.Default())
	if err != nil {
		t.Fatal(err)
	}
	handler := preservePOSTTrailers(gateway)
	for _, selector := range []string{"one", "two"} {
		wire := "POST /stocks HTTP/1.1\r\nHost: local\r\nTransfer-Encoding: chunked\r\n\r\n1\r\na\r\n0\r\nX-Selector: " + selector + "\r\n\r\n"
		request, parseErr := http.ReadRequest(bufio.NewReader(strings.NewReader(wire)))
		if parseErr != nil {
			t.Fatal(parseErr)
		}
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, request)
		request.Body.Close()
		if rec.Code != 200 || rec.Header().Get("X-CSAR-Cache") != "BYPASS" || rec.Body.String() != "a:"+selector {
			t.Fatalf("status=%d cache=%s body=%q, want 200 bypass and a:%s", rec.Code, rec.Header().Get("X-CSAR-Cache"), rec.Body.String(), selector)
		}
	}
}
