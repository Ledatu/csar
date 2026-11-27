package main

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ledatu/csar-core/gatewayctx"
	"github.com/ledatu/csar-core/jwtx"
	"github.com/ledatu/csar-core/stsclient"
	"github.com/ledatu/csar-core/tlsx"
	"github.com/ledatu/csar/internal/backpressure"
)

// Exercise normal STS negotiation/decoding and existing v1 backpressure together.
func TestResponseGzipSTSClientPreservesV1(t *testing.T) {
	key, err := jwtx.GenerateKeyPair("EdDSA")
	if err != nil {
		t.Fatal(err)
	}
	var exchanges atomic.Int32
	sts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		exchanges.Add(1)
		_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "test-token", "token_type": "Bearer", "expires_in": 3600})
	}))
	defer sts.Close()
	source, err := stsclient.New(&stsclient.Config{STSEndpoint: sts.URL, Audience: "test", ServiceName: "svc:test", AssertionAudience: "issuer", KeyPair: key, HTTPClient: sts.Client()})
	if err != nil {
		t.Fatal(err)
	}
	transport, err := tlsx.NewHTTPTransport(tlsx.ClientConfig{})
	if err != nil {
		t.Fatal(err)
	}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: source.Transport(transport), Timeout: 5 * time.Second}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	payload := `{"data":"` + strings.Repeat("plain-json", 2048) + `"}`
	type sample struct {
		status  int
		body    string
		headers http.Header
	}
	baseline := make(map[string]sample)
	for _, enabled := range []bool{false, true} {
		upstream := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Header.Get(gatewayctx.HeaderCsarAuthorization) != "Bearer test-token" || r.Header.Get("Authorization") != "Bearer provider-test-key" {
				t.Error("STS or caller authorization changed")
			}
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("X-CSAR-Protocol-Version", "1")
			switch r.URL.Path {
			case "/rate-limited":
				w.Header().Set("Retry-After", "2")
				w.WriteHeader(http.StatusTooManyRequests)
				_, _ = io.WriteString(w, `{"error":"vendor quota"}`)
			case "/unavailable":
				w.WriteHeader(http.StatusServiceUnavailable)
				_, _ = io.WriteString(w, `{"error":"vendor unavailable"}`)
			default:
				_, _ = io.WriteString(w, payload)
			}
		})
		observed := backpressure.New(upstream, backpressure.Config{Enabled: true}, nil, logger)
		server := httptest.NewServer(withResponseGzip(observed, enabled, logger))
		for _, path := range []string{"/ok", "/rate-limited", "/unavailable"} {
			req, requestErr := http.NewRequestWithContext(context.Background(), http.MethodPost, server.URL+path, http.NoBody)
			if requestErr != nil {
				t.Fatal(requestErr)
			}
			req.Header.Set("Authorization", "Bearer provider-test-key")
			resp, requestErr := client.Do(req)
			if requestErr != nil {
				t.Fatal(requestErr)
			}
			body, readErr := io.ReadAll(resp.Body)
			_ = resp.Body.Close()
			if readErr != nil {
				t.Fatal(readErr)
			}
			headers := make(http.Header)
			for _, name := range []string{"Content-Type", "X-CSAR-Protocol-Version", "X-CSAR-Status", "X-CSAR-Wait-MS", "Retry-After"} {
				headers[name] = resp.Header.Values(name)
			}
			got := sample{resp.StatusCode, string(body), headers}
			if !enabled {
				baseline[path] = got
			} else if !reflect.DeepEqual(got, baseline[path]) {
				t.Errorf("gzip changed decoded body or v1 errors on %s", path)
			}
			if path == "/ok" && (resp.Uncompressed != enabled || string(body) != payload) {
				t.Error("normal STS client did not transparently decode negotiated gzip")
			}
			if path != "/ok" && resp.Uncompressed {
				t.Error("gzip encoded an existing v1 error")
			}
			if path == "/rate-limited" && (resp.StatusCode != 503 || resp.Header.Get("X-CSAR-Status") != "throttled") {
				t.Error("existing 429 normalization changed")
			}
		}
		server.Close()
	}
	if exchanges.Load() != 1 {
		t.Errorf("token exchanges=%d, want one cached token", exchanges.Load())
	}
}
