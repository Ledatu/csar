package main

import (
	"bytes"
	"compress/gzip"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/ledatu/csar/internal/cache"
	"github.com/ledatu/csar/internal/dlp"
	"github.com/ledatu/csar/internal/proxy"
)

func TestResponseGzipAfterRedactionAndCache(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	calls := 0
	upstream := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"email":"private@example.test","data":"`+strings.Repeat("x", 4096)+`"}`)
	})
	redacted := dlp.NewRedactor(logger).Wrap(dlp.Config{Fields: []string{"email"}}, upstream)
	cached := cache.NewResponseCache(logger).Wrap(cache.Config{RouteKey: "test", TTL: time.Minute}, redacted)
	h := withResponseGzip(cached, true, logger)
	for i := 0; i < 2; i++ {
		req := httptest.NewRequest("GET", "/", nil)
		req.Header.Set("Accept-Encoding", "gzip")
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Header().Get("Content-Encoding") != "gzip" {
			t.Fatalf("encoding=%q", rec.Header().Get("Content-Encoding"))
		}
		zr, err := gzip.NewReader(bytes.NewReader(rec.Body.Bytes()))
		if err != nil {
			t.Fatal(err)
		}
		decoded, err := io.ReadAll(zr)
		_ = zr.Close()
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Contains(decoded, []byte("private@example.test")) || !bytes.Contains(decoded, []byte("REDACTED")) {
			t.Fatal("redaction did not precede encoding")
		}
	}
	if calls != 1 {
		t.Fatalf("upstream calls=%d, want one cache fill", calls)
	}
}

func TestResponseGzipDisabled(t *testing.T) {
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, strings.Repeat("x", 4096))
	})
	h := withResponseGzip(next, false, slog.Default())
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Accept-Encoding", "gzip")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Header().Get("Content-Encoding") != "" || rec.Body.Len() != 4096 {
		t.Fatal("disabled flag changed response")
	}
}

func TestResponseGzipThroughFlushedChunkedProxy(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	payload := strings.Repeat("x", 4096)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(200)
		_ = http.NewResponseController(w).Flush()
		_, _ = io.WriteString(w, payload)
	}))
	defer upstream.Close()
	rp, err := proxy.New(upstream.URL)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(withResponseGzip(rp, true, logger))
	defer server.Close()
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.DisableCompression = true
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 5 * time.Second}
	req, _ := http.NewRequest("GET", server.URL, nil)
	req.Header.Set("Accept-Encoding", "gzip")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.Header.Get("Content-Encoding") != "gzip" {
		t.Fatal("chunked proxy flush disabled gzip")
	}
	zr, err := gzip.NewReader(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := io.ReadAll(zr)
	_ = zr.Close()
	if err != nil {
		t.Fatal(err)
	}
	if string(decoded) != payload {
		t.Fatal("chunked proxy response changed")
	}
}
