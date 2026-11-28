package main

import (
	"bytes"
	"compress/gzip"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
)

func TestExplicitGzipDoesNotInferPolicyFromURL(t *testing.T) {
	plain := []byte(`{"data":"` + strings.Repeat("synthetic", 2048) + `"}`)
	var encoded bytes.Buffer
	zw := gzip.NewWriter(&encoded)
	if _, err := zw.Write(plain); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"/svc", "/svc/", "/svc/future-resource/owner/data", "/svc%2Fnew-resource", "/svc-other/data", "/public/data"} {
		for _, upstreamGzip := range []bool{false, true} {
			t.Run(path+map[bool]string{false: "/plain", true: "/gzip"}[upstreamGzip], func(t *testing.T) {
				var calls atomic.Int32
				upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					calls.Add(1)
					if r.Header.Get("Accept-Encoding") != "gzip" {
						t.Error("upstream negotiation was changed")
					}
					w.Header().Set("Content-Type", "application/json")
					w.Header().Set("X-CSAR-Protocol-Version", "1")
					if upstreamGzip {
						w.Header().Set("Content-Encoding", "gzip")
						_, _ = w.Write(encoded.Bytes())
					} else {
						_, _ = w.Write(plain)
					}
				}))
				defer upstream.Close()
				target, err := url.Parse(upstream.URL)
				if err != nil {
					t.Fatal(err)
				}
				proxy := httputil.NewSingleHostReverseProxy(target)
				handler := withResponseGzip(proxy, true, slog.New(slog.NewTextHandler(io.Discard, nil)))
				req := httptest.NewRequest(http.MethodGet, "http://router.invalid"+path, nil)
				req.Header.Set("Accept-Encoding", "gzip")
				rec := httptest.NewRecorder()
				handler.ServeHTTP(rec, req)
				if calls.Load() != 1 || rec.Code != 200 || rec.Header().Get("X-CSAR-Protocol-Version") != "1" {
					t.Fatal("upstream attempts/status/protocol changed")
				}
				switch {
				case upstreamGzip:
					if rec.Header().Get("Content-Encoding") != "gzip" || !bytes.Equal(rec.Body.Bytes(), encoded.Bytes()) {
						t.Fatal("upstream gzip was transformed")
					}
				default:
					if rec.Header().Get("Content-Encoding") != "gzip" {
						t.Fatal("external negotiated compression disabled")
					}
				}
			})
		}
	}
}
