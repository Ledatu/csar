package router

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	auditcore "github.com/ledatu/csar-core/audit"
	"github.com/ledatu/csar/internal/config"
)

func TestAuditFiniteChunkedProxyResponse(t *testing.T) {
	for _, encoded := range []bool{false, true} {
		t.Run(map[bool]string{false: "JSON", true: "gzip"}[encoded], func(t *testing.T) {
			payload := []byte(`{"code":"unavailable","message":"Bearer privatecredential","password":"must-not-store"}`)
			if encoded {
				var buf bytes.Buffer
				zw := gzip.NewWriter(&buf)
				if _, err := zw.Write(payload); err != nil {
					t.Fatal(err)
				}
				if err := zw.Close(); err != nil {
					t.Fatal(err)
				}
				payload = buf.Bytes()
			}
			release := make(chan struct{})
			var once sync.Once
			unblock := func() { once.Do(func() { close(release) }) }
			var calls atomic.Int32
			split := len(payload) / 2
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
				calls.Add(1)
				w.Header().Set("Content-Type", "application/json")
				if encoded {
					w.Header().Set("Content-Encoding", "gzip")
				}
				w.WriteHeader(503)
				_, _ = w.Write(payload[:split])
				if err := http.NewResponseController(w).Flush(); err != nil {
					t.Error(err)
					return
				}
				select {
				case <-release:
					_, _ = w.Write(payload[split:])
				case <-req.Context().Done():
				}
			}))
			defer upstream.Close()
			defer unblock()
			mode := config.AuditModeErrors
			events := make(auditChannelRecorder, 2)
			r, err := New(newTestConfig(map[string]config.PathConfig{"/stream": {"get": {
				Backend: config.BackendConfig{TargetURL: upstream.URL}, Audit: &mode,
			}}}), newTestLogger(), func(r *Router) { r.auditClient = events })
			if err != nil {
				t.Fatal(err)
			}
			defer r.Close()
			server := httptest.NewServer(r)
			defer server.Close()
			defer unblock()
			client := &http.Client{Transport: &http.Transport{DisableCompression: true}, Timeout: 3 * time.Second}
			defer client.CloseIdleConnections()
			req, err := http.NewRequestWithContext(context.Background(), "GET", server.URL+"/stream", nil)
			if err != nil {
				t.Fatal(err)
			}
			req.Header.Set("Accept-Encoding", "gzip")
			response, err := client.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			defer response.Body.Close()
			prefix := make([]byte, split)
			if _, err := io.ReadFull(response.Body, prefix); err != nil {
				t.Fatalf("prefix was not forwarded before upstream completed: %v", err)
			}
			if !bytes.Equal(prefix, payload[:split]) || response.ContentLength != -1 || response.StatusCode != 503 || response.Header.Get("X-CSAR-Protocol-Version") != "1" {
				t.Fatal("changed streamed response or v1 headers")
			}
			if encoded && response.Header.Get("Content-Encoding") != "gzip" {
				t.Fatal("changed upstream gzip representation")
			}
			select {
			case <-events:
				t.Fatal("emitted audit before response completion")
			default:
			}
			unblock()
			rest, err := io.ReadAll(response.Body)
			if err != nil || !bytes.Equal(append(prefix, rest...), payload) {
				t.Fatalf("changed forwarded body: %v", err)
			}
			select {
			case event := <-events:
				var meta struct {
					Response auditcore.HTTPResponse `json:"http_response"`
				}
				if err := json.Unmarshal(event.Metadata, &meta); err != nil {
					t.Fatal(err)
				}
				if meta.Response.State != "captured" || !meta.Response.CaptureComplete || meta.Response.Code != "unavailable" || meta.Response.ObservedBytes != int64(len(payload)) {
					t.Fatalf("response=%+v", meta.Response)
				}
				if strings.Contains(string(event.Metadata), "privatecredential") || strings.Contains(string(event.Metadata), "must-not-store") {
					t.Fatal("unsafe error persisted")
				}
			case <-time.After(time.Second):
				t.Fatal("audit was not emitted")
			}
			if calls.Load() != 1 || len(events) != 0 {
				t.Fatal("unexpected retry or duplicate audit")
			}
		})
	}
}

func TestAuditTrueStreamsRemainOmitted(t *testing.T) {
	for _, requestStream := range []bool{false, true} {
		t.Run(map[bool]string{false: "response SSE", true: "request SSE"}[requestStream], func(t *testing.T) {
			events := &stubAuditRecorder{}
			r := &Router{auditClient: events}
			rt := &route{auditMode: config.AuditModeErrors}
			h := r.wrapUpstreamWithAudit(rt, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				ct := "text/event-stream; charset=utf-8"
				if requestStream {
					ct = "application/json"
				}
				w.Header().Set("Content-Type", ct)
				w.WriteHeader(503)
				_, _ = io.WriteString(w, `{"message":"do-not-capture"}`)
				_ = http.NewResponseController(w).Flush()
			}))
			req := httptest.NewRequest("GET", "/stream", nil)
			if requestStream {
				req.Header.Set("Accept", "text/event-stream")
			}
			h.ServeHTTP(httptest.NewRecorder(), req)
			if len(events.events) != 1 || !bytes.Contains(events.events[0].Metadata, []byte(`"omission_reason":"streaming"`)) || bytes.Contains(events.events[0].Metadata, []byte("do-not-capture")) {
				t.Fatal("captured event stream or lost audit")
			}
		})
	}
}

type auditBrokenReader struct{}

func (auditBrokenReader) Read([]byte) (int, error) { return 0, io.ErrUnexpectedEOF }

func TestAuditReadFromFailureIsIncomplete(t *testing.T) {
	capture := &auditResponseCapture{ResponseWriter: httptest.NewRecorder(), capture: true}
	capture.WriteHeader(503)
	_, err := capture.ReadFrom(io.MultiReader(strings.NewReader(`{"message":"valid prefix"}`), auditBrokenReader{}))
	if !errors.Is(err, io.ErrUnexpectedEOF) || !capture.failed {
		t.Fatal("read failure was not marked incomplete")
	}
}

func TestAuditIncompleteJSONEnvelopeIsNotSaved(t *testing.T) {
	for _, canceled := range []bool{false, true} {
		t.Run(map[bool]string{false: "reader error", true: "canceled request"}[canceled], func(t *testing.T) {
			events := &stubAuditRecorder{}
			r := &Router{auditClient: events}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			h := r.wrapUpstreamWithAudit(&route{auditMode: config.AuditModeErrors}, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(503)
				body := `{"message":"valid but incomplete source"}`
				if canceled {
					_, _ = io.WriteString(w, body)
					cancel()
					return
				}
				readerFrom, ok := w.(io.ReaderFrom)
				if !ok {
					t.Fatal("audit writer lost ReadFrom")
				}
				_, _ = readerFrom.ReadFrom(io.MultiReader(strings.NewReader(body), auditBrokenReader{}))
			}))
			h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("GET", "/test", nil).WithContext(ctx))
			if len(events.events) != 1 || bytes.Contains(events.events[0].Metadata, []byte("valid but incomplete")) || !bytes.Contains(events.events[0].Metadata, []byte(`"capture_complete":false`)) {
				t.Fatal("stored a complete JSON prefix from an incomplete response")
			}
		})
	}
}

func TestAuditEncodingIncludesEveryHeaderLine(t *testing.T) {
	capture := &auditResponseCapture{ResponseWriter: httptest.NewRecorder(), capture: true}
	capture.Header().Add("Content-Encoding", "gzip")
	capture.Header().Add("Content-Encoding", "br")
	capture.WriteHeader(503)
	if capture.contentEncoding != "gzip,br" {
		t.Fatal("ignored later encoding header")
	}
}

func TestAuditCopyRemainsBoundedAcrossFlushes(t *testing.T) {
	for _, status := range []int{200, 503} {
		capture := &auditResponseCapture{ResponseWriter: httptest.NewRecorder(), capture: true}
		capture.WriteHeader(status)
		chunk := bytes.Repeat([]byte("x"), 8<<10)
		for range 128 {
			if _, err := capture.Write(chunk); err != nil {
				t.Fatal(err)
			}
			if err := capture.FlushError(); err != nil {
				t.Fatal(err)
			}
		}
		want := 0
		if status >= 400 {
			want = auditcore.MaxHTTPInspectBytes + 1
		}
		if len(capture.body) != want || capture.observedBytes != int64(128*len(chunk)) {
			t.Fatalf("captured=%d observed=%d", len(capture.body), capture.observedBytes)
		}
	}
}
