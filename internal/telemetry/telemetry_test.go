package telemetry

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestNoop_CreatesValidProvider(t *testing.T) {
	p := Noop()
	if p == nil {
		t.Fatal("Noop() returned nil")
	}
	if p.Tracer() == nil {
		t.Fatal("Tracer() returned nil")
	}
	if err := p.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
}

func TestInit_WithoutOTLP(t *testing.T) {
	p, err := Init(context.Background(), Config{
		ServiceName:    "csar-test",
		ServiceVersion: "0.0.1-test",
		SampleRate:     1.0,
		// No OTLPEndpoint — uses noop exporter
	})
	if err != nil {
		t.Fatalf("Init: %v", err)
	}
	defer p.Close()

	if p.Tracer() == nil {
		t.Fatal("Tracer() returned nil")
	}
}

func TestHTTPMiddleware_WrapsHandler(t *testing.T) {
	p := Noop()
	defer p.Close()

	called := false
	upstream := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})

	handler := p.HTTPMiddleware("test-op", upstream)

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if !called {
		t.Error("upstream handler was not called")
	}
	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rec.Code)
	}
}

func TestStartSpan_CreatesChildSpan(t *testing.T) {
	p := Noop()
	defer p.Close()

	upstream := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Start a child span
		_, span := p.StartSpan(r, "child-operation")
		defer span.End()

		// Span should be valid (even if noop)
		if span == nil {
			t.Error("span is nil")
		}

		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	rec := httptest.NewRecorder()
	upstream.ServeHTTP(rec, req)
}

func TestInit_DefaultServiceName(t *testing.T) {
	p, err := Init(context.Background(), Config{
		// Empty ServiceName should default to "csar"
	})
	if err != nil {
		t.Fatalf("Init: %v", err)
	}
	defer p.Close()

	if p.Tracer() == nil {
		t.Fatal("Tracer() returned nil after default init")
	}
}
