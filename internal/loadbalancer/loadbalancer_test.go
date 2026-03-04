package loadbalancer

import (
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
)

// newTestLogger returns a minimal slog.Logger suitable for tests.
func newTestLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
}

// TestNewDirector_ReplaceMode_Default verifies that the default (no pathMode)
// behaviour uses replace mode: the target path replaces the incoming request path.
func TestNewDirector_ReplaceMode_Default(t *testing.T) {
	var receivedPath string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedPath = r.URL.Path
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	pool, err := New(
		[]string{upstream.URL + "/adv/v1/balance"},
		RoundRobin,
		newTestLogger(),
	)
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/v1/balance", nil)
	rec := httptest.NewRecorder()
	pool.ServeHTTP(rec, req)

	if receivedPath != "/adv/v1/balance" {
		t.Errorf("upstream received path = %q, want %q (replace mode default)", receivedPath, "/adv/v1/balance")
	}
}

// TestNewDirector_ReplaceMode_Explicit verifies that explicitly setting
// path_mode="replace" behaves the same as the default.
func TestNewDirector_ReplaceMode_Explicit(t *testing.T) {
	var receivedPath string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedPath = r.URL.Path
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	pool, err := New(
		[]string{upstream.URL + "/adv/v1/balance"},
		RoundRobin,
		newTestLogger(),
		WithPathMode("replace"),
	)
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/v1/balance", nil)
	rec := httptest.NewRecorder()
	pool.ServeHTTP(rec, req)

	if receivedPath != "/adv/v1/balance" {
		t.Errorf("upstream received path = %q, want %q (replace mode explicit)", receivedPath, "/adv/v1/balance")
	}
}

// TestNewDirector_AppendMode verifies that path_mode="append" joins the target
// base path with the incoming request path.
func TestNewDirector_AppendMode(t *testing.T) {
	var receivedPath string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedPath = r.URL.Path
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	pool, err := New(
		[]string{upstream.URL + "/v2"},
		RoundRobin,
		newTestLogger(),
		WithPathMode("append"),
	)
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/users/42", nil)
	rec := httptest.NewRecorder()
	pool.ServeHTTP(rec, req)

	want := "/v2/api/users/42"
	if receivedPath != want {
		t.Errorf("upstream received path = %q, want %q (append mode)", receivedPath, want)
	}
}

// TestNewDirector_ReplaceMode_QueryPreserved verifies that query parameters
// from the request are preserved in replace mode.
func TestNewDirector_ReplaceMode_QueryPreserved(t *testing.T) {
	var receivedPath, receivedQuery string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedPath = r.URL.Path
		receivedQuery = r.URL.RawQuery
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	pool, err := New(
		[]string{upstream.URL + "/adv/v1/balance"},
		RoundRobin,
		newTestLogger(),
	)
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/v1/balance?seller_id=42&page=1", nil)
	rec := httptest.NewRecorder()
	pool.ServeHTTP(rec, req)

	if receivedPath != "/adv/v1/balance" {
		t.Errorf("path = %q, want %q", receivedPath, "/adv/v1/balance")
	}
	if receivedQuery != "seller_id=42&page=1" {
		t.Errorf("query = %q, want %q", receivedQuery, "seller_id=42&page=1")
	}
}

// TestNewDirector_AppendMode_EmptyBasePath verifies that append mode with an
// empty target path just uses the incoming request path.
func TestNewDirector_AppendMode_EmptyBasePath(t *testing.T) {
	var receivedPath string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedPath = r.URL.Path
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	pool, err := New(
		[]string{upstream.URL},
		RoundRobin,
		newTestLogger(),
		WithPathMode("append"),
	)
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/users/42", nil)
	rec := httptest.NewRecorder()
	pool.ServeHTTP(rec, req)

	if receivedPath != "/users/42" {
		t.Errorf("path = %q, want %q", receivedPath, "/users/42")
	}
}

// TestJoinPaths covers edge cases for the joinPaths helper.
func TestJoinPaths(t *testing.T) {
	tests := []struct {
		base, reqPath, want string
	}{
		{"", "/users", "/users"},
		{"/", "/users", "/users"},
		{"/v2", "", "/v2"},
		{"/v2", "/", "/v2"},
		{"/v2", "/users/42", "/v2/users/42"},
		{"/v2/", "/users/42", "/v2/users/42"},
		{"/v2", "users/42", "/v2/users/42"},
		{"/v2/", "users/42", "/v2/users/42"},
	}
	for _, tt := range tests {
		got := joinPaths(tt.base, tt.reqPath)
		if got != tt.want {
			t.Errorf("joinPaths(%q, %q) = %q, want %q", tt.base, tt.reqPath, got, tt.want)
		}
	}
}
