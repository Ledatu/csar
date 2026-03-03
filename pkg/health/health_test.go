package health

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestHandler_ReturnsOK(t *testing.T) {
	handler := Handler("1.0.0")

	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	rec := httptest.NewRecorder()

	handler(rec, req)

	resp := rec.Result()
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want %d", resp.StatusCode, http.StatusOK)
	}

	if ct := resp.Header.Get("Content-Type"); ct != "application/json" {
		t.Errorf("Content-Type = %q, want %q", ct, "application/json")
	}

	var status Status
	if err := json.NewDecoder(resp.Body).Decode(&status); err != nil {
		t.Fatalf("decode error: %v", err)
	}

	if status.Status != "ok" {
		t.Errorf("Status = %q, want %q", status.Status, "ok")
	}
	if status.Version != "1.0.0" {
		t.Errorf("Version = %q, want %q", status.Version, "1.0.0")
	}
}

func TestHandler_DifferentVersions(t *testing.T) {
	versions := []string{"dev", "2.0.0-rc1", "0.0.1"}

	for _, v := range versions {
		t.Run(v, func(t *testing.T) {
			handler := Handler(v)
			req := httptest.NewRequest(http.MethodGet, "/health", nil)
			rec := httptest.NewRecorder()
			handler(rec, req)

			var status Status
			json.NewDecoder(rec.Result().Body).Decode(&status)
			if status.Version != v {
				t.Errorf("Version = %q, want %q", status.Version, v)
			}
		})
	}
}
