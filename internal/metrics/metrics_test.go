package metrics

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

func TestNew_RegistersAllMetrics(t *testing.T) {
	reg := prometheus.NewRegistry()
	m := New(reg)

	if m == nil {
		t.Fatal("New() returned nil")
	}

	// Verify metrics are registered by gathering them
	_, err := reg.Gather()
	if err != nil {
		t.Fatalf("Gather: %v", err)
	}

	// Should have metrics registered (they appear once values are set)
	// Let's trigger some metrics and check
	m.RequestsTotal.WithLabelValues("GET", "/api", "200").Inc()
	m.ConnectedRouters.Set(5)
	m.KMSCacheHits.Inc()

	families, err := reg.Gather()
	if err != nil {
		t.Fatalf("Gather after increment: %v", err)
	}

	wantMetrics := map[string]bool{
		"csar_router_requests_total":         false,
		"csar_coordinator_connected_routers": false,
		"csar_kms_cache_hits_total":          false,
	}

	for _, f := range families {
		if _, ok := wantMetrics[f.GetName()]; ok {
			wantMetrics[f.GetName()] = true
		}
	}

	for name, found := range wantMetrics {
		if !found {
			t.Errorf("metric %q not found in registry", name)
		}
	}
}

func TestMetricsMiddleware_RecordsRequestCount(t *testing.T) {
	reg := prometheus.NewRegistry()
	m := New(reg)

	upstream := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	})

	handler := m.Middleware("/api/v1", upstream)

	// Make 3 requests
	for i := 0; i < 3; i++ {
		req := httptest.NewRequest(http.MethodGet, "/api/v1", nil)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200", rec.Code)
		}
	}

	// Check counter
	families, _ := reg.Gather()
	for _, f := range families {
		if f.GetName() == "csar_router_requests_total" {
			for _, metric := range f.GetMetric() {
				if metric.GetCounter().GetValue() != 3 {
					t.Errorf("requests_total = %f, want 3", metric.GetCounter().GetValue())
				}
				// Check labels
				labels := map[string]string{}
				for _, lp := range metric.GetLabel() {
					labels[lp.GetName()] = lp.GetValue()
				}
				if labels["method"] != "GET" {
					t.Errorf("method label = %q, want GET", labels["method"])
				}
				if labels["path"] != "/api/v1" {
					t.Errorf("path label = %q, want /api/v1", labels["path"])
				}
				if labels["status"] != "200" {
					t.Errorf("status label = %q, want 200", labels["status"])
				}
			}
			return
		}
	}
	t.Error("csar_router_requests_total metric not found")
}

func TestMetricsMiddleware_RecordsDuration(t *testing.T) {
	reg := prometheus.NewRegistry()
	m := New(reg)

	upstream := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(10 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
	})

	handler := m.Middleware("/api/v1", upstream)

	req := httptest.NewRequest(http.MethodGet, "/api/v1", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	families, _ := reg.Gather()
	for _, f := range families {
		if f.GetName() == "csar_router_request_duration_seconds" {
			for _, metric := range f.GetMetric() {
				count := metric.GetHistogram().GetSampleCount()
				if count != 1 {
					t.Errorf("duration count = %d, want 1", count)
				}
				sum := metric.GetHistogram().GetSampleSum()
				if sum < 0.01 {
					t.Errorf("duration sum = %f, want >= 0.01", sum)
				}
			}
			return
		}
	}
	t.Error("csar_router_request_duration_seconds metric not found")
}

func TestMetricsMiddleware_RecordsErrorStatus(t *testing.T) {
	reg := prometheus.NewRegistry()
	m := New(reg)

	upstream := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	})

	handler := m.Middleware("/api/v1", upstream)

	req := httptest.NewRequest(http.MethodPost, "/api/v1", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	families, _ := reg.Gather()
	for _, f := range families {
		if f.GetName() == "csar_router_requests_total" {
			for _, metric := range f.GetMetric() {
				labels := map[string]string{}
				for _, lp := range metric.GetLabel() {
					labels[lp.GetName()] = lp.GetValue()
				}
				if labels["status"] == "500" && labels["method"] == "POST" {
					return // Found it
				}
			}
		}
	}
	t.Error("expected requests_total with status=500 and method=POST")
}

func TestRecordThrottleWait(t *testing.T) {
	reg := prometheus.NewRegistry()
	m := New(reg)

	m.RecordThrottleWait("GET:/api", 150*time.Millisecond, false)
	m.RecordThrottleWait("GET:/api", 0, true) // timeout

	families, _ := reg.Gather()

	foundWait := false
	foundTimeout := false
	for _, f := range families {
		if f.GetName() == "csar_throttle_wait_duration_seconds" {
			for _, metric := range f.GetMetric() {
				if metric.GetHistogram().GetSampleCount() == 2 {
					foundWait = true
				}
			}
		}
		if f.GetName() == "csar_throttle_timeouts_total" {
			for _, metric := range f.GetMetric() {
				if metric.GetCounter().GetValue() == 1 {
					foundTimeout = true
				}
			}
		}
	}

	if !foundWait {
		t.Error("throttle wait duration not recorded")
	}
	if !foundTimeout {
		t.Error("throttle timeout not recorded")
	}
}

func TestSetThrottleQueueDepth(t *testing.T) {
	reg := prometheus.NewRegistry()
	m := New(reg)

	m.SetThrottleQueueDepth("GET:/api", 42)

	families, _ := reg.Gather()
	for _, f := range families {
		if f.GetName() == "csar_throttle_queue_depth" {
			metrics := f.GetMetric()
			if len(metrics) == 0 {
				t.Error("no metrics found")
				return
			}
			metric := metrics[0]
			if metric.GetGauge().GetValue() != 42 {
				t.Errorf("queue_depth = %f, want 42", metric.GetGauge().GetValue())
			}
			return
		}
	}
	t.Error("csar_throttle_queue_depth not found")
}

func TestRecordUpstream(t *testing.T) {
	reg := prometheus.NewRegistry()
	m := New(reg)

	m.RecordUpstream("GET:/api", 200, 50*time.Millisecond)
	m.RecordUpstream("GET:/api", 500, 1*time.Second)

	families, _ := reg.Gather()

	foundDuration := false
	foundError := false
	for _, f := range families {
		if f.GetName() == "csar_upstream_duration_seconds" {
			foundDuration = true
		}
		if f.GetName() == "csar_upstream_errors_total" {
			for _, metric := range f.GetMetric() {
				if metric.GetCounter().GetValue() >= 1 {
					foundError = true
				}
			}
		}
	}

	if !foundDuration {
		t.Error("upstream duration not recorded")
	}
	if !foundError {
		t.Error("upstream error for 500 not recorded")
	}
}

func TestSetCircuitBreakerState(t *testing.T) {
	reg := prometheus.NewRegistry()
	m := New(reg)

	m.SetCircuitBreakerState("api-breaker", 1) // open
	m.RecordCircuitBreakerTrip("api-breaker")

	families, _ := reg.Gather()
	for _, f := range families {
		if f.GetName() == "csar_circuit_breaker_state" {
			metrics := f.GetMetric()
			if len(metrics) == 0 {
				t.Error("no metrics found")
				return
			}
			metric := metrics[0]
			if metric.GetGauge().GetValue() != 1 {
				t.Errorf("cb state = %f, want 1 (open)", metric.GetGauge().GetValue())
			}
			return
		}
	}
	t.Error("circuit breaker state metric not found")
}

func TestRecordKMSDecrypt(t *testing.T) {
	reg := prometheus.NewRegistry()
	m := New(reg)

	m.RecordKMSDecrypt("key-123", 5*time.Millisecond, false)  // miss
	m.RecordKMSDecrypt("key-123", 100*time.Microsecond, true) // hit

	families, _ := reg.Gather()

	foundHits := false
	foundMisses := false
	for _, f := range families {
		if f.GetName() == "csar_kms_cache_hits_total" {
			for _, metric := range f.GetMetric() {
				if metric.GetCounter().GetValue() == 1 {
					foundHits = true
				}
			}
		}
		if f.GetName() == "csar_kms_cache_misses_total" {
			for _, metric := range f.GetMetric() {
				if metric.GetCounter().GetValue() == 1 {
					foundMisses = true
				}
			}
		}
	}

	if !foundHits {
		t.Error("KMS cache hits not recorded")
	}
	if !foundMisses {
		t.Error("KMS cache misses not recorded")
	}
}

func TestMetricsHandler_ServesPrometheus(t *testing.T) {
	reg := prometheus.NewRegistry()
	m := New(reg)

	// Increment something
	m.RequestsTotal.WithLabelValues("GET", "/test", "200").Inc()

	handler := m.Handler()
	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rec.Code)
	}

	body, _ := io.ReadAll(rec.Result().Body)
	if !strings.Contains(string(body), "csar_router_requests_total") {
		t.Error("metrics response should contain csar_router_requests_total")
	}
}
