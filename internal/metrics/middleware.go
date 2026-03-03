package metrics

import (
	"fmt"
	"net/http"
	"strconv"
	"time"
)

// Middleware returns an HTTP middleware that records request metrics.
func (m *Metrics) Middleware(routeLabel string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()

		rec := &responseRecorder{ResponseWriter: w, statusCode: http.StatusOK}
		next.ServeHTTP(rec, r)

		duration := time.Since(start).Seconds()
		status := strconv.Itoa(rec.statusCode)

		m.RequestsTotal.WithLabelValues(r.Method, routeLabel, status).Inc()
		m.RequestDuration.WithLabelValues(r.Method, routeLabel).Observe(duration)
	})
}

// RecordThrottleWait records throttle queue wait time for a route.
func (m *Metrics) RecordThrottleWait(route string, waitDuration time.Duration, timedOut bool) {
	m.ThrottleWaitDuration.WithLabelValues(route).Observe(waitDuration.Seconds())
	if timedOut {
		m.ThrottleTimeouts.WithLabelValues(route).Inc()
	}
}

// SetThrottleQueueDepth sets the current queue depth for a route.
func (m *Metrics) SetThrottleQueueDepth(route string, depth int64) {
	m.ThrottleQueueDepth.WithLabelValues(route).Set(float64(depth))
}

// RecordUpstream records an upstream call's duration and status.
func (m *Metrics) RecordUpstream(route string, statusCode int, duration time.Duration) {
	status := strconv.Itoa(statusCode)
	m.UpstreamDuration.WithLabelValues(route, status).Observe(duration.Seconds())
	if statusCode >= 500 {
		m.UpstreamErrors.WithLabelValues(route, fmt.Sprintf("http_%d", statusCode)).Inc()
	}
}

// RecordUpstreamError records an upstream connection error.
func (m *Metrics) RecordUpstreamError(route string, err error) {
	m.UpstreamErrors.WithLabelValues(route, "connection_error").Inc()
}

// SetCircuitBreakerState sets the circuit breaker state gauge.
// state: 0=closed, 1=open, 2=half-open
func (m *Metrics) SetCircuitBreakerState(breakerName string, state int) {
	m.CircuitBreakerState.WithLabelValues(breakerName).Set(float64(state))
}

// RecordCircuitBreakerTrip records a circuit breaker trip to open.
func (m *Metrics) RecordCircuitBreakerTrip(breakerName string) {
	m.CircuitBreakerTrips.WithLabelValues(breakerName).Inc()
}

// RecordKMSDecrypt records a KMS decrypt operation.
func (m *Metrics) RecordKMSDecrypt(keyID string, duration time.Duration, cacheHit bool) {
	m.KMSDecryptDuration.WithLabelValues(keyID).Observe(duration.Seconds())
	if cacheHit {
		m.KMSCacheHits.Inc()
	} else {
		m.KMSCacheMisses.Inc()
	}
}

// responseRecorder captures the HTTP status code from the response.
type responseRecorder struct {
	http.ResponseWriter
	statusCode int
}

func (r *responseRecorder) WriteHeader(code int) {
	r.statusCode = code
	r.ResponseWriter.WriteHeader(code)
}
