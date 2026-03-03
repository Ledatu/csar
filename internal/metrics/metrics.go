package metrics

import (
	"net/http"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Metrics holds all Prometheus metrics for CSAR.
type Metrics struct {
	// --- Request metrics ---

	// RequestsTotal counts total HTTP requests by method, path, and status code.
	RequestsTotal *prometheus.CounterVec

	// RequestDuration observes request latency in seconds by method and path.
	RequestDuration *prometheus.HistogramVec

	// --- Throttle metrics ---

	// ThrottleQueueDepth is a gauge of currently waiting requests per route.
	ThrottleQueueDepth *prometheus.GaugeVec

	// ThrottleWaitDuration observes how long requests waited in the queue.
	ThrottleWaitDuration *prometheus.HistogramVec

	// ThrottleTimeouts counts requests that exceeded max_wait per route.
	ThrottleTimeouts *prometheus.CounterVec

	// --- Circuit breaker metrics ---

	// CircuitBreakerState reports the current state of each circuit breaker.
	// Values: 0 = closed, 1 = open, 2 = half-open.
	CircuitBreakerState *prometheus.GaugeVec

	// CircuitBreakerTrips counts how many times each breaker transitioned to open.
	CircuitBreakerTrips *prometheus.CounterVec

	// --- Upstream metrics ---

	// UpstreamDuration observes upstream response time in seconds.
	UpstreamDuration *prometheus.HistogramVec

	// UpstreamErrors counts upstream errors (connection failures, 5xx).
	UpstreamErrors *prometheus.CounterVec

	// --- KMS / Auth metrics ---

	// KMSDecryptDuration observes KMS decrypt latency.
	KMSDecryptDuration *prometheus.HistogramVec

	// KMSCacheHits counts cache hits for KMS decryption.
	KMSCacheHits prometheus.Counter

	// KMSCacheMisses counts cache misses for KMS decryption.
	KMSCacheMisses prometheus.Counter

	// --- Coordinator metrics ---

	// ConnectedRouters is a gauge of currently connected routers.
	ConnectedRouters prometheus.Gauge

	// QuotaRedistributions counts how many times quotas were recalculated.
	QuotaRedistributions prometheus.Counter

	// ConfigPushes counts config updates pushed to routers.
	ConfigPushes *prometheus.CounterVec

	// Registry for testing.
	registry *prometheus.Registry
}

// New creates and registers all CSAR Prometheus metrics.
// If registry is nil, the default global registry is used.
func New(registry *prometheus.Registry) *Metrics {
	if registry == nil {
		registry = prometheus.DefaultRegisterer.(*prometheus.Registry)
	}

	factory := promauto.With(registry)

	m := &Metrics{
		registry: registry,

		// --- Request ---
		RequestsTotal: factory.NewCounterVec(prometheus.CounterOpts{
			Namespace: "csar",
			Subsystem: "router",
			Name:      "requests_total",
			Help:      "Total number of HTTP requests handled by the router.",
		}, []string{"method", "path", "status"}),

		RequestDuration: factory.NewHistogramVec(prometheus.HistogramOpts{
			Namespace: "csar",
			Subsystem: "router",
			Name:      "request_duration_seconds",
			Help:      "Request processing duration in seconds.",
			Buckets:   prometheus.DefBuckets,
		}, []string{"method", "path"}),

		// --- Throttle ---
		ThrottleQueueDepth: factory.NewGaugeVec(prometheus.GaugeOpts{
			Namespace: "csar",
			Subsystem: "throttle",
			Name:      "queue_depth",
			Help:      "Number of requests currently waiting in the throttle queue.",
		}, []string{"route"}),

		ThrottleWaitDuration: factory.NewHistogramVec(prometheus.HistogramOpts{
			Namespace: "csar",
			Subsystem: "throttle",
			Name:      "wait_duration_seconds",
			Help:      "Time spent waiting in the throttle queue.",
			Buckets:   []float64{0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1, 5, 10, 30},
		}, []string{"route"}),

		ThrottleTimeouts: factory.NewCounterVec(prometheus.CounterOpts{
			Namespace: "csar",
			Subsystem: "throttle",
			Name:      "timeouts_total",
			Help:      "Total number of requests that exceeded the max_wait timeout.",
		}, []string{"route"}),

		// --- Circuit breaker ---
		CircuitBreakerState: factory.NewGaugeVec(prometheus.GaugeOpts{
			Namespace: "csar",
			Subsystem: "circuit_breaker",
			Name:      "state",
			Help:      "Current circuit breaker state (0=closed, 1=open, 2=half-open).",
		}, []string{"breaker"}),

		CircuitBreakerTrips: factory.NewCounterVec(prometheus.CounterOpts{
			Namespace: "csar",
			Subsystem: "circuit_breaker",
			Name:      "trips_total",
			Help:      "Number of times the circuit breaker transitioned to open state.",
		}, []string{"breaker"}),

		// --- Upstream ---
		UpstreamDuration: factory.NewHistogramVec(prometheus.HistogramOpts{
			Namespace: "csar",
			Subsystem: "upstream",
			Name:      "duration_seconds",
			Help:      "Upstream response time in seconds.",
			Buckets:   prometheus.DefBuckets,
		}, []string{"route", "status"}),

		UpstreamErrors: factory.NewCounterVec(prometheus.CounterOpts{
			Namespace: "csar",
			Subsystem: "upstream",
			Name:      "errors_total",
			Help:      "Total upstream errors (connection failures, 5xx responses).",
		}, []string{"route", "error_type"}),

		// --- KMS ---
		KMSDecryptDuration: factory.NewHistogramVec(prometheus.HistogramOpts{
			Namespace: "csar",
			Subsystem: "kms",
			Name:      "decrypt_duration_seconds",
			Help:      "KMS decrypt operation duration in seconds.",
			Buckets:   []float64{0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1},
		}, []string{"key_id"}),

		KMSCacheHits: factory.NewCounter(prometheus.CounterOpts{
			Namespace: "csar",
			Subsystem: "kms",
			Name:      "cache_hits_total",
			Help:      "Number of KMS cache hits.",
		}),

		KMSCacheMisses: factory.NewCounter(prometheus.CounterOpts{
			Namespace: "csar",
			Subsystem: "kms",
			Name:      "cache_misses_total",
			Help:      "Number of KMS cache misses.",
		}),

		// --- Coordinator ---
		ConnectedRouters: factory.NewGauge(prometheus.GaugeOpts{
			Namespace: "csar",
			Subsystem: "coordinator",
			Name:      "connected_routers",
			Help:      "Number of currently connected router instances.",
		}),

		QuotaRedistributions: factory.NewCounter(prometheus.CounterOpts{
			Namespace: "csar",
			Subsystem: "coordinator",
			Name:      "quota_redistributions_total",
			Help:      "Number of times rate limit quotas were redistributed.",
		}),

		ConfigPushes: factory.NewCounterVec(prometheus.CounterOpts{
			Namespace: "csar",
			Subsystem: "coordinator",
			Name:      "config_pushes_total",
			Help:      "Number of configuration updates pushed to routers.",
		}, []string{"type"}),
	}

	return m
}

// Handler returns an HTTP handler that exposes metrics for Prometheus scraping.
func (m *Metrics) Handler() http.Handler {
	return promhttp.HandlerFor(m.registry, promhttp.HandlerOpts{
		EnableOpenMetrics: true,
	})
}
