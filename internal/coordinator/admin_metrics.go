package coordinator

import (
	"sync"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// AdminMetrics holds Prometheus metrics for the coordinator admin API.
type AdminMetrics struct {
	RequestsTotal          *prometheus.CounterVec
	FailuresTotal          *prometheus.CounterVec
	InvalidationBroadcasts prometheus.Counter
	KMSEncryptDuration     prometheus.Histogram
	StoreWriteDuration     prometheus.Histogram
	CacheEntries           prometheus.Gauge
}

var (
	adminMetricsOnce      sync.Once
	adminMetricsSingleton *AdminMetrics
)

// NewAdminMetrics returns the singleton admin API metrics instance.
// Safe to call multiple times (metrics are registered only once).
func NewAdminMetrics() *AdminMetrics {
	adminMetricsOnce.Do(func() {
		adminMetricsSingleton = &AdminMetrics{
			RequestsTotal: promauto.NewCounterVec(prometheus.CounterOpts{
				Name: "coordinator_token_admin_requests_total",
				Help: "Total number of admin API requests by operation and status.",
			}, []string{"operation", "status"}),

			FailuresTotal: promauto.NewCounterVec(prometheus.CounterOpts{
				Name: "coordinator_token_admin_failures_total",
				Help: "Total number of admin API failures by operation and reason.",
			}, []string{"operation", "reason"}),

			InvalidationBroadcasts: promauto.NewCounter(prometheus.CounterOpts{
				Name: "coordinator_token_invalidation_broadcast_total",
				Help: "Total number of token invalidation broadcasts sent to routers.",
			}),

			KMSEncryptDuration: promauto.NewHistogram(prometheus.HistogramOpts{
				Name:    "coordinator_token_kms_encrypt_duration_seconds",
				Help:    "Duration of KMS encryption operations for token mutations.",
				Buckets: prometheus.DefBuckets,
			}),

			StoreWriteDuration: promauto.NewHistogram(prometheus.HistogramOpts{
				Name:    "coordinator_token_store_write_duration_seconds",
				Help:    "Duration of storage write operations for token mutations.",
				Buckets: prometheus.DefBuckets,
			}),

			CacheEntries: promauto.NewGauge(prometheus.GaugeOpts{
				Name: "coordinator_token_cache_entries",
				Help: "Current number of tokens in the coordinator's in-memory cache.",
			}),
		}
	})
	return adminMetricsSingleton
}
