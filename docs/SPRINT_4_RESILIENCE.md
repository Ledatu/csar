# Sprint 4: Resilience and Metrics

## Goal
Circuit breaker, Prometheus metrics, OpenTelemetry tracing, graceful shutdown with queue draining.

## Tasks

### 4.1 Circuit Breaker integration
- Create `internal/resilience/circuitbreaker.go`
- Wrap `github.com/sony/gobreaker`
- Place BEFORE the rate limiter in the pipeline (if circuit is open, fail fast with 503)
- Configurable per route via `x-csar-resilience.circuit_breaker`
- Named breaker profiles (e.g. `standard_wb`) defined in config

### 4.2 Prometheus metrics
- Create `internal/metrics/metrics.go`
- Queue depth (requests waiting in throttle)
- Request latency histograms (per route, per upstream)
- Circuit breaker state gauge (closed/half-open/open)
- Rate limiter utilization
- Expose on `/metrics` endpoint

### 4.3 OpenTelemetry tracing
- Create `internal/telemetry/telemetry.go`
- Trace spans for: route match, throttle wait, proxy forward, KMS decrypt
- Propagate trace context to upstream via headers
- OTLP exporter configuration

### 4.4 Graceful shutdown with queue draining
- Update router main.go
- `signal.NotifyContext` for SIGTERM/SIGINT
- Drain in-flight requests (especially those waiting in throttle queue)
- Close gRPC connections, flush telemetry

## Dependencies
- `github.com/sony/gobreaker`
- `github.com/prometheus/client_golang`
- `go.opentelemetry.io/otel`
- `go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc`

## Acceptance Criteria
- Circuit breaker opens after configured failures, closes after timeout
- Prometheus `/metrics` endpoint exposes all defined metrics
- Trace spans appear in OTLP-compatible backend
- Graceful shutdown waits for queued requests before exiting
