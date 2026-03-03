# Sprint 1: Foundation and Proxying

## Goal
A working reverse proxy with OpenAPI-driven YAML config parsing and local rate limiting with `Wait()` semantics (smoothing instead of failures).

## Tasks

### 1.1 Rework config to OpenAPI-driven `x-csar-*` format
- Rewrite `internal/config/config.go` to match the target YAML schema
- Sections: `paths`, `x-csar-backend`, `x-csar-security`, `x-csar-traffic`, `x-csar-resilience`
- `Load(path string) (*Config, error)` using `gopkg.in/yaml.v3`
- Update `config.example.yaml` to match

### 1.2 Implement ReverseProxy with `httputil.ReverseProxy`
- Build `httputil.ReverseProxy` per route target in `internal/proxy/proxy.go`
- Director function rewrites Host, Path, Scheme
- Error handler for upstream failures
- Response modifier hooks for future logging/metrics

### 1.3 Implement Smart Throttler (Token Bucket + Wait)
- Create `internal/throttle/throttle.go`
- Wrap `golang.org/x/time/rate.Limiter` per route
- `Wait(ctx)` with `max_wait` timeout from config (`x-csar-traffic`)
- Return `503` only if context deadline exceeds `max_wait` -- NOT `429`
- This is the core "smoothing" logic

### 1.4 Wire Router with config, throttle, and proxy
- Implement `internal/router/router.go`
- Path matching from config
- Request pipeline: match route -> throttle.Wait -> proxy.Forward
- HTTP server on `listen_addr`

### 1.5 Wire main.go
- CLI flag for config path (using `flag` stdlib)
- Load config, create router, start HTTP server
- Graceful shutdown via `signal.NotifyContext`

## Dependencies
- `gopkg.in/yaml.v3`
- `golang.org/x/time`

## Acceptance Criteria
- `make build` succeeds
- Router starts, reads config, proxies requests to an upstream
- Rate-limited routes queue requests (smoothing) instead of rejecting with 429
- Graceful shutdown drains in-flight requests
