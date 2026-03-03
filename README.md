# CSAR — Coordinated Stateless API Router

CSAR is a lightweight, security-first API gateway written in Go. It proxies HTTP requests to upstream services while handling **credential injection**, **rate limiting**, **circuit breaking**, **load balancing**, **CORS**, **response caching**, and **IP access control** — all driven by a single YAML config file using OpenAPI-style extensions.

A central **Coordinator** distributes configuration, encrypted tokens, and quota assignments to a fleet of stateless routers over gRPC, enabling horizontal scaling without shared state.

## Architecture

```
                        ┌──────────────────────┐
                        │     Coordinator       │
                        │  (gRPC control plane) │
                        │  - Config push        │
                        │  - AuthService (KMS)  │
                        │  - Quota allocation   │
                        │  - Token invalidation │
                        └──────────┬───────────┘
                         TLS/mTLS  │  gRPC stream
              ┌────────────────────┼────────────────────┐
              ▼                    ▼                     ▼
     ┌────────────────┐  ┌────────────────┐   ┌────────────────┐
     │  CSAR Router   │  │  CSAR Router   │   │  CSAR Router   │
     │  (stateless)   │  │  (stateless)   │   │  (stateless)   │
     └───────┬────────┘  └───────┬────────┘   └───────┬────────┘
             │                   │                     │
    IP check │ → CORS → auth → throttle → CB → retry → proxy/LB
             │                   │                     │
             ▼                   ▼                     ▼
        ┌─────────┐        ┌─────────┐           ┌─────────┐
        │Upstream A│        │Upstream B│           │Upstream C│
        └─────────┘        └─────────┘           └─────────┘
```

### Request Pipeline

Each request passes through these stages in order:

1. **IP Access Control** — global or per-route CIDR allowlists
2. **CORS** — preflight handling and origin validation
3. **Streaming Detection** — WebSocket/SSE bypass for DLP and retry buffering
4. **Header Injection** — static headers and stripped client-supplied auth headers
5. **Auth Injection** — fetches encrypted token, decrypts via KMS, injects into upstream request
6. **JWT Validation** — inbound JWKS-based bearer token validation
7. **Throttling** — token-bucket rate limiting (local, Redis, or coordinator-assigned quotas)
8. **Circuit Breaker** — protects upstreams from cascading failures
9. **Retry** — automatic retry with exponential backoff and jitter
10. **DLP Redaction** — masks sensitive fields in upstream responses
11. **Response Cache** — serves cached responses for idempotent requests
12. **Load Balancer** — distributes requests across upstream pool with health checking
13. **Reverse Proxy** — forwards the request to the upstream target

## Features

| Area | Details |
|---|---|
| **Credential Injection** | Fetch encrypted tokens (file or gRPC AuthService), decrypt via KMS, inject into upstream headers. Supports multi-credential, dynamic per-account resolution (`{query.param}`, `{header.Name}`), and `Bearer {token}` / custom formats. |
| **Rate Limiting** | Per-route token-bucket throttling with `rps`, `burst`, and `max_wait`. Three backends: local (in-memory), Redis (distributed sliding window), or coordinator (dynamic quota assignment). |
| **Circuit Breaking** | Named profiles with configurable failure thresholds, intervals, and recovery timeouts. |
| **Load Balancing** | Round-robin and random strategies across multiple upstream targets. Active health checking (HTTP/TCP) with configurable thresholds automatically removes unhealthy targets. |
| **CORS** | Per-route Cross-Origin Resource Sharing with O(1) origin lookups and automatic OPTIONS preflight short-circuiting. |
| **Response Caching** | In-memory LRU cache for idempotent requests with configurable TTL, max entries, and max body size. Respects `Cache-Control: no-store/no-cache`. |
| **Payload Redaction (DLP)** | Masks sensitive JSON fields (`ssn`, `card_number`, nested paths) in upstream responses before returning to clients. Configurable `max_response_size` prevents DoS. |
| **Multi-Tenant Routing** | Routes to different backends based on tenant identifier in headers or host. |
| **Streaming Support** | Detects `Upgrade: websocket` and `text/event-stream` (SSE) to bypass buffering middlewares for persistent connections. |
| **JWT/JWKS Validation** | Validates inbound bearer tokens against JWKS endpoints. Supports issuer/audience checks, required claims, and claim forwarding to upstream headers. |
| **IP Access Control** | Global and per-route allowlists with individual IPs, CIDR ranges (IPv4/IPv6), and optional `X-Forwarded-For`/`X-Real-IP` trust. |
| **SSRF Protection** | Custom `DialContext` validates resolved IPs against RFC 1918/3927/4291/metadata ranges. Prevents DNS rebinding (TOCTOU) by connecting directly to validated IPs. |
| **TLS Everywhere** | Inbound HTTPS + mTLS, outbound upstream TLS + mTLS, router↔coordinator TLS + mTLS. |
| **Observability** | Prometheus metrics (request count, latency, status codes, throttle queue depth) + OpenTelemetry distributed tracing. |
| **Coordinator** | Central gRPC control plane that pushes config updates, distributes encrypted secrets, allocates per-router quotas, and broadcasts token invalidation events. |
| **Live Reload** | SIGHUP-based hot config reload without dropping active connections. |
| **KMS** | Pluggable provider interface. Ships with a local (passphrase-based) provider for dev and Yandex Cloud KMS for production. Decrypt results are cached with configurable TTL. |
| **Hardened Defaults** | Non-root Docker image, server timeouts, `MaxHeaderBytes`, TLS 1.3 for coordinator, fail-closed auth, ReDoS-safe route patterns. |

## Quick Start

### Prerequisites

- Go 1.25+
- (Optional) Redis for distributed rate limiting
- (Optional) Docker & Docker Compose for E2E tests
- (Optional) `protoc` + Go gRPC plugins for proto regeneration

### Build

```bash
make build-all          # builds csar, csar-coordinator, and mockapi
```

### Run (Development)

```bash
# 1. Start the router with the example config (no auth — no secure routes)
make run

# 2. Or with local token injection:
./bin/csar \
  -config config.example.yaml \
  -kms-provider local \
  -kms-local-keys "key-1=my-dev-passphrase,key-2=another-passphrase" \
  -token-file tokens-dev.yaml
```

**`tokens-dev.yaml`** (local dev token file):

```yaml
client_secret:
  plaintext: "my-upstream-api-secret"
  kms_key_id: "key-1"

orders_api_token:
  plaintext: "my-orders-api-key"
  kms_key_id: "key-2"
```

### Run Coordinator

```bash
# Development (insecure):
./bin/csar-coordinator \
  --listen :9090 \
  --allow-insecure-dev \
  --token-file coordinator-tokens.yaml

# Production (TLS + mTLS + allowlist):
./bin/csar-coordinator \
  --listen :9090 \
  --tls-cert /etc/csar/tls/server.pem \
  --tls-key /etc/csar/tls/server-key.pem \
  --client-ca /etc/csar/tls/client-ca.pem \
  --allowed-routers "router-1.csar.internal,router-2.csar.internal" \
  --token-file /etc/csar/tokens.yaml
```

## Configuration

CSAR is configured via a single YAML file. See [`config.example.yaml`](config.example.yaml) for a fully annotated example.

### Top-Level Fields

| Field | Description |
|---|---|
| `listen_addr` | HTTP(S) listen address (e.g. `":8080"`) |
| `tls` | Inbound TLS settings (`cert_file`, `key_file`, `client_ca_file`, `min_version`) |
| `access_control` | Global IP allowlist (`allow_cidrs`, `trust_proxy`) |
| `ssrf_protection` | SSRF protection settings (block private/loopback/link-local/metadata IPs) |
| `redis` | Redis connection for distributed rate limiting (`address`, `password`, `db`, `key_prefix`) |
| `coordinator` | Coordinator connection settings (see below) |
| `circuit_breakers` | Named circuit breaker profiles |
| `paths` | Route definitions using OpenAPI-style `x-csar-*` extensions |

### Route Extensions

Each route is defined under `paths.<path>.<method>`:

```yaml
paths:
  /api/v1/products:
    get:
      x-csar-backend:
        target_url: "https://upstream.example.com/products"
        targets:                                    # additional targets for load balancing
          - "https://upstream-2.example.com/products"
        load_balancer: "round_robin"                # "round_robin" or "random"
        health_check:                               # active health checking
          enabled: true
          mode: "http"                              # "http" or "tcp"
          path: "/health"
          interval: "10s"
          unhealthy_threshold: 3
          healthy_threshold: 2
        tls:
          ca_file: "/etc/csar/upstream-ca.pem"
          cert_file: "/etc/csar/client.pem"
          key_file: "/etc/csar/client-key.pem"

      x-csar-security:
        kms_key_id: "my-key-id"
        token_ref: "my_api_token"
        inject_header: "Authorization"
        inject_format: "Bearer {token}"

      x-csar-traffic:
        rps: 5.0
        burst: 10
        max_wait: "30s"
        backend: "local"                  # "local", "redis", or "coordinator"

      x-csar-resilience:
        circuit_breaker: "standard"

      x-csar-retry:
        max_attempts: 3
        backoff: "1s"
        max_backoff: "10s"

      x-csar-cors:
        allowed_origins: ["https://app.example.com"]
        allowed_methods: ["GET", "POST"]
        allowed_headers: ["Content-Type", "Authorization"]
        allow_credentials: true
        max_age: 86400

      x-csar-cache:
        ttl: "5m"
        max_entries: 1000
        max_body_size: 1048576

      x-csar-redact:
        fields: ["ssn", "card_number"]
        mask: "***REDACTED***"

      x-csar-access:
        allow_cidrs: ["10.0.0.0/8"]
        trust_proxy: true

      max_response_size: 10485760         # 10MB — prevents DLP/retry buffer DoS
```

### Rate Limiting Backends

| Backend | Description |
|---|---|
| `local` (default) | In-memory token bucket per pod. Fast, zero dependencies. |
| `redis` | Distributed sliding window via Redis. Globally coordinated limits across all pods. Requires top-level `redis` config. |
| `coordinator` | Local token bucket with quotas dynamically assigned by the coordinator. Quotas are redistributed as routers join/leave the fleet. |

### Coordinator Settings

```yaml
coordinator:
  enabled: true
  address: "coordinator.internal:9090"
  ca_file: "/etc/csar/tls/coordinator-ca.pem"
  cert_file: "/etc/csar/tls/router-client.pem"
  key_file: "/etc/csar/tls/router-client-key.pem"
  allow_insecure: false
```

**Validation rules** (fail at startup):

- `cert_file` and `key_file` must both be set (or both empty)
- mTLS (`cert_file`/`key_file`) requires `ca_file`
- Transport security is mandatory: provide `ca_file` or explicitly set `allow_insecure: true`
- Contradictory `ca_file` + `allow_insecure` emits a warning (`ca_file` takes precedence)

When the coordinator is enabled, the router automatically subscribes to its gRPC stream and:
- Applies **quota assignments** to local throttlers in real time
- Processes **token invalidation** events to clear stale-cached credentials

## CLI Flags

### `csar` (Router)

| Flag | Default | Description |
|---|---|---|
| `-config` | `config.example.yaml` | Path to config file |
| `-metrics-addr` | `:9100` | Prometheus metrics address (empty to disable) |
| `-otlp-endpoint` | *(empty)* | OTLP gRPC endpoint for tracing |
| `-otlp-insecure` | `false` | Allow insecure OTLP connection |
| `-kms-provider` | *(empty)* | KMS provider: `"local"` or `"yandexapi"` |
| `-kms-local-keys` | *(empty)* | Local KMS keys: `"keyID=passphrase,..."` |
| `-kms-cache-ttl` | `0` | KMS decrypt cache TTL (e.g. `"60s"`, `0` to disable) |
| `-token-file` | *(empty)* | YAML file with plaintext tokens (local dev) |

### `csar-coordinator`

| Flag | Default | Description |
|---|---|---|
| `--listen` | `:9090` | gRPC listen address |
| `--tls-cert` | *(empty)* | Server TLS certificate |
| `--tls-key` | *(empty)* | Server TLS private key |
| `--client-ca` | *(empty)* | Client CA for mTLS |
| `--allowed-routers` | *(empty)* | Comma-separated CN/SAN allowlist |
| `--allow-insecure-dev` | `false` | Allow running without TLS |
| `--token-file` | *(empty)* | YAML file with pre-encrypted token entries |

## Testing

```bash
make test              # all tests (unit + integration)
make test-unit         # unit tests only
make test-integration  # integration tests only
make test-race         # all tests with race detector
make test-e2e          # Docker-based end-to-end tests
```

### Test Coverage

| Package | What's Tested |
|---|---|
| `internal/config` | YAML parsing, validation (TLS, security, coordinator, access control, health check, CORS, cache, traffic backend) |
| `internal/router` | Route matching, prefix boundary, IP allowlisting, `trust_proxy` isolation, fail-closed auth, streaming bypass, load balancing, CORS integration |
| `internal/coordinator` | AuthService (token CRUD, gRPC errors), coordinator subscribe/health |
| `internal/kms` | Encrypt/decrypt, cache (SHA-256 keys), local provider |
| `internal/throttle` | Token bucket, burst, max wait timeout, quota updates |
| `internal/resilience` | Circuit breaker state transitions |
| `internal/proxy` | Reverse proxy forwarding, header handling, SSRF protection |
| `pkg/middleware` | Auth injection, file fetcher, coordinator fetcher |
| `tests/integration` | Full pipeline: proxy, throttle, circuit breaker, auth injection, coordinator gRPC E2E |
| `tests/e2e` | Docker Compose: mockapi → CSAR → test runner |

## Docker

```bash
# Build images
make docker-build

# Run E2E test suite
make test-e2e
```

**`Dockerfile`** produces a minimal Alpine image running as a non-root user (`csar`, UID 10001).

## Project Structure

```
cmd/
  csar/                   Router entry point
  csar-coordinator/       Coordinator entry point
  mockapi/                Test upstream server
internal/
  authn/                  JWT/JWKS validation
  cache/                  Response caching middleware
  config/                 YAML config loading + validation
  coordclient/            Coordinator subscription client (quota + token invalidation)
  coordinator/            gRPC coordinator + AuthService
  cors/                   CORS middleware
  dlp/                    Data Loss Prevention (response redaction)
  kms/                    KMS provider interface + implementations
  loadbalancer/           Upstream pool load balancing + health checking
  logging/                Structured logging + secret redaction
  metrics/                Prometheus instrumentation
  proxy/                  HTTP reverse proxy + SSRF protection
  resilience/             Circuit breaker
  retry/                  Retry middleware with backoff
  router/                 Core HTTP router (matching, pipeline, IP ACL)
  statestore/             Pluggable state store (memory, PostgreSQL placeholder)
  telemetry/              OpenTelemetry tracing
  tenant/                 Multi-tenant routing
  throttle/               Token-bucket rate limiter + Redis distributed limiter
pkg/
  health/                 Health check handler
  middleware/             Auth injection, token fetchers (static, file, gRPC)
proto/csar/v1/            Protobuf definitions (CoordinatorService, AuthService)
tests/
  integration/            In-process integration tests
  e2e/                    Docker Compose E2E tests
```

## Security Model

- **Fail-closed**: router refuses to start if `x-csar-security` routes exist but no KMS/token source is configured.
- **Header stripping**: client-supplied auth headers matching `inject_header` are always removed before injection.
- **KMS envelope encryption**: tokens are stored encrypted; decryption happens per-request via a pluggable KMS provider with caching.
- **SSRF protection**: custom `DialContext` resolves DNS, validates each IP against blocked ranges, then connects directly to the validated address — preventing DNS rebinding attacks.
- **ReDoS mitigation**: route regex patterns are length-limited and checked for catastrophic backtracking patterns at startup.
- **DLP safeguards**: `max_response_size` prevents unbounded buffer growth; streaming connections bypass buffering entirely.
- **TLS by default**: coordinator requires TLS unless explicitly overridden with `--allow-insecure-dev`. Router↔coordinator transport validates CA, cert/key pairs, and rejects contradictory configs at startup.
- **mTLS + allowlist**: coordinator supports client certificate verification and CN/SAN-based router identity allowlisting.
- **IP access control**: global and per-route CIDR allowlists with route-scoped `trust_proxy` (no cross-route bleed).
- **Sensitive log redaction**: optional `redact_sensitive_logs` scrubs authorization tokens, passwords, and secrets from structured log output.
- **Non-root container**: Docker images run as UID 10001.

## Performance

A single CSAR instance can handle **10,000+ RPS** on modern hardware. The bottleneck is typically upstream latency, not the proxy itself. Key considerations:

- Routes without DLP/retry: near-zero overhead (map lookup + token bucket CAS)
- DLP routes: limited by response body size (JSON parsing)
- Redis rate limiting: adds ~0.5–1ms per request (network RTT)
- KMS decryption: amortized by caching; cold calls go to the KMS endpoint

For deployments above ~20k RPS, deploy multiple CSAR pods behind a L4 load balancer and use `traffic.backend: "redis"` or `"coordinator"` for globally coordinated rate limits.

## License

Private — all rights reserved.
