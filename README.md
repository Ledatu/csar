# CSAR — Coordinated Stateless API Router

CSAR is a lightweight, security-first API gateway written in Go. It proxies HTTP requests to upstream services while handling **credential injection**, **rate limiting**, **circuit breaking**, **load balancing**, **CORS**, **response caching**, **user/service authentication**, and **IP access control** — all driven by YAML config files using OpenAPI-style extensions.

A central **Coordinator** distributes configuration, encrypted tokens, and quota assignments to a fleet of stateless routers over gRPC, enabling horizontal scaling without shared state.

## Architecture

```
                        ┌──────────────────────┐
                        │    Coordinator       │
                        │ (gRPC control plane) │
                        │ - Config push        │
                        │ - AuthService (KMS)  │
                        │ - Quota allocation   │
                        │ - Token invalidation │
                        └──────────┬───────────┘
                         TLS/mTLS  │  gRPC stream
              ┌────────────────────┼────────────────────┐
              ▼                    ▼                    ▼
     ┌────────────────┐  ┌────────────────┐   ┌────────────────┐
     │  CSAR Router   │  │  CSAR Router   │   │  CSAR Router   │
     │  (stateless)   │  │  (stateless)   │   │  (stateless)   │
     └───────┬────────┘  └───────┬────────┘   └────────┬───────┘
             │                   │                     │
    IP check │ → CORS → auth → throttle → CB → retry → proxy/LB
             │                   │                     │
             ▼                   ▼                     ▼
        ┌──────────┐        ┌──────────┐           ┌──────────┐
        │Upstream A│        │Upstream B│           │Upstream C│
        └──────────┘        └──────────┘           └──────────┘
```

### Request Pipeline

Each request passes through these stages in order:

1. **IP Access Control** — global or per-route CIDR allowlists
2. **CORS** — preflight handling and origin validation
3. **Streaming Detection** — WebSocket/SSE bypass for DLP and retry buffering
4. **Header Injection** — static headers and stripped client-supplied auth headers
5. **Auth Injection** — fetches encrypted token, decrypts via KMS, injects into upstream request
6. **Authentication** — JWT, session or personal-key validation; shared routes select exactly one credential
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
| **Rate Limiting** | Per-route token-bucket throttling with `rps`, `burst`, and `max_wait`. Three backends: local (in-memory), Redis (distributed GCRA), or coordinator (dynamic quota assignment). Supports dynamic per-entity keys (`{query.*}`, `{header.*}`, `{path.*}`) and VIP overrides. |
| **Global Throttle** | Safety-net rate limit applied to all routes before per-route throttle. Fast in-memory atomic counter prevents runaway traffic. |
| **Adaptive Backpressure** | Reads upstream wait headers (`Retry-After`, `X-RateLimit-Reset` as seconds or epoch, or any configured header such as `X-Ratelimit-Retry`) from 429 responses and suspends the token bucket accordingly — on Redis backends only the key of the entity that got the 429. |
| **Circuit Breaking** | Named profiles with configurable failure thresholds, intervals, and recovery timeouts. |
| **Load Balancing** | Round-robin and random strategies across multiple upstream targets. Active health checking (HTTP/TCP) with configurable thresholds automatically removes unhealthy targets. |
| **CORS** | Per-route Cross-Origin Resource Sharing with O(1) origin lookups and automatic OPTIONS preflight short-circuiting. |
| **Response Caching** | In-memory LRU cache for idempotent requests with configurable TTL, max entries, and max body size. Respects `Cache-Control: no-store/no-cache`. |
| **Payload Redaction (DLP)** | Masks sensitive JSON fields (`ssn`, `card_number`, nested paths, wildcards) in upstream responses before returning to clients. Configurable `max_response_size` prevents DoS. |
| **Multi-Tenant Routing** | Routes to different backends based on tenant identifier in headers or host. |
| **Streaming Support** | Detects `Upgrade: websocket` and `text/event-stream` (SSE) to bypass buffering middlewares for persistent connections. |
| **Authentication** | JWT/JWKS, browser sessions and personal API keys. Shared routes select exactly one credential and reject ambiguity without fallback. JWTs support issuer/audience checks, required claims and claim forwarding. |
| **IP Access Control** | Global and per-route allowlists with individual IPs, CIDR ranges (IPv4/IPv6), and optional `X-Forwarded-For`/`X-Real-IP` trust. |
| **SSRF Protection** | Custom `DialContext` validates resolved IPs against RFC 1918/3927/4291/metadata ranges. Prevents DNS rebinding (TOCTOU) by connecting directly to validated IPs. |
| **TLS Everywhere** | Inbound HTTPS + mTLS, outbound upstream TLS + mTLS, router↔coordinator TLS + mTLS. |
| **Observability** | Prometheus metrics (request count, latency, status codes, throttle queue depth) + OpenTelemetry distributed tracing. |
| **Coordinator** | Central gRPC control plane that pushes config updates, distributes encrypted secrets, allocates per-router quotas, and broadcasts token invalidation events. Supports three token backends (file, PostgreSQL, S3 on-demand) and three config sources (file, S3, HTTP) with SHA-256 integrity checking (TOFU or pinned). |
| **Multi-File Config** | Split configuration across multiple files with `include:` glob patterns, cycle detection, and deterministic merge order. |
| **Named Policies** | Define reusable throttling, CORS, retry, redact, auth-validate, and security policies at the top level. Routes reference them by name with optional inline overrides. |
| **Env Var Expansion** | Config string values support `${VAR}` and `$VAR` expansion, applied post-YAML-parse (injection-safe). |
| **Live Reload** | SIGHUP-based hot config reload without dropping active connections. Throttle state and health checks survive reload. |
| **KMS** | Pluggable provider interface. Ships with a local (passphrase-based) provider for dev and Yandex Cloud KMS for production (metadata, IAM token, OAuth, or service account auth). Decrypt results are cached with configurable TTL. |
| **Deployment Profiles** | Three built-in profiles (`dev-local`, `prod-single`, `prod-distributed`) enforce security constraints at startup. Set via `profile:` in config. Runtime KMS provider is also validated against the active profile. |
| **JSON Schema** | IDE autocomplete and validation via `csar.schema.json`. Works with VS Code (YAML extension), JetBrains, Neovim, and any editor supporting yaml-language-server. |
| **csar-helper CLI** | Companion tool: `init` (config scaffolding), `validate`, `inspect` (resolved config with source tracing), `simulate` (dry-run route matching), `bench` (HTTP load testing with live TUI), `dev-jwks` (local JWKS server), `keys` (key generation, JWKS conversion, JWT issuing), `db init`/`migrate`, `token encrypt`. |
| **Hardened Defaults** | Non-root Docker image, server timeouts, `MaxHeaderBytes`, TLS 1.3 for coordinator, fail-closed auth, ReDoS-safe route patterns. |

## Wire Protocol

CSAR implements a versioned wire protocol for SDK clients. Every response includes:

- `X-CSAR-Protocol-Version: 1` — protocol version for SDK compatibility detection
- `X-CSAR-Status` — present only on CSAR-originated errors (`throttled`, `throttle_unavailable`, `circuit_open`, `circuit_half_open`, `backpressure`)
- `X-CSAR-Wait-MS` — on a throttled `503`, the milliseconds the client should wait before retrying (SDKs prefer it over `Retry-After`); on success, the milliseconds the request spent in CSAR's internal queue
- `Retry-After` — standard HTTP retry hint (seconds)

See [`docs/PROTOCOL_SPEC.md`](docs/PROTOCOL_SPEC.md) for the complete specification, error codes, and SDK compatibility matrix.

## Health & Readiness

CSAR exposes two probe endpoints:

| Endpoint | Purpose | Response |
|---|---|---|
| `/health` | Liveness probe | `{"status":"ok","version":"..."}` — always returns 200 |
| `/readiness` | Readiness probe | `{"status":"ready\|degraded\|not_ready","version":"...","checks":{...}}` — returns 503 when not ready |

Readiness checks verify:
- **Router**: coordinator stream, config source, KMS reachability
- **Coordinator**: token backend, state store, admin API TLS

Configure via:

```yaml
readiness:
  enabled: true
  path: "/readiness"
  include_details: true
```

## Debug Headers & Traceability

When `debug_headers` is enabled, CSAR generates/propagates request IDs and emits route identifiers for debugging:

- `X-Request-ID` — generated (UUID) if not present in the inbound request; propagated to upstream and response
- `X-CSAR-Route-ID` — matched route key (e.g. `GET:/api/v1/products`)

```yaml
debug_headers:
  enabled: true
  emit_route_id: true
  request_id_header: "X-Request-ID"
```

Both headers are automatically added to the CORS `Access-Control-Expose-Headers` list.

## Error Response Format

All CSAR-originated error responses use a stable JSON schema:

```json
{
  "code": "throttled",
  "status": 503,
  "message": "service temporarily unavailable",
  "retry_after_ms": 5000,
  "request_id": "abc-123-def"
}
```

Standard error codes: `route_not_found`, `access_denied`, `auth_failed`, `throttled`, `circuit_open`, `backpressure`, `upstream_error`, `no_healthy_upstream`, `tenant_not_found`, `response_too_large`. See [`docs/PROTOCOL_SPEC.md`](docs/PROTOCOL_SPEC.md) for details.

## SDK Metrics

CSAR exposes SDK-oriented Prometheus metrics for monitoring protocol behavior:

| Metric | Type | Labels | Description |
|---|---|---|---|
| `csar_sdk_throttled_responses_total` | counter | route, status_value | CSAR-originated 503 responses |
| `csar_sdk_wait_emitted_ms` | histogram | route | X-CSAR-Wait-MS values on success |
| `csar_sdk_backpressure_retries_total` | counter | route | Transparent upstream 429 retries |
| `csar_sdk_circuit_open_responses_total` | counter | route | Circuit-breaker 503 responses |
| `csar_sdk_client_limit_presence_total` | counter | route | Requests with X-CSAR-Client-Limit |

## Quick Start

### Prerequisites

- Go 1.25+
- (Optional) Redis for distributed rate limiting
- (Optional) PostgreSQL, MySQL, or SQLite for `csar-helper db` commands
- (Optional) Docker & Docker Compose for E2E tests
- (Optional) `protoc` + Go gRPC plugins for proto regeneration

### Build

```bash
make build-all          # builds csar, csar-coordinator, csar-helper, and mockapi
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

# Production with S3 token store (on-demand fetching) + HTTP config source:
./bin/csar-coordinator \
  --listen :9090 \
  --tls-cert /etc/csar/tls/server.pem \
  --tls-key /etc/csar/tls/server-key.pem \
  --client-ca /etc/csar/tls/client-ca.pem \
  --token-source s3 \
  --s3-bucket my-tokens-bucket \
  --s3-prefix tokens/ \
  --s3-auth-mode service_account \
  --s3-sa-key-file /etc/csar/sa-key.json \
  --config-source http \
  --config-url https://config-server.internal/routes.yaml \
  --config-http-bearer "${CONFIG_BEARER_TOKEN}" \
  --config-refresh-interval 60s
```

### Token Management with `csar-helper`

```bash
# 1. Generate config scaffolding for your deployment profile
csar-helper init --profile prod-single --output /etc/csar

# 2. Create the token database schema
csar-helper db init --dsn "postgres://user:pass@localhost/csar"

# 3. Migrate tokens from a YAML file into the database
csar-helper db migrate \
  --source yaml \
  --source-file tokens.yaml \
  --target-dsn "postgres://user:pass@localhost/csar" \
  --encrypt \
  --kms-provider local \
  --kms-key-id key-1 \
  --kms-local-keys "key-1=my-passphrase"

# 4. Encrypt a single token
echo "my-secret-token" | csar-helper token encrypt \
  --kms-provider local \
  --kms-key-id key-1 \
  --kms-local-keys "key-1=my-passphrase"

# 5. Validate config against its declared profile
csar-helper validate --config /etc/csar/config.yaml

# 6. Inspect resolved config (after includes + policy merges)
csar-helper inspect --config /etc/csar/config.yaml --route "GET /api/v1/products"

# 7. Simulate route matching
csar-helper simulate --config config.yaml --path /api/v1/users/42 --method GET
```

## Configuration

CSAR is configured via YAML files. See [`config.example.yaml`](config.example.yaml) for a fully annotated example.

> **IDE Support**: CSAR ships a JSON Schema (`csar.schema.json`) for YAML autocomplete and validation. Install the [YAML extension](https://marketplace.visualstudio.com/items?itemName=redhat.vscode-yaml) for VS Code, or use the `# yaml-language-server: $schema=./csar.schema.json` modeline in any editor with yaml-language-server support.

### Multi-File Configuration

Split your config across multiple files using the `include:` directive:

```yaml
include:
  - "routes/*.yaml"          # glob pattern
  - "policies/throttle.yaml" # specific file

listen_addr: ":8080"
paths:
  # ... routes defined here or in included files
```

**Include rules:**
- Paths are resolved relative to the directory of the file containing the `include:`
- Glob patterns are supported (deterministic sort order)
- Cycle detection prevents infinite loops
- Root-only fields (`listen_addr`, `tls`, `coordinator`, etc.) in included files are ignored with a warning
- Duplicate routes (same path + method) across files are rejected

### Top-Level Fields

| Field | Description |
|---|---|
| `include` | List of file paths or glob patterns to merge into this config |
| `profile` | Deployment profile: `"dev-local"`, `"prod-single"`, `"prod-distributed"` |
| `listen_addr` | HTTP(S) listen address (e.g. `":8080"`) |
| `tls` | Inbound TLS settings (`cert_file`, `key_file`, `client_ca_file`, `min_version`) |
| `access_control` | Global IP allowlist (`allow_cidrs`, `trust_proxy`) |
| `security_policy` | Environment-level security constraints (`environment`, `forbid_insecure_in_prod`, `redact_sensitive_logs`) |
| `ssrf_protection` | SSRF protection settings (block private/loopback/link-local/metadata IPs, `allowed_internal_hosts`) |
| `kms` | KMS provider settings (`provider`, `default_key_id`, `retry`, `cache`, `yandex`, `local_keys`) |
| `redis` | Redis connection for distributed rate limiting (`address`, `password`, `db`, `key_prefix`) |
| `coordinator` | Coordinator connection settings (see below) |
| `security_profiles` | Named reusable security configurations |
| `circuit_breakers` | Named circuit breaker profiles |
| `throttling_policies` | Named reusable throttling configurations |
| `cors_policies` | Named reusable CORS configurations |
| `retry_policies` | Named reusable retry configurations |
| `redact_policies` | Named reusable redaction configurations |
| `auth_validate_policies` | Named reusable auth validation configurations |
| `global_throttle` | Global rate limit safety net (`rate` or `requests` + `period`, `burst`, `max_wait`) |
| `paths` | Route definitions using OpenAPI-style `x-csar-*` extensions |

### Named Policies

Define reusable configurations at the top level, then reference them by name in routes. Six policy types are supported:

| Top-Level Key | Route Extension | Description |
|---|---|---|
| `security_profiles` | `x-csar-security` | Credential injection profiles |
| `throttling_policies` | `x-csar-traffic` | Rate limiting policies |
| `cors_policies` | `x-csar-cors` | CORS policies |
| `retry_policies` | `x-csar-retry` | Retry policies |
| `redact_policies` | `x-csar-redact` | DLP redaction policies |
| `auth_validate_policies` | `x-csar-authn-validate` | JWT, session, personal-key or credential-selected authentication policies |

**Reference syntax** (all policy types support the same patterns):

```yaml
# 1. Bare string reference
x-csar-traffic: "standard-api"

# 2. Object with policy reference + inline overrides
x-csar-traffic:
  use: "standard-api"
  max_wait: "5s"          # override one field from the policy

# 3. Inline object (no policy reference)
x-csar-traffic:
  rps: 10
  burst: 20
  max_wait: "500ms"
```

`x-csar-security` additionally supports arrays for multi-credential injection:

```yaml
x-csar-security:
  - "upstream_bearer"                       # profile reference
  - kms_key_id: "key-2"                    # inline credential
    token_ref: "client_secret"
    inject_header: "X-Client-Secret"
    inject_format: "{token}"
```

### Shared user and service authentication

A route can use `mode: select` to accept a browser session, personal API key or
service STS token through the same endpoint. Each method reuses its existing
validator; authorization remains a separate `x-csar-authz` permission check.

```yaml
auth_validate_policies:
  browser:
    mode: session
    session_endpoint: https://auth.example.com/auth/validate
    cookie_name: csar_session
    forward_headers: [X-Gateway-Subject]
  personal-key:
    mode: token
    introspection_endpoint: https://auth.example.com/auth/token/introspect
    introspection_tls: authn-mtls # configured backend_tls_policies entry
    required_scope: adverts:read
    seller_path_param: seller_id
  service:
    mode: jwt
    jwks_url: https://auth.example.com/.well-known/jwks.json
    issuer: https://auth.example.com
    audiences: [owner-read]
    forward_claims: {sub: X-Gateway-Subject}
  owner-read:
    mode: select
    methods: [browser, personal-key, service]
```

Reference `owner-read` from `x-csar-authn-validate`. Configure **2–3 terminal
methods with distinct credential locations**: a named cookie, `Authorization`
for personal keys, and `X-Csar-Authorization` by default for JWTs. Policy names
or inline objects are accepted. Selectors cannot nest, carry validator options
on their parent, or issue session route tokens.

Exactly one credential must be presented. Duplicate headers/cookies, conflicting
credential types, unsupported authorization headers and missing credentials are
rejected. An invalid, expired or unavailable credential never triggers fallback
to another identity. After success, credential headers and cookies are removed
before authorization and upstream dispatch. Existing single-mode policies keep
their behavior. Service authentication alone does not grant seller access.

Upgrade router and coordinator binaries before enabling selector policies:
coordinator snapshots carry the method list, and older readers reject the new
mode. JWT audience lists accept any configured audience after signature, issuer
and expiry validation; an accepted audience is not an authorization grant.

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
        path_rewrite: "/products/$1"                # regex back-references
        path_mode: "replace"                        # "replace" (default) or "append"
        health_check:
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

      x-csar-authn-validate:
        jwks_url: "https://auth.example.com/.well-known/jwks.json"
        issuer: "https://auth.example.com/"
        audiences: ["my-api"]
        required_claims:
          role: "admin"
        forward_claims:
          sub: "X-User-ID"
        cookie_name: "session_jwt"              # read JWT from cookie instead of header

      x-csar-traffic:
        rps: 5.0
        burst: 10
        max_wait: "30s"
        backend: "local"                        # "local", "redis", or "coordinator"
        key: "seller:{query.seller_id}"         # per-entity rate limiting ({query.*}, {header.*}, {path.*})
        vip_overrides:                          # header-based policy switching
          - header: "X-API-Key"
            values:
              "vip-key-123": "vip-unlimited"

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

      x-csar-tenant:
        header: "X-Tenant-ID"
        backends:
          acme: "https://api-acme.internal"
          globex: "https://api-globex.internal"
        default: "https://api-default.internal"

      max_response_size: 10485760               # 10MB — prevents DLP/retry buffer DoS
```

Read-only POST routes can opt into response caching through a named policy.
The body is always part of a POST cache key. CSAR hashes the exact bytes with
SHA-256 and includes the escaped request path, Content-Type and Content-Encoding alongside configured
identity, query, header and namespace dimensions. Whitespace, field order and
array order remain significant. Configure the key with every caller and seller
dimension that can change the response. Authenticated POST policies require
`{subject}` or `{tenant}` in the key itself.

```yaml
cache_policies:
  stocks-read:
    store: redis
    methods: [POST]
    key: "stocks:{subject}:{path.seller_id}"
    key_query: {sort: true}
    max_request_body_size: 65536
    ttl: 30s
    content_types: [application/json]

# On a read-only POST route with a seller_id path parameter
# x-csar-cache: stocks-read
# Or override the policy's request limit on this route
# x-csar-cache:
#   use: stocks-read
#   max_request_body_size: 131072
```

`max_request_body_size` bounds request buffering and defaults to 64 KiB when
omitted or zero. It is a scalar in named policies, so a nonzero inline value
overrides the policy. Larger bodies and requests with trailers bypass caching
with their bodies intact. A request-body read failure returns HTTP 400 before
proxying. `max_body_size` continues to control response admission. Stale POST
refreshes replay an independent body reader, retain request context values and
run for at most 60 seconds, bounded further by the original request deadline.

Upgrade every serving router and coordinator before enabling POST caching or
publishing its request limit. Existing routers accept POST method lists but
compute keys without the body, and older protobuf readers ignore the new field.
Disable existing POST caching during a mixed-version rollout and before rolling
back to older routers.

### Route Matching Precedence

A request is served by exactly one route, chosen the same way on every router and after every reload:

1. **Exact path**: a path without `{...}` that equals the request path.
2. **Path templates**: paths with `{var}` or `{var:regex}`, tried from the most precise to the widest. Two templates are compared segment by segment from the left; at the first segment where they differ, the more precise one wins:
   1. a literal segment (`list`);
   2. literal text mixed with variables (`v{version}`, `{id}.json`);
   3. a regex-constrained variable (`{id:[0-9]+}`, `{report:list/goods|quarantine/goods}`);
   4. a plain variable (`{id}`);
   5. a variable whose regex can span segments (`{rest:.*}`).

   Ties go to the template with more segments, then more literal characters, then the template text.
3. **Longest prefix**: the longest path without `{...}` that is a prefix of the request path on a `/` boundary.

So `/svc/wb/{marketplace}/{external_id}/finance/api/finance/v1/sales-reports/list` always wins over `/svc/wb/{marketplace}/{external_id}/finance/{rest:.*}` for that request, and the wide route serves the rest of `finance/`. `csar-helper simulate` uses the same order.

### KMS Configuration

```yaml
kms:
  provider: "yandexapi"                         # "local" for dev, "yandexapi" for production
  default_key_id: "abj-xxx"
  operation_timeout: "2s"
  retry:
    max_attempts: 3
    base_delay: "100ms"
    max_delay: "2s"
    jitter: true
  cache:
    enabled: true
    ttl: "60s"
    max_entries: 10000
  yandex:
    auth_mode: "service_account"                # "metadata", "iam_token", "oauth_token", "service_account"
    sa_key_file: "/etc/csar/sa-key.json"        # recommended for VMs outside Yandex Cloud
  # local_keys:                                 # for provider: "local" (dev only)
  #   key1: "passphrase1"
```

### Readable rate configuration

Named `throttling_policies`, `global_throttle`, and inline `x-csar-traffic`
accept an integer request count and a positive duration:

```yaml
throttling_policies:
  finance:
    requests: 1
    period: 1m
    burst: 1
  prices:
    requests: 10
    period: 6s
    burst: 5
paths:
  /report:
    get:
      x-csar-backend: {target_url: "https://example.com/report"}
      x-csar-traffic: finance
```

`requests / period` sets the replenishment rate. `burst` controls the initial
capacity independently; this is pacing, not a fixed calendar window. Redis GCRA
rounds each emission interval up to whole milliseconds (3 requests/second means
334 ms between replenishments); local token buckets use the normalized RPS.

The existing `rate` field on policies/global limits and `rps` on inline traffic
remain supported. Set either the legacy field or both `requests` and `period`.
Mixed forms, incomplete pairs, non-positive counts/durations and fractional
counts are rejected. Inline overrides replace the policy rate as a complete
pair, e.g. `{use: finance, requests: 3, period: 1m}`. A legacy `rps` override
also works on a period-based policy, and a pair can override a legacy policy.

Resolution converts authoring units into the existing RPS fields. Compiled YAML
and coordinator snapshots retain the legacy wire representation; no protobuf
upgrade is needed. Upgrade tools, coordinators and routers that load authored
YAML before publishing the new syntax: older parsers ignore unknown fields.
Upgrade routers to receive the Redis interval rounding fix as well.

### Backpressure defaults in throttle policies

Put `adaptive_backpressure` in a named `throttling_policies` entry to share
`enabled`, `respect_headers`, `suspend_bucket` and `max_body_buffer` settings.
Routes can then use just `x-csar-traffic: {use: finance}`. A route inherits the
whole block when omitted; an explicit route block replaces it completely,
including `{enabled: false}` to disable backpressure. `client_limit_mode` also
inherits unless the route specifies a value such as `ignore`.

Resolved routes carry these settings through compilation and the existing
coordinator route protocol. Backpressure does not enable retries: configure
`max_attempts: 1`, `auto_retry_429: false` and
`x-csar-protocol: {transparent_retry: false}` to keep replay disabled.

### Global Throttle

```yaml
global_throttle:
  rate: 1000            # global RPS limit across all routes
  burst: 2000
  max_wait: "0s"        # "0s" = reject immediately when exceeded
```

### Environment Variable Expansion

String values in config support `${VAR}` and `$VAR` expansion:

```yaml
kms:
  yandex:
    oauth_token: "${YANDEX_OAUTH_TOKEN}"
redis:
  password: "$REDIS_PASSWORD"
```

Expansion happens post-YAML-parse, so values containing YAML control characters are safe. Bare numeric references (`$1`, `$2`) are preserved for `path_rewrite` regex back-references.

### Rate Limiting Backends

| Backend | Description |
|---|---|
| `local` (default) | In-memory token bucket per pod. Fast, zero dependencies. |
| `redis` | Distributed GCRA via Redis. Globally coordinated limits across all pods. Requires top-level `redis` config. |
| `coordinator` | Local token bucket with quotas dynamically assigned by the coordinator. Quotas are redistributed as routers join/leave the fleet. |

### Coordinator Settings

```yaml
coordinator:
  enabled: true
  address: "coordinator.internal:9090"
  discovery_method: "static"                    # "static", "dns", "consul", "kubernetes"
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
- Rebuilds the router from **full config snapshots**, skipping a snapshot identical to the one already applied (a reconnect replays the current snapshot)

The coordinator pings each router connection after `--grpc-keepalive-time` of silence, so a proxy with an idle timeout (the prod HAProxy closes connections idle for 2 minutes) does not cut healthy streams. If the stream does drop, the router retries after 1 s, doubling up to 60 s while the coordinator stays unreachable; the delay starts over once a stream delivers a message.

## CLI Flags

### `csar` (Router)

| Flag | Default | Description |
|---|---|---|
| `-config` | `config.example.yaml` | Path to config file |
| `-health-addr` | `:9100` | Plain HTTP health/readiness/metrics sidecar address (empty to disable) |
| `-otlp-endpoint` | *(empty)* | OTLP gRPC endpoint for tracing |
| `-otlp-insecure` | `false` | Allow insecure OTLP connection |
| `-kms-provider` | *(empty)* | KMS provider: `"local"` or `"yandexapi"` |
| `-kms-local-keys` | *(empty)* | Local KMS keys: `"keyID=passphrase,..."` |
| `-kms-cache-ttl` | `0` | KMS decrypt cache TTL (e.g. `"60s"`, `0` to disable) |
| `-token-file` | *(empty)* | YAML file with plaintext tokens (local dev) |
| `-yandex-kms-endpoint` | *(empty)* | Yandex Cloud KMS API endpoint |
| `-yandex-auth-mode` | `metadata` | Yandex auth mode: `iam_token`, `oauth_token`, `metadata` |
| `-yandex-iam-token` | *(empty)* | Static IAM token for Yandex KMS (dev only) |
| `-yandex-oauth-token` | *(empty)* | OAuth token for IAM token exchange |
| `-yandex-sa-key-file` | *(empty)* | Service account key file for Yandex KMS |

### `csar-coordinator`

#### Core flags

| Flag | Default | Description |
|---|---|---|
| `--listen` | `:9090` | gRPC listen address |
| `--tls-cert` | *(empty)* | Server TLS certificate |
| `--tls-key` | *(empty)* | Server TLS private key |
| `--client-ca` | *(empty)* | Client CA for mTLS |
| `--allowed-routers` | *(empty)* | Comma-separated CN/SAN allowlist |
| `--allow-insecure-dev` | `false` | Allow running without TLS (dev only) |
| `--grpc-keepalive-time` | `30s` | Ping a connection after this long without activity, so router streams stay open through idle-closing proxies |
| `--grpc-keepalive-timeout` | `10s` | Close a connection whose ping is not acknowledged in time; a silently dead router is unregistered and leaves the quota split |
| `--snapshot-debounce` | `1s` | Wait until route changes have been quiet this long, then push one config snapshot (`0` pushes one per change) |

#### Token source (choose one)

| Flag | Default | Description |
|---|---|---|
| `--token-file` | *(empty)* | YAML file with pre-encrypted token entries (`file` source) |
| `--token-source` | *(auto-detect)* | Explicit backend: `file`, `postgres`, `s3` |

#### PostgreSQL token source (`--token-source=postgres`)

| Flag | Default | Description |
|---|---|---|
| `--postgres-dsn` | *(required)* | PostgreSQL connection string |
| `--postgres-max-conns` | `10` | Max open DB connections |
| `--postgres-refresh-interval` | `30s` | Polling interval for token changes |

#### S3 token source (`--token-source=s3`)

Tokens are fetched **on-demand** — no `ListObjects` calls are made at startup or during operation. Each token is fetched individually the first time it is requested.

| Flag | Default | Description |
|---|---|---|
| `--s3-bucket` | *(required)* | S3 bucket name |
| `--s3-endpoint` | `https://storage.yandexcloud.net` | S3-compatible endpoint |
| `--s3-region` | `ru-central1` | S3 region for signing |
| `--s3-prefix` | `tokens/` | Key prefix for token objects |
| `--s3-auth-mode` | `static` | Auth: `static`, `iam_token`, `oauth_token`, `metadata`, `service_account` |
| `--s3-access-key-id` | *(empty)* | Access key ID (static auth) |
| `--s3-secret-access-key` | *(empty)* | Secret access key (static auth) |
| `--s3-iam-token` | *(empty)* | Static IAM token (iam_token auth) |
| `--s3-oauth-token` | *(empty)* | OAuth token for IAM exchange (oauth_token auth) |
| `--s3-sa-key-file` | *(empty)* | Service account key JSON file (service_account auth) |
| `--s3-kms-mode` | `kms` | Token encryption mode: `kms` (CSAR KMS) or `passthrough` (SSE-only) |

#### State store

| Flag | Default | Description |
|---|---|---|
| `--store` | `memory` | State store backend: `memory`, `etcd` |
| `--etcd-endpoints` | `localhost:2379` | Comma-separated etcd endpoints |
| `--etcd-prefix` | `/csar` | etcd key prefix |
| `--etcd-router-ttl` | `30` | etcd lease TTL (seconds) for router entries |

#### Config source (`--config-source`)

The coordinator can load route configuration from an external source and push it into the state store, polling for changes at a configurable interval. Supports three backends: `file`, `s3`, `http`.

| Flag | Default | Description |
|---|---|---|
| `--config-source` | *(empty)* | Source backend: `file`, `s3`, `http` (empty = disabled) |
| `--config-refresh-interval` | `60s` | Polling interval |
| `--config-sha256` | *(empty)* | Pin expected SHA-256 hash (hex); empty = TOFU mode |

**`--config-source=file`**

| Flag | Default | Description |
|---|---|---|
| `--config-file` | *(required)* | Path to YAML config file |

**`--config-source=http`**

| Flag | Default | Description |
|---|---|---|
| `--config-url` | *(required)* | URL to fetch config from |
| `--config-http-header` | *(empty)* | Extra headers: `key=value,key2=value2` |
| `--config-http-bearer` | *(empty)* | Bearer token for `Authorization` header |

**`--config-source=s3`**

| Flag | Default | Description |
|---|---|---|
| `--config-s3-bucket` | *(required)* | S3 bucket for config |
| `--config-s3-key` | `config.yaml` | S3 object key |
| `--config-s3-endpoint` | `https://storage.yandexcloud.net` | S3 endpoint |
| `--config-s3-region` | `ru-central1` | S3 region |
| `--config-s3-auth-mode` | `static` | Auth mode (same values as token S3 source) |
| `--config-s3-access-key-id` | *(empty)* | Access key ID (static auth) |
| `--config-s3-secret-access-key` | *(empty)* | Secret access key (static auth) |
| `--config-s3-iam-token` | *(empty)* | Static IAM token (iam_token auth) |
| `--config-s3-oauth-token` | *(empty)* | OAuth token for IAM exchange |
| `--config-s3-sa-key-file` | *(empty)* | Service account key JSON file |

##### Config source integrity

The watcher validates every fetched config against a SHA-256 hash using one of two policies:

| Policy | Behaviour |
|---|---|
| **TOFU** (default) | Trusts the first fetch, then detects unexpected content changes when the ETag is unchanged — catches silent content replacement / tampering. |
| **Pinned** (`--config-sha256`) | Validates every fetch against the operator-provided hash; rejects any mismatch. |

On any partial store failure during diff application the ETag is invalidated, forcing a full re-fetch and re-apply on the next poll rather than silently leaving the state store in a half-applied state.

### `csar-helper`

#### `csar-helper init`

| Flag | Default | Description |
|---|---|---|
| `--profile` | *(required)* | Deployment profile: `dev-local`, `prod-single`, `prod-distributed` |
| `--output` | `.` | Output directory for generated files |
| `--force` | `false` | Overwrite existing files (default: fail if file exists) |

#### `csar-helper validate`

| Flag | Default | Description |
|---|---|---|
| `--config` | `config.yaml` | Path to config file to validate |

#### `csar-helper inspect`

Shows the fully resolved config after all includes and policy merges, with source file/line tracing.

| Flag | Default | Description |
|---|---|---|
| `--config` | `config.yaml` | Path to config file |
| `--route` | *(empty)* | Filter to a single route: `"METHOD /path"` |
| `--format` | `yaml` | Output format: `yaml` or `json` |

Values are expanded from the local environment and secrets are omitted, so the output is for reading, not for publishing.

#### `csar-helper compile`

Validates the config, merges all includes and resolves named policies into one YAML document for S3, HTTP or manifest config sources. `${VAR}` references, including secret fields, are kept as written, so every router expands them from its own environment when it loads the document.

| Flag | Default | Description |
|---|---|---|
| `--config` | `config.yaml` | Path to config file |

#### `csar-helper simulate`

Dry-runs route matching against your config without network requests.

| Flag | Default | Description |
|---|---|---|
| `--config` | `config.yaml` | Path to CSAR config file |
| `--path` | *(required)* | Request path to simulate |
| `--method` | `GET` | HTTP method |

#### `csar-helper bench`

Built-in HTTP benchmark with live TUI showing P50/P95/P99 latencies.

| Flag | Default | Description |
|---|---|---|
| `--url` | *(required)* | Target URL |
| `--method` | `GET` | HTTP method |
| `--concurrency` | `10` | Number of concurrent workers |
| `--duration` | `10s` | Benchmark duration |
| `--header` | *(empty)* | Repeatable HTTP header in `"Key: Value"` format |

#### `csar-helper dev-jwks`

Starts a local JWKS server for JWT validation testing.

| Flag | Default | Description |
|---|---|---|
| `--pub-key` | *(empty)* | Path to PEM-encoded public key |
| `--jwks-file` | *(empty)* | Path to existing jwks.json file |
| `--addr` | `:8080` | Listen address for the JWKS server |

#### `csar-helper keys`

Cryptographic key generation and conversion.

| Subcommand | Description |
|---|---|
| `keys generate` | Generate a signing key pair (`--algorithm ed25519\|rsa`, `--output`, `--name`) |
| `keys to-jwks` | Convert a public key to JWKS format (`--pub-key`, `--output`) |
| `keys to-env` | Export keys as base64 environment variables (`--priv-key`, `--pub-key`) |
| `keys issue-token` | Issue a signed JWT (`--priv-key`, `--sub`, `--iss`, `--aud`, `--ttl`, `--claim key=value`) |

#### `csar-helper db init`

| Flag | Default | Description |
|---|---|---|
| `--dsn` | *(required)* | Target database DSN (e.g. `postgres://user:pass@host/db`) |
| `--table` | `csar_tokens` | Table name for tokens |
| `--if-not-exists` | `true` | Use `IF NOT EXISTS` in `CREATE TABLE` |
| `--state-store` | `false` | Also create state store tables (`csar_routers`, `csar_quotas`) |

#### `csar-helper db migrate`

| Flag | Default | Description |
|---|---|---|
| `--source` | *(required)* | Source type: `sql`, `yaml`, `json`, `env`, `vault`, `http` |
| `--target-dsn` | *(required)* | Target database DSN |
| `--table` | `csar_tokens` | Target table name |
| `--encrypt` | `false` | Encrypt plaintext tokens before inserting |
| `--kms-provider` | `local` | KMS provider: `local` or `yandexapi` |
| `--kms-key-id` | *(empty)* | KMS key ID for encryption |
| `--kms-local-keys` | *(empty)* | Local KMS keys (`keyID=passphrase,...`) |
| `--dry-run` | `false` | Show what would be migrated without writing |
| `--upsert` | `true` | Update existing tokens (false = skip/error) |
| `--source-dsn` | *(empty)* | SQL source DSN (for `--source=sql`) |
| `--source-query` | *(empty)* | Custom SQL query for source |
| `--source-file` | *(empty)* | Path to YAML/JSON file (for `--source=yaml`/`json`) |
| `--env-prefix` | *(empty)* | Environment variable prefix (for `--source=env`) |
| `--vault-addr` | *(empty)* | Vault address (for `--source=vault`) |
| `--vault-token` | *(empty)* | Vault authentication token |
| `--vault-path` | *(empty)* | Vault secret path |
| `--http-url` | *(empty)* | HTTP API URL (for `--source=http`) |
| `--http-header` | *(empty)* | Repeatable HTTP header in `"Key: Value"` format |
| `--jq` | *(empty)* | Dot-separated path to extract tokens from JSON response |

#### `csar-helper token encrypt`

| Flag | Default | Description |
|---|---|---|
| `--plaintext` | *(stdin)* | Plaintext token to encrypt (reads from stdin if omitted) |
| `--kms-provider` | `local` | KMS provider: `local` or `yandexapi` |
| `--kms-key-id` | *(required)* | KMS key ID |
| `--kms-local-keys` | *(empty)* | Local KMS keys (`keyID=passphrase,...`) |
| `--yandex-kms-endpoint` | *(empty)* | Yandex Cloud KMS API endpoint |
| `--yandex-auth-mode` | `metadata` | Yandex auth mode |

Outputs the encrypted ciphertext as a base64-encoded string.

## Deployment Profiles

CSAR supports three deployment profiles that enforce security and operational constraints at startup. Set via `profile:` in config:

| Profile | Use Case | Key Constraints |
|---|---|---|
| `dev-local` | Local development | No restrictions; allows `allow_insecure`, local KMS, dev environment. |
| `prod-single` | Single-node production | Rejects `allow_insecure` coordinator, `dev` environment, local KMS with secure routes; requires TLS. |
| `prod-distributed` | Multi-node production | All `prod-single` rules plus: requires coordinator enabled with valid address and CA file. |

### Profile Enforcement

Profile rules are enforced at two points:

1. **Config validation** (`Config.Validate()`) — checks the YAML-declared settings against the profile constraints at startup.
2. **Runtime KMS validation** (`ValidateResolvedKMSProvider()`) — checks the *actually resolved* KMS provider (CLI flag → config fallback) against profile rules. This prevents bypassing prod security by passing `--kms-provider=local` on the command line while the config declares a prod profile.

### Scaffolding

Generate profile-specific config templates with:

```bash
# Generate dev-local scaffolding
csar-helper init --profile dev-local --output ./my-config

# Generate prod-single scaffolding (fails if files exist; use --force to overwrite)
csar-helper init --profile prod-single --output /etc/csar --force
```

## Live Reload (SIGHUP)

Send SIGHUP to reload configuration without dropping active connections:

```bash
kill -HUP $(pidof csar)
```

**What survives a reload:**
- Throttle state (token buckets, counters) — existing rate limits continue
- Coordinator connection and quota assignments
- Active health checks are gracefully stopped and restarted

**What changes take effect:**
- Routes (paths, methods, backend targets)
- Circuit breaker profiles
- Named policies (throttling, CORS, retry, redact, auth-validate, security)
- Access control rules
- SSRF blocking switches and the exact `allowed_internal_hosts` allowlist
- Redis `key_prefix` for throttling and response caching
- Global throttle settings, including removal of the entire block

SSRF policy is rebuilt with each router, including coordinator snapshots and
periodic source refreshes. Removing a host revokes it for new requests; requests
already using the previous router may finish. Removing the YAML block restores
secure defaults (all four IP classes blocked, empty allowlist).

Coordinator `FullConfigSnapshot.ssrf_protection` (field 18) carries this policy.
Policy-only publishes also notify connected routers without requiring route
changes. With a source config loaded, snapshots and quotas use its last successful
complete apply; partial route-store writes are not published. Without a source
config, coordinator snapshots continue to read the route store. Routes are sorted
before serialization so reconnects do not rebuild identical configurations merely
because map iteration order changed. Upgrade routers first, then coordinators
before relying on this behavior.
Old routers ignore the new field. New routers retain their last applied SSRF
policy and log a warning when an old coordinator omits it; complete YAML reloads
still apply locally. Reverting to an older binary restores its startup-only SSRF
behavior, so restart routers against the intended configuration when rolling back.

`FullConfigSnapshot.redis_key_prefix` (optional field 19) carries only the Redis
namespace, without connection credentials. A legacy snapshot omitting the field
retains the last successfully applied prefix. An explicit empty prefix, or a
complete YAML reload omitting `redis`, restores the built-in throttle/cache
prefixes. Changing a prefix selects another Redis namespace; existing keys stay
in the previous one until their normal expiry. Upgrade all routers and then
coordinators before relying on prefix updates.

The global limiter belongs to each router instance. Removing `global_throttle`
disables it for new requests; an unsuccessful rebuild cannot replace the active
global limiter. Requests already executing the previous router retain its limiter.
As before, a successful rebuild creates a fresh global token bucket.
Per-route throttle registrations are staged until the complete router build
succeeds, preserving live quota updates when a later route fails validation.

Startup settings require a process restart: `listen_addr`, inbound `tls`,
`profile`, `security_policy`, `kms`, `coordinator`, Redis connection settings
(`address`, `password`, `db`), `readiness`, `authz`, and audit connection settings.
Full YAML reloads warn against the router's startup snapshot. Coordinator
publishes warn when these fields change from the previous successfully applied
config, including fields that are intentionally absent from gRPC snapshots.
Warnings contain only field names, never previous/new values, credentials or
key-map entries. Hot `redis.key_prefix` and `audit.capture` changes do not require
restart warnings; audit capture defaults are compiled into routes.

## Testing

```bash
make test              # all tests (unit + integration)
make test-unit         # unit tests only
make test-integration  # integration tests only
make test-race         # all tests with race detector
make test-e2e          # Docker-based end-to-end tests
make lint-strict      # quality and security linters
make lint-security    # standalone gosec; writes gosec-report.json
```

The standalone security scan excludes generated protobuf code. Reviewed source
exceptions use rule-specific `#nosec` comments with a reason; HTTP timeout checks
remain enabled. Config/scaffold output and private keys are written with owner-only
permissions, including overwrites. Generated PostgreSQL Compose services require
`POSTGRES_PASSWORD` instead of supplying a known default. Install certificates
and configure the generated profile's upstream before starting it. Scaffold
generation checks every destination before writing and creates files exclusively
unless force was requested. The scaffold library does not write progress to
stdout, preserving the MCP server's stdio protocol.

### Test Coverage

| Package | What's Tested |
|---|---|
| `internal/config` | YAML parsing, validation (TLS, security, coordinator, access control, health check, CORS, cache, traffic backend), profile enforcement, runtime KMS provider validation, multi-file includes, named policy resolution |
| `internal/configsource` | Watcher diff + apply cycle, partial-apply ETag invalidation, Apply mutex serialisation, TOFU + pinned hash policies, file/HTTP/S3 source adapters |
| `internal/router` | Route matching, prefix boundary, IP allowlisting, `trust_proxy` isolation, fail-closed auth, streaming bypass, load balancing, CORS integration |
| `internal/coordinator` | AuthService (token CRUD, gRPC errors), coordinator subscribe/health, S3 on-demand token fetching |
| `internal/kms` | Encrypt/decrypt, cache (SHA-256 keys), local provider, Yandex Cloud KMS |
| `internal/throttle` | Token bucket, burst, max wait timeout, quota updates |
| `internal/resilience` | Circuit breaker state transitions |
| `internal/proxy` | Reverse proxy forwarding, header handling, SSRF protection |
| `pkg/middleware` | Auth injection, file fetcher, coordinator fetcher |
| `tests/integration` | Full pipeline: proxy, throttle, circuit breaker, auth injection, coordinator gRPC E2E |
| `internal/helper` | Token sources (YAML, SQL, env, Vault, HTTP), dialect detection, migration, encryption, profile validation |
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
  csar-helper/            Helper CLI (init, validate, inspect, simulate, bench, keys, db, dev-jwks)
  mockapi/                Test upstream server
internal/
  authn/                  JWT/JWKS validation + cookie auth
  cache/                  Response caching middleware
  config/                 YAML config loading, multi-file includes, policy resolution, validation
  configsource/           Pluggable config sources for coordinator (file, S3, HTTP) with SHA-256 integrity
  coordclient/            Coordinator subscription client (quota + token invalidation)
  coordinator/            gRPC coordinator + AuthService + token store backends (PostgreSQL, S3, file)
  cors/                   CORS middleware
  dlp/                    Data Loss Prevention (response redaction)
  helper/                 csar-helper logic (migration, encryption, profiles, token sources)
  kms/                    KMS provider interface + implementations (local, Yandex Cloud)
  loadbalancer/           Upstream pool load balancing + health checking
  logging/                Structured logging + secret redaction
  metrics/                Prometheus instrumentation
  proxy/                  HTTP reverse proxy + SSRF protection
  resilience/             Circuit breaker
  retry/                  Retry middleware with backoff
  router/                 Core HTTP router (matching, pipeline, IP ACL)
  s3store/                S3-compatible object storage client (static + IAM auth, on-demand fetching)
  statestore/             Pluggable state store (memory, etcd, PostgreSQL placeholder)
  telemetry/              OpenTelemetry tracing
  tenant/                 Multi-tenant routing
  throttle/               Token-bucket rate limiter + Redis distributed limiter
  ycloud/                 Yandex Cloud IAM token resolver (singleflight refresh, multiple auth modes)
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
- **Profile enforcement**: deployment profiles (`dev-local`, `prod-single`, `prod-distributed`) enforce security constraints at config validation time. The runtime-resolved KMS provider is also validated against the active profile, preventing local KMS bypass via CLI flags in production.
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

## Audit error response diagnostics

A route's existing `x-csar-audit` mode decides whether it emits an event.
Every audited route attempts sanitized error-response diagnostics by default,
including `errors`, `all`/`true` and the existing method-based audit default.
No `x-csar-audit-capture` block is required:

```yaml
paths:
  /example:
    get:
      x-csar-audit: errors
      x-csar-backend:
        target_url: https://example.com
```

`errors` emits only final HTTP errors, with safe diagnostics. `all` also emits
successful events, but never captures successful response bodies. Neither mode
implicitly enables request-body or query capture. `x-csar-audit: false`/`off`
still excludes the route entirely. To retain error events without response
inspection, set `x-csar-audit-capture: {response: off}` on the route (or use an
existing named capture policy with `response: off`).

`response` accepts `off` or `errors`; an unspecified mode defaults to `errors`
at runtime on audited routes. `response_max_bytes` accepts 0–4096 bytes;
0 selects the 4096-byte default. Explicit policy/route/global capture defaults
are resolved before coordinator distribution, including hot reload. Invalid
global and unused named response policies fail config loading. Global capture
defaults retain their existing scope: routes with an audit-capture block.

For a final HTTP status of at least 400, the matched-route audit wrapper observes
the final response sent to the caller, including local authentication, security,
throttle and open-circuit refusals. Retries produce one final event; a successful
retry stores no error response. Unmatched URLs, CORS preflights and audit-off
routes retain their prior exclusion. Client bytes and status are forwarded
without buffering the whole response or changing the response body.

`metadata.http_response` is a version-1 diagnostic envelope defined in
`csar-core/audit`: status, origin/stage, elapsed milliseconds, observed byte count,
capture state/reason and optional code, message and sanitized body. At most
64 KiB is inspected. Only complete, uncompressed JSON error envelopes are kept,
and only allowlisted diagnostic fields survive. Built-in sensitive-field and
reflected-credential redaction always applies, even without a request redaction
policy; route redaction rules add protection. The stored body is limited to
4096 UTF-8 bytes, and the entire event metadata stays within the existing 16 KiB
budget. Invalid/oversized JSON, unsupported encodings/content types and streaming
or hijacked responses get an omission reason instead of a raw prefix. A truncated
sanitized body is a string, not a malformed JSON object.

The captured body is the final client response after response shaping, rather
than the original upstream payload. Origin is `router` for local refusals and
trusted proxy transport failures (`stage: upstream_transport`, meaning no
upstream HTTP response was received); otherwise it remains `unknown`. Upstream
response headers cannot assert this origin. Audit identity comes from validated
gateway headers; early denials stay anonymous, and `actor_email` is accepted only
from a configured validator's forwarded email field. Incoming email headers alone
cannot assert an audit identity.

Release the matching helper and coordinator/router readers before publishing
configs with `response` fields. Existing audit ingest/storage transports preserve
the additive metadata without a schema migration. Disabling response capture
stops further collection while old events remain readable.

## Stored token freshness

Coordinators validate a stored credential on the first request after
`--stored-token-refresh-interval` (default `1m`, must be positive). Each ref is
checked independently; idle tenants cause no reads and S3 mode performs no
listing or periodic token scan. Concurrent checks for the same ref share one
bounded backend fetch. A changed credential is returned to the triggering
request immediately. A missing/invalid credential is not served from the old
cache; a backend outage fails closed with a five-second validation retry delay.
Local rotation/deletion wins over a backend read started earlier. Minted tokens
retain their separate soft refresh and hard expiry behavior.

## Delegated access for service routes

Configure three named authentication policies with a versioned HTTPS introspection endpoint, verified client TLS, one entry in `audiences`, and a `required_scope`. The issuer implements the JSON request and result in `csar-core/authntokens`.

| Mode | Inbound bearer header | Upstream receives |
| --- | --- | --- |
| `grant-exchange` | Authorization | Verified identity and a fresh proof in Authorization over backend mTLS |
| `grant-discovery` | X-Csar-Authorization | Verified subject and grant ID for the configured catalog owner |
| `grant-resource` | X-Csar-Authorization | Verified identity and canonical tenant after checking the matched resource |

For example, a documents service can configure `audiences: ["https://documents.example"]`, `required_scope: documents:read`, and `resource_path_param: project_id` on `/projects/{project_id}/files`. Set the route Authz policy to the required action and tenant. A platform-scoped policy can authorize a resource without a tenant. The issuer independently checks the credential, audience, purpose, scope and requested resource. It issues and consumes short-lived one-time proofs. The gateway checks the returned bindings on each request. Discovery and resource routes consume the credential before proxying. Exchange and discovery routes always reach the backend, so the catalog owner can evaluate current access on each call. Response caching is available on authorized resource routes.

Install compatible routers, coordinators and an issuer before distributing the new modes. Existing seller routes continue to use their original protocol until migrated.

Signed-origin forwarding is opt-in per route with `x-csar-origin-receiver:
"svc:reports"` (the backend service principal, independently of the access-token
audience). It requires a router-local root issuer, verified HTTPS/mTLS backend,
authentication and tenant authorization. Receiver policies survive route-store
JSON and coordinator snapshots, including explicit removal. New routers advertise
`csar.origin_policy_version=1`; coordinators refuse enabled receiver policies for
unsupported subscribers. A router with active policies rejects legacy snapshots
and retains its last successful configuration. Upgrade the entire router fleet
and coordinator before distributing policies; disconnected older routers can
still serve their previous configuration. No production routes are enabled here.

The router constructs a shared root client only when the local `origin_issuer`
startup block is present. Example (paths reference mounted files):

```yaml
origin_issuer:
  endpoint: https://authn-router/internal/origin-context/root
  issuer: https://id.example
  jwks_url: https://authn-router/.well-known/jwks.json
  tls:
    ca_file: /etc/csar/authn-ca.pem
    cert_file: /etc/csar/root-client.pem
    key_file: /etc/csar/root-client-key.pem
```

Both URLs require verified HTTPS; the root ingress must trust only the dedicated
router identity. Core bounds root issuance and JWKS verification to the source
deadline and five seconds, with no redirects or automatic root retries. The
client and JWKS cache survive SIGHUP, source-watcher and coordinator rebuilds.
Issuer URLs, expected issuer and TLS settings require a process restart; reload
reports changed field names and keeps the startup client. Coordinator snapshots
carry receiver policies, never these local issuer settings. This adds source
support only; issuer ingress, trust roots and production rollout remain separate.

Protected read routes can opt into `x-csar-audit-release: true` together with
`x-csar-audit: all`, authentication and authorization. Before cache or backend
dispatch the router waits at most one second (also bounded by request/transport
timeouts) for synchronous ingest acceptance, which upgraded audit instances issue
only after persistent broker confirmation. A failed or uncertain receipt returns
retryable `503 audit_unavailable`; HIT requires its own current-caller receipt.
Streaming requests are unsupported under this policy.

The compact `read.release_authorized` event records permission to attempt release,
not payload existence, receipt by the client or PG persistence. A separate final
event includes `release_event_id` and cache outcome. No receipt/identity enters
the reusable response. Source/proof expiry is checked again after waiting.
Coordinator capability metadata preserves the policy and explicit removal;
unsupported routers/snapshots cannot silently drop an active barrier. Upgrade
broker-confirming ingest and the entire router/coordinator fleet before enabling.

`x-csar-usage-budget` opts a tenant route into shared ingress admission with
`name`, `window`, `caller`, `owner`, `owner_tenant` and `fleet` capacities.
`owner_seller` remains a compatibility alias; equal aliases are accepted and
conflicting aliases fail. Both names charge the same owner-plus-verified-tenant
counter. Stored JSON, protobuf and Redis retain their existing `owner_seller`
identifiers, so changing vocabulary cannot reset spending or double-charge. Routes
sharing a policy name must use identical limits, including compatible API/MCP
paths. Every accepted request costs one unit before KMS, cache or receipt work;
HIT, polling and pages are charged too. Credentials, RPC IDs and body/query
variation do not create new budgets, and caller kind grants no quota exemption.

Admission uses registered, verified caller metadata and the actual tenant authz
scope. Service hops charge the verified origin when present; a standalone service
uses its own identity. Legacy unknown and platform-only contexts are unsupported
under this initial opt-in policy. Missing Redis/configuration fails startup;
runtime quota exhaustion returns `429 usage_exceeded` with dimension/retry timing,
and unavailable Redis returns `503 usage_unavailable` without cache fallback.

The existing Redis endpoint supplies a separate admission pool capped at eight
connections and 250ms operations, with context deadlines and driver retries off.
Counters use fixed windows from first acceptance; uncertain outcomes may consume
usage and are not refunded. Versioned coordinator capabilities preserve policy
limits and explicit removal. This supplies ingress protection; owner compute,
unique-work, concurrency and byte reservations remain separate W3 work. Capacity,
HA failure and fairness acceptance remain gates before production activation.

Request quota contracts: `csar/throttle/v1.RequestQuota` carries additional rolling
request caps alongside GCRA pacing. CSAR requires Redis and capability version1;
all windows charge atomically using Redis time. Stable names/keys preserve attempts
across replicas/reloads and limit reductions. Window changes fail closed until old
state expires (up to24h); never rename keys to reset spent quota. Redis must retain
state across restarts with persistence and no eviction. Losing state loses spent
attempts, so restore it or suspend affected routes before resuming. CSAR publishes
Retry-After/X-CSAR timing; workers own refresh schedules, not provider counters.
A zero cap explicitly denies admission until an allowance is verified. Quota routes
reject ordinary/transparent inline retries; each admitted request has one attempt.
Config and runtime share policy validation. Backend causes remain in server logs,
while client errors stay generic.


## Response streaming and optional gzip

Retries are disabled by default. Omit `x-csar-retry`; an empty block or a
resolved attempt budget of zero also enables no retries and installs no retry
middleware. A named policy's explicit budget is inherited only when referenced.
The original request/response streams without retry buffering. The legacy
max_attempts: 1 spelling remains supported but is unnecessary. A route or named
policy must explicitly set max_attempts above 1 to enable ordinary retries;
methods must also be eligible. Non-retryable responses and final attempts stream
immediately; only intermediate retryable responses are captured. Configured retry
methods/statuses and delays retain their meaning. Adaptive
backpressure observes 429 headers without reading/copying the request body unless
transparent 429 replay was explicitly enabled. Known requests above its body cap
retain their existing raw-response bypass. Unknown-length bodies stream without
pre-reading; a later body read failure is handled by the proxy rather than by
a replay-buffer preflight. New coordinators serialize an
omitted attempt budget as one so older routers do not infer three total attempts.
A response already committed to the caller is never replayed because of a later
body or connection failure. Redaction and cache fills can still buffer bodies.

The restart-required `--response-gzip` router flag defaults to false. When enabled,
Core's `httpx/compress` adds fast negotiated gzip to HTTP 200 JSON responses of at
least 1 KiB on non-internal routes. Every route on the shared `/svc` and
`/svc/…` internal surface skips CSAR-generated compression, independently of
service name or cache status; request Accept-Encoding and upstream encoded bytes
pass through unchanged. Its decision buffers at most a small prefix, not the whole body. An
explicit flush immediately commits the negotiated encoding, including for small
prefixes, so chunked proxy responses can stay compressed and stream. Existing
upstream gzip passes through unchanged. The wrapper sits outside the reloadable router,
so redaction and cache selection finish first; health/readiness endpoints are
not wrapped. HEAD, ranges, partial/non-JSON responses, upgrades, cookies,
no-store and no-transform bypass new compression. No request decompression,
new retries or automatic production activation is introduced.

Response-cache keys always include every Accept-Encoding header line, including
absence, independently of authored vary_headers. GET/HEAD use an encoding version
marker and POST keys are post-v2. Previous keys are not reused: deployment creates
a cold cache, and mixed versions use separate keys until old entries expire.
Fallback gzip occurs after cache storage, while upstream-encoded representations
remain partitioned. Cache-fill buffering/coalescing and DLP's existing full-body
processing are separate from this streaming change.

CSAR pins the published Core compression source commit for standalone builds.
Local development can also use an isolated Go workspace with the matching Core
and CSAR worktrees. Compression adds CPU work; benchmark actual
payloads/concurrency before enabling it in deployment settings.

Normal Go STS HTTP clients negotiate gzip through their underlying transport and
receive decoded JSON automatically; no manual Accept-Encoding injection or STS
token endpoint change is needed. Explicitly setting Accept-Encoding leaves
decoding to the caller. A native STS integration test checks decoded payloads,
caller/token header separation, and unchanged v1 upstream-429 normalization and
503 errors with fallback gzip enabled. Production commands may include extra
credential-rejection route flags: preserve the full deployed argv when enabling
gzip rather than replacing it with a shorter base Compose command.
