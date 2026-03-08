# CSAR — Coordinated Stateless API Router

CSAR is a lightweight, security-first API gateway written in Go. It proxies HTTP requests to upstream services while handling **credential injection**, **rate limiting**, **circuit breaking**, **load balancing**, **CORS**, **response caching**, **JWT validation**, and **IP access control** — all driven by YAML config files using OpenAPI-style extensions.

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
6. **JWT Validation** — inbound JWKS-based bearer token validation (header or cookie)
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
| **Rate Limiting** | Per-route token-bucket throttling with `rps`, `burst`, and `max_wait`. Three backends: local (in-memory), Redis (distributed GCRA), or coordinator (dynamic quota assignment). Supports dynamic per-entity keys and VIP overrides. |
| **Global Throttle** | Safety-net rate limit applied to all routes before per-route throttle. Fast in-memory atomic counter prevents runaway traffic. |
| **Adaptive Backpressure** | Reads upstream `Retry-After` / `X-RateLimit-Reset` headers from 429 responses and suspends the token bucket accordingly. |
| **Circuit Breaking** | Named profiles with configurable failure thresholds, intervals, and recovery timeouts. |
| **Load Balancing** | Round-robin and random strategies across multiple upstream targets. Active health checking (HTTP/TCP) with configurable thresholds automatically removes unhealthy targets. |
| **CORS** | Per-route Cross-Origin Resource Sharing with O(1) origin lookups and automatic OPTIONS preflight short-circuiting. |
| **Response Caching** | In-memory LRU cache for idempotent requests with configurable TTL, max entries, and max body size. Respects `Cache-Control: no-store/no-cache`. |
| **Payload Redaction (DLP)** | Masks sensitive JSON fields (`ssn`, `card_number`, nested paths, wildcards) in upstream responses before returning to clients. Configurable `max_response_size` prevents DoS. |
| **Multi-Tenant Routing** | Routes to different backends based on tenant identifier in headers or host. |
| **Streaming Support** | Detects `Upgrade: websocket` and `text/event-stream` (SSE) to bypass buffering middlewares for persistent connections. |
| **JWT/JWKS Validation** | Validates inbound bearer tokens against JWKS endpoints. Supports issuer/audience checks, required claims, claim forwarding to upstream headers, and cookie-based JWT auth. |
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
| `global_throttle` | Global rate limit safety net (`rate`, `burst`, `max_wait`) |
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
| `auth_validate_policies` | `x-csar-auth-validate` | JWT validation policies |

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

      x-csar-auth-validate:
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
        key: "seller:{query.seller_id}"         # per-entity rate limiting
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

Root-only fields (`listen_addr`, TLS, coordinator address) log a warning if changed — a full restart is required for those.

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
