# CSAR — Current Status and Next Steps

**Date:** 2026-03-04
**Codebase:** ~15,200 lines Go, 20 test packages, 13 e2e tests

---

## What Was Done

### Audit Cycle 1 — `AUDIT_AND_YANDEX_KMS_PLAN.md` (P0–P2)

| Task | Status |
|------|--------|
| P0-1: Remove plaintext `SecretDistribution` from proto + `BroadcastSecrets` from coordinator | Done |
| P0-2: Production security policy (`dev/stage/prod`, `forbid_insecure_in_prod`, `require_mtls_for_coordinator`) | Done |
| P0-3: Implement `YandexAPIProvider` with direct HTTP/REST (no Go SDK) | Done |
| P1-1: Wire `CachingProvider` in bootstrap with TTL + `max_entries` | Done |
| P1-2: End-to-end token versioning (`TokenEntry.Version` → `GetEncryptedToken` → router cache invalidation) | Done |
| P2-1: Extend `Provider` interface with `Name()`, `Health()` | Done |
| P2-2: Add `kms`, `security_policy`, `on_kms_error`, `token_version` to YAML config | Done |

### Audit Cycle 2 — `audit8.md`

| Task | Status |
|------|--------|
| Inbound TLS in prod is a hard error (not warning) | Done |
| Correct Yandex KMS endpoint to `kms.api.cloud.yandex.net` | Done |
| Wire `on_kms_error`, `token_version`, `kms.cache.max_entries` into runtime | Done |
| Proto cleanup: reserve field 3, remove `SecretDistribution`, update comments | Done |
| Regenerate `.pb.go` stubs | Done |

### Audit Cycle 3 — `SECURITY_AUDIT.md`

| Task | Status |
|------|--------|
| Fix X-Forwarded-For spoofing (rightmost IP extraction) | Done |
| Implement `redact_sensitive_logs` via `RedactingHandler` (`slog.Handler`) | Done |
| Enforce `insecure_skip_verify` as hard error in prod | Done |
| `slog.LogValuer` on `logging.Secret`, `TokenEntry`, `staticToken` | Done |

### Audit Cycle 4 — `security_and_tool_audit.md`

| Task | Status |
|------|--------|
| §2.2: `.golangci.yml` with strict linters (`gosec`, `errcheck`, `gocritic`, `bodyclose`) | Done |
| §2.2: `lint-security` and `lint-strict` Makefile targets | Done |
| §1.2: `insecure_skip_verify` staging-specific warning (recommend `ca_file` for parity) | Done |
| §3.1: SIGHUP config hot-reload (`reloadableHandler` with `atomic.Pointer`) | Done |
| §3.1: `x-csar-retry` config + retry middleware with exponential backoff/jitter | Done |
| §1.2: `TokenInvalidation` proto message + coordinator `BroadcastTokenInvalidation` | Done |
| §1.2: `AuthInjector.InvalidateToken` / `InvalidateAllTokens` (stale cache clear) | Done |
| §3.2: Path rewriting & regex matching (`{var:regex}` + `path_rewrite`) | Done |
| §3.3.1: Inbound JWT/JWKS validation middleware (`x-csar-auth-validate`) | Done |
| §3.3.2: Payload redaction / DLP middleware (`x-csar-redact`) | Done |
| §3.3.3: Multi-tenant gateway (`x-csar-tenant`, Host/header routing) | Done |

### Audit Cycle 5 — Multi-Credential & Dynamic Token Resolution

| Task | Status |
|------|--------|
| §1: `x-csar-headers` — static header injection per route (`User-Agent`, etc.) | Done |
| §2: `x-csar-security` as array — multi-credential support (list-based) | Done |
| §2: Backward-compatible YAML unmarshal (`SecurityConfigs` handles object or array) | Done |
| §3: Dynamic `token_ref` — `{query.param}` / `{header.Name}` interpolation | Done |
| §3: Stale cache keyed by resolved ref (no cross-pollution between sellers) | Done |
| §4: Updated `config.example.yaml` with WB multi-credential + dynamic token flow | Done |

### Build & Infra

| Task | Status |
|------|--------|
| Fix Makefile ldflags case (`main.version` → `main.Version` for router) | Done |
| Create `Dockerfile.coordinator` (multi-stage, non-root, stripped) | Done |
| Add coordinator to `docker-build` Makefile target | Done |

---

## What Still Works

- `make build-all` — compiles `csar`, `csar-coordinator`, `mockapi`
- `go vet ./...` — clean
- `go test` — 20 packages pass (including `authn`, `dlp`, `tenant`, `retry`)
- `make test-e2e` — 13 Docker-based e2e tests pass (etcd-backed coordinator)
- `make lint-strict` — `.golangci.yml` with `gosec`, `errcheck`, `gocritic`, `bodyclose`
- `make lint-security` — `gosec` SAST scan with JSON report output
- Binary sizes: ~15 MB router, ~11 MB coordinator (stripped)
- SIGHUP config reload — `kill -HUP <pid>` reloads routes/ACLs/retry without downtime

---

## What To Do Next

### High Priority

**1. Per-Client Rate Limiting**
- Currently `TrafficConfig` applies global per-route RPS/burst limits. A single attacker can exhaust the entire route quota.
- Add `limit_by: "ip"` or `limit_by: "header"` to `TrafficConfig`.
- Implement per-IP token buckets in `internal/throttle` (local sharded map or `sync.Map`).
- Files to change: `internal/config/config.go` (add `LimitBy` field), `internal/throttle/throttle.go` (per-key bucketing), `internal/router/router.go` (pass client IP/header to throttler).

**2. Secure Memory Handling for Tokens**
- `staleCache` in `pkg/middleware/auth.go` stores decrypted tokens as plain `string`. Go GC doesn't zero freed memory.
- Replace `map[string]string` with `map[string][]byte` and zero-wipe on eviction/replacement.
- Consider `awnumar/memguard` for heap-protected storage.
- Files to change: `pkg/middleware/auth.go` (`staleCache` type and `setStale`/`getStale` methods).

### Medium Priority

**3. KMS Retry/Backoff**
- `kms.retry.*` config fields are parsed but emit a "reserved for future release" warning.
- Implement a `RetryProvider` wrapper in `internal/kms/` using exponential backoff with jitter.
- Wire it between `CachingProvider` and the inner provider in `cmd/csar/main.go`.

**4. Automated Secret Rotation (Coordinator)**
- The coordinator stores static `TokenEntry` values. There is no rotation mechanism.
- Add a rotation loop that re-encrypts tokens, bumps `token_version`, and signals routers via the config stream to drop stale cache entries.
- Files to change: `internal/coordinator/authservice.go`, proto if needed.

**5. Trusted Proxy CIDRs for X-Forwarded-For**
- Current `trust_proxy` is a boolean. Deep proxy chains need `trusted_proxy_cidrs` to walk the XFF list from right to left, dropping known proxies.
- Add `TrustedProxyCIDRs []string` to `AccessControlConfig`.
- Update `extractClientIP` in `internal/router/router.go` to iterate XFF right-to-left, skipping IPs in trusted CIDRs.

### Long Term

**6. Distributed Rate Limiting (audit §1.2)**
- In-memory `x-csar-traffic` is per-pod. In a multi-replica K8s deployment, the global rate seen by the upstream is `rps × pod_count`.
- Introduce a distributed rate-limiting backend. Candidates:
  - **Redis** with sliding-window or token-bucket script (`EVALSHA` with atomic Lua).
  - **Coordinator-based global quotas** (already partially implemented via `QuotaAssignment`) — extend to enforce coordinated budget across routers in real time.
- Files to change: `internal/throttle/`, new `internal/ratelimit/` package, config additions.

**7. SSRF Outbound Protections**
- The reverse proxy (`internal/proxy/proxy.go`) does not restrict outbound destinations.
- Add a `DialContext` hook on the `http.Transport` that rejects connections to `169.254.169.254`, `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, and `127.0.0.0/8` unless explicitly allowlisted.
- This also protects the Yandex KMS metadata endpoint from SSRF exploitation.

**8. Audit Logging Service**
- Security events (token decryptions, access denials, rate limit triggers, mTLS rejections) are mixed into application logs.
- Create a dedicated `internal/auditlog` package with its own `slog.Logger` writing to a separate sink (file, stdout channel, or remote collector).
- Emit structured audit events at each security decision point in the router pipeline.

**9. KMS Provider Observability**
- Add Prometheus metrics: `kms_operation_duration_seconds{op,provider,status}`, `kms_cache_hit_total`, `kms_cache_miss_total`, `kms_errors_total{class}`.
- Add OpenTelemetry span attributes per KMS call (provider, key_id, operation, result).
- These live in middleware wrappers in `internal/kms/`.

**~~10. Path Rewriting & Regex Matching (audit §3.2)~~** — **Done**
- `compilePathPattern` converts `{var:regex}` paths to compiled regexps.
- `path_rewrite` in `BackendConfig` with `$1/$2` back-references.
- Regex routes are matched after exact/prefix routes.

**~~11. Inbound JWT/JWKS Validation (audit §3.3.1)~~** — **Done**
- `internal/authn/jwt.go`: `JWTValidator` middleware with JWKS caching, RSA + ECDSA signature verification.
- `x-csar-auth-validate` config block with `jwks_url`, `issuer`, `audiences`, `required_claims`, `forward_claims`.
- Rejects `alg=none`, validates `exp`/`nbf`/`iss`/`aud`, forwards claims to request headers.

**~~12. Payload Redaction / DLP (audit §3.3.2)~~** — **Done**
- `internal/dlp/redact.go`: `Redactor` response middleware for JSON field masking.
- `x-csar-redact` config block with `fields` (dot-notation, wildcards), `mask`, `enabled`.
- Supports nested objects, arrays, `*.` wildcards for array element fields.

**~~13. Multi-Tenant Gateway (audit §3.3.3)~~** — **Done**
- `internal/tenant/tenant.go`: `Router` selects upstream based on tenant header.
- `x-csar-tenant` config block with `header`, `backends` map, `default` fallback.
- Case-insensitive Host matching, port stripping, cached reverse proxies per target.

**14. Automated Dependency Scanning (audit §2.2)**
- Enable Dependabot or Renovate in CI to automate minor patch updates for indirect dependencies, reducing CVE exposure window.
- Add `.github/dependabot.yml` or `renovate.json` configuration.

**~~15. Persistent Store for Coordinator State (etcd > PostgreSQL)~~** — **Done**
- `EtcdStore` implemented in `internal/statestore/etcd.go`.
- Wire via `--store=etcd --etcd-endpoints=...` in `cmd/csar-coordinator/main.go`.
- e2e tests run against etcd (`quay.io/coreos/etcd:v3.5.17`).

---

## Architecture Reference

```
Client → [TLS] → CSAR Router → [mTLS] → Upstream Backend
                     │
                     ├── IP Access Control (rightmost XFF)
                     ├── JWT/JWKS Validation (x-csar-auth-validate)
                     ├── Static Header Injection (x-csar-headers)            ← NEW
                     ├── Multi-Credential Auth (x-csar-security as array)    ← NEW
                     │   ├── Dynamic token_ref ({query.x}, {header.x})       ← NEW
                     │   └── KMS decrypt → header inject (per credential)
                     ├── Throttle (per-route token bucket)
                     ├── Retry (exponential backoff + jitter)
                     ├── Circuit Breaker (per-route)
                     ├── DLP Redaction (x-csar-redact)
                     ├── Multi-Tenant Routing (x-csar-tenant)
                     ├── Path Rewrite ({var:regex} → $1/$2)
                     └── Reverse Proxy
                     
CSAR Router ←──[gRPC/mTLS]──→ Coordinator ←──→ etcd
                                  ├── AuthService (encrypted tokens)
                                  ├── ConfigStream (route + token invalidation updates)
                                  └── QuotaService (RPS redistribution)

Signals: SIGHUP → reload config atomically (no connection drops)
```

## Key Files

| Area | Files |
|------|-------|
| Router pipeline | `internal/router/router.go` |
| Auth injection | `pkg/middleware/auth.go` |
| JWT/JWKS validation | `internal/authn/jwt.go` |
| DLP / payload redaction | `internal/dlp/redact.go` |
| Multi-tenant routing | `internal/tenant/tenant.go` |
| Retry middleware | `internal/retry/retry.go` |
| KMS providers | `internal/kms/{kms,local,yandex,cache}.go` |
| Config + validation | `internal/config/config.go` |
| Coordinator auth | `internal/coordinator/authservice.go` |
| State store (etcd) | `internal/statestore/etcd.go` |
| Log redaction | `internal/logging/redact.go` |
| Protobuf | `proto/csar/v1/{coordinator,auth}.proto` |
| Bootstrap | `cmd/csar/main.go`, `cmd/csar-coordinator/main.go` |
| Linter config | `.golangci.yml` |
| Config reference | `config.example.yaml` |
| E2E tests | `tests/e2e/`, `docker-compose.e2e.yaml` |
