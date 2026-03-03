# CSAR (Centralized Smart API Router) Security and Tool Audit

This document outlines a comprehensive security, tool, and architecture audit of the CSAR project. It highlights strengths, identifies potential risks, and provides actionable recommendations to improve security posture, configurations, and overall functionality.

## 1. Security Assessment

### 1.1 Strengths
- **Strict Production Defaults (Fail-Fast)**: The `SecurityPolicyConfig` implements a `forbid_insecure_in_prod` flag. This correctly forces a hard failure at startup if TLS is missing or if plaintext gRPC is attempted in a production environment, eliminating a whole class of misconfiguration errors.
- **Robust Log Redaction**: The custom `logging.Secret` struct and `RedactingHandler` are excellent. Implementing `slog.LogValuer` on credentials provides compile-time defense-in-depth, guaranteeing that if a secret is accidentally passed to a logger, it resolves to `[REDACTED]`.
- **Anti-Spoofing Client IP Extraction**: In `extractClientIP`, checking the *rightmost* IP from `X-Forwarded-For` when `trust_proxy` is enabled is a very secure practice. This prevents trivial leftmost-spoofing attacks when CSAR sits behind trusted reverse proxies (like AWS ALB or Nginx).
- **KMS Payload Encryption & Token Injection**: Storing tokens externally (Coordinator/etcd) in an encrypted state and only decrypting them in-memory at request time significantly minimizes the blast radius of an etcd compromise.
- **Mutual TLS (mTLS)**: Fully supported for both the internal control plane (Coordinator ↔ Router) and the data plane (Router ↔ Upstream APIs).

### 1.2 Areas for Improvement & Vulnerabilities
- **Token Rotation & Cache Invalidation Strategy**: Currently, cache invalidation relies on manually bumping the `token_version` in the YAML configuration. 
  - **Risk**: Rotating compromised tokens requires a configuration redeployment/restart across all CSAR router instances.
  - **Recommendation**: Implement bi-directional gRPC streaming. The Coordinator should push cache invalidation events instantly to all connected Routers when an underlying token or KMS key is rotated in etcd.
- **In-Memory Rate Limiting in Distributed Environments**: 
  - **Risk**: `x-csar-traffic` (RPS and Burst) uses Go's standard `golang.org/x/time/rate` library. In a multi-replica Kubernetes deployment, this limit is per-pod. If `rps: 5` is set, 10 pods will allow 50 RPS to the upstream API, potentially violating third-party rate limits.
  - **Recommendation**: Introduce a distributed rate-limiting backend (e.g., Redis (check for the best solution first)) to enforce global traffic shaping across all nodes.
- **Transport Security Edge Cases**:
  - **Risk**: If developers use `tls: { insecure_skip_verify: true }` in staging environments for `https://` targets, it trains them to bypass security checks. 
  - **Recommendation**: Enforce custom CA injection (`ca_file`) even in staging, to ensure exact parity with production TLS verification mechanisms.

---

## 2. Tool and Dependency Audit

### 2.1 Dependencies
- **Go Version**: `1.25.0`. The project leverages modern Go capabilities. 
- **Libraries**: OpenTelemetry (`v1.41.0`), Prometheus (`v1.23.2`), and etcd (`v3.6.8`) are well-maintained, up-to-date, and standard choices for observability and distributed systems.

### 2.2 Implemented Tools
- **Code Linter Consistency**: The project now includes a strict `.golangci.yml` configuration encompassing `gosec`, `errcheck`, `gocritic`, and `bodyclose`, which significantly hardens the build against unhandled errors and security pitfalls.

### 2.3 Tooling Recommendations
- **Static Application Security Testing (SAST)**: 
  - While `gosec` is configured in the linter, ensure the linter is fully integrated into the CI/CD pipeline (e.g., GitHub Actions) to automate scanning.
- **Dependency Scanning**: 
  - Enable Dependabot or Renovate to automate minor patch updates for indirect dependencies, reducing the window of exposure to CVEs.

---

## 3. Configuration & Functionality Improvements

### 3.1 Implemented Enhancements
- **Global Downstream Retry Policies**: The newly implemented `x-csar-retry` config allows CSAR to automatically retry idempotent (e.g., `GET`, `HEAD`) requests with exponential backoff and jitter upon receiving HTTP 502/503/504 from the upstream, increasing resilience to transient network failures.

### 3.2 Enhancing the OpenAPI-style Configs — ✅ Implemented
- **Dynamic Live-Reloading** — ✅ Implemented via SIGHUP signal handler (`reloadableHandler` with `atomic.Pointer`). `kill -HUP <pid>` reloads `Paths`, `AccessControl`, and `CircuitBreakers` without dropping active HTTP connections.
- **Path Rewriting & Regex Matching** — ✅ Implemented in `internal/router/router.go`. `compilePathPattern()` converts `{var:regex}` paths to compiled regexps. `path_rewrite` field in `BackendConfig` supports `$1/$2` back-references for rewriting before proxying.

### 3.3 Expanding CSAR Use Cases — ✅ Implemented
1. **Inbound Identity Validation (API Gateway role)** — ✅ Implemented in `internal/authn/jwt.go`.
   `x-csar-auth-validate` block validates JWT signatures against JWKS endpoints (RS256/384/512, ES256/384/512). Supports issuer/audience validation, `required_claims`, `forward_claims` (copies JWT claims to request headers), and JWKS key caching with configurable TTL. Rejects `alg=none` tokens.

2. **Payload Redaction (Data Loss Prevention)** — ✅ Implemented in `internal/dlp/redact.go`.
   `x-csar-redact` block intercepts JSON responses and masks specified fields. Supports dot-notation paths (`user.email`), wildcard array iteration (`users.*.email`), and configurable mask strings.

3. **Multi-Tenant Gateway** — ✅ Implemented in `internal/tenant/tenant.go`.
   `x-csar-tenant` block routes to different backends based on `Host` or custom `X-Tenant-ID` headers. Supports case-insensitive host matching, port stripping, and a `default` fallback URL. Reverse proxies are cached per target URL.

### 3.4 Multi-Credential & Dynamic Token Resolution — ✅ Implemented

1. **Static Header Injection (`x-csar-headers`)** — ✅ Implemented in `internal/router/router.go`.
   Injects fixed key-value headers into upstream requests (e.g., `User-Agent`). Defined per-route, applied before security injection. No KMS involvement — purely static.

2. **Multi-Credential Support (`x-csar-security` as array)** — ✅ Implemented.
   `x-csar-security` now accepts a YAML list of credential entries. Each is independently resolved, decrypted via KMS, and injected into the upstream request. A backward-compatible custom `UnmarshalYAML` on `SecurityConfigs` also accepts the old single-object syntax.

3. **Dynamic Token Ref (`{query.param}`, `{header.Name}`)** — ✅ Implemented in `pkg/middleware/auth.go`.
   `token_ref` supports interpolation placeholders like `token_{query.account_id}`. At request time, `resolveTokenRef()` extracts the value from URL query parameters or request headers and resolves the full token reference. Missing parameters return HTTP 400. The stale cache is keyed by the resolved ref, preventing cross-pollution between different accounts.
