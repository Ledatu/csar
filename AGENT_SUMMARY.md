# csar Agent Summary

## Role In Prod
`csar` is the trusted API router and coordinator pair for the stack. The router
owns authn validation, authz enforcement, throttling, circuit breaking, token
injection, and upstream proxying. The coordinator owns config/token distribution
and internal admin surfaces.

## Runtime Entry Points
- `cmd/csar/main.go` starts the router.
- `cmd/csar-coordinator/main.go` starts the coordinator.
- `cmd/csar-helper/main.go` and related helper commands are used for config and
  key tooling.

## Trust/Auth Model
- Inbound JWTs are validated at the router against JWKS.
- Opaque seller personal keys use mTLS introspection against `csar-authn`.
  The router bounds token caching to 15 seconds, checks `adverts:read` and
  the bound seller ID, strips the raw token, then evaluates current authz.
- `x-csar-authz` policies gate routes before proxying; a policy or route may list `any_of` branches (first allow wins) so tenant members and platform staff can share a route.
- `gatewayctx` is the trusted identity carrier for backends, but it is only safe
  when paired with mTLS, `TrustedMiddleware`, or equivalent network isolation.
- Coordinator admin access is mTLS-protected and profile-guarded.

## Critical Flows
- Request pipeline order matters: authn, authz, throttling, circuit breaking,
  retry/backpressure, response shaping, and proxying.
- Config loading supports file, S3, and HTTP sources with profile validation.
- KMS-backed token injection and coordinator-driven quota/token sync are core
  prod flows.
- Each router holds one coordinator `Subscribe` stream through HAProxy, which
  closes connections idle for 2 minutes. The coordinator's gRPC keepalive
  (`--grpc-keepalive-time`) keeps the stream open. A reconnect replays the
  current snapshot, and the router skips rebuilding when it is unchanged.
- Path templates match from the most precise to the widest
  (`internal/routepattern`), identically on every router build and in
  `csar-helper simulate`.
- Readiness and health sidecars are part of the operational contract.

## Config And Secrets
- Throttle policies, inline traffic and global limits accept `requests` +
  `period` as an alternative to legacy RPS fields. Resolution consumes the pair
  before inheritance/distribution; compiled YAML and protobuf remain canonical
  RPS. Mixed units and invalid pairs fail config loading. Redis GCRA rounds
  emission intervals up to milliseconds. See `README.md` for semantics
  and the required reader upgrade before publishing authored period configs.
- Named throttle policies also provide adaptive backpressure and client-limit
  defaults. Omitted route blocks inherit detached copies; explicit blocks
  replace the whole object and can disable it with `enabled: false`. Resolved
  route protobufs already carry these settings; no protocol change is needed.
- `profile:` and `ValidateResolvedKMSProvider` are security-critical; the runtime
  KMS provider must match the active deployment profile.
- `tls`, `coordinator`, `authz`, `audit`, and token source settings are the
  main trust-sensitive knobs.
- `configsource` / manifest-backed inputs should be treated as untrusted until
  validated.

## Audit Hotspots
- Every active audit mode (errors/all/implicit mutating-method audit) attempts
  a versioned, bounded, sanitized final-client error diagnostic in
  `metadata.http_response` by default, even without an audit-capture block.
  Explicit `x-csar-audit-capture.response: off` opts out; request/query capture
  is never implicitly enabled and successful response bodies are omitted.
  `csar-core/audit` owns the envelope and sanitization; no audit storage/proto
  migration is needed. Coordinator `AuditCaptureConfigProto` fields 11–12 carry
  explicit response mode/limit. No protobuf/storage change is needed for the
  runtime default; upgrade routers for routes without explicit response capture.
- Auditing wraps matched routes before auth/security/admission refusals, emits
  only once after retries/response shaping, and preserves preflight/unmatched
  exclusions. Identity/email must come from validated gateway/forwarded claims,
  never caller-supplied early-denial headers. The private proxy response observer
  distinguishes transport failures from empty upstream HTTP responses without
  trusting upstream headers. Streaming/flush/hijack bodies are omitted.
- JWKS handling is split between router-local logic and `csar-core/jwtx`.
- `gatewayctx` trust depends on the surrounding transport and network policy.
- KMS/profile enforcement lives in both config validation and the runtime
  entrypoint; future entrypoints must keep calling the resolved-provider check.
- Recent commits touched config merging, authz policies, authn JWKS TLS, and
  readiness behavior, so re-read those paths before changing request flow.

## First Files To Read
- `cmd/csar/main.go`
- `cmd/csar-coordinator/main.go`
- `internal/router/builder.go`
- `internal/router/serve.go`
- `internal/authn/jwt.go`
- `internal/config/validate.go`
- `internal/config/profiles.go`

## DRY / Extraction Candidates
- Prefer `csar-core/jwtx` for remote JWKS handling instead of duplicating cache
  and key-conversion logic.
- Keep trust and transport primitives in `csar-core`; do not re-implement them
  in router code.

## Required Quality Gates
- `make lint`
- `make test`
- `make test-race`
- `make lint-strict` and `make lint-security` when routing/security behavior changes
  touch the router surface

## Authn session schema validation
The core dependency includes `legacy_users_sync.lock_database_dsn`, required for
enabled PostgreSQL sync apply. Release this matching csar-helper before publishing
that config; router/coordinator source behavior is unchanged in this update.
CI covers the actual default branch master as well as main, and prepares the
existing MCP schema embed input before scanning/building all Go packages.
