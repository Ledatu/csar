# csar Agent Summary

W2 opaque API-key/MCP and universal grant validation preserve optional issuer
caller metadata after subject/credential binding checks. Malformed present
metadata fails closed and is not cached; legacy absence remains compatible.
The reserved gateway namespace is stripped before validation. Backend parsing
requires upgraded Core readers. JWT/session adoption, signed origin and audit
receipt barriers remain later W2 work; no production configuration is changed.

## Hosted seller authentication

The dedicated `mcp` validation mode exchanges a resource bearer at Authn and forwards a per-request delegation to the hosted seller adapter. The `delegated` mode consumes it before cabinet authorization and report-cache lookup. Both modes consult Authn on every request. Personal-key routes forward only the scope verified for that route.


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
- Shared routes may select session, personal-key or STS authentication by credential location; selection is compiled once, preserves verified audit identity, and rejects ambiguity without fallback. Usage belongs in README.md and csar.schema.json.
- Inbound JWTs are validated at the router against JWKS.
- Opaque seller personal keys use mTLS introspection against `csar-authn`.
  The router bounds token caching to 15 seconds, checks `adverts:read` and
  the bound seller ID, strips the raw token, then evaluates current authz.
- `x-csar-authz` policies gate routes before proxying; a policy or route may list `any_of` branches (first allow wins) so tenant members and platform staff can share a route.
- `gatewayctx` is the trusted identity carrier for backends, but it is only safe
  when paired with mTLS, `TrustedMiddleware`, or equivalent network isolation.
- Coordinator admin access is mTLS-protected and profile-guarded.

## Critical Flows
- Source-config snapshots and quota assignments use the last successful complete
  config; partial route-store writes never combine new routes with old policies.
  Store-only mode remains supported. Route ordering is stable for snapshot hashes.
  Failed router builds discard staged throttle registrations and stop their health
  checks, preserving the live coordinator quota registry.
- Opt-in `--stored-token-coherence` uses inspected stored expiry, durable exact-ref
  etcd revisions and trusted upstream-401 reports. Read
  `STORED_CREDENTIAL_LIFETIME.md` for the all-writer activation boundary,
  unknown-expiry compatibility and pending-write recovery requirements.
  Upstream-401 quarantine requires explicit `--credential-rejection-route`
  selection of one configured route and one injected credential; `#Header` explicitly
  targets one entry on multi-entry routes. Default off.
  Owners supply expiry; storage/injection never infer it from JWT shape.

- Legacy stored-credential freshness is checked on demand per ref, at most once per minute
  by default (`--stored-token-refresh-interval`). Only the requested credential
  is fetched; S3 mode still has no listing or background scan. Concurrent
  checks coalesce, failures close access and retry no sooner than five seconds,
  and a concurrent local rotation/deletion wins over an older backend fetch.
  Minted-token soft/hard expiry policy is unchanged.
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
- Optional snapshot `redis_key_prefix` field 19 preserves namespace presence:
  absent legacy fields retain the last successful prefix; explicit empty and
  omitted full-YAML Redis blocks restore built-in prefixes. Connection secrets
  remain local. Upgrade routers, then coordinators before relying on changes.
- Global throttle is router-owned, so removing its block disables it and a
  failed rebuild cannot alter the current global limiter. Per-route quota
  management remains shared with the coordinator client.
- `config.SnapshotRestartRequired` captures all bootstrap blocks, excluding hot
  Redis prefix and audit capture. Routers warn on complete YAML reloads;
  coordinators warn on changes between successful config applies. Diagnostics
  report field names only, including for secret changes, and never values.
- SSRF policy is rebuilt on every router reload. Coordinator snapshots carry
  optional `ssrf_protection` field 18; absent legacy messages retain the last
  applied policy with a warning, while omitted YAML blocks reset to secure
  defaults. Policy-only config applies notify active subscriptions through
  the existing debounce. Upgrade routers, then coordinators; older routers
  ignore the field. In-flight requests may finish under their previous policy.
- Explicitly cached POST reads include an exact-body SHA-256 digest, request
  Content-Type and Content-Encoding in a separate versioned key format.
  `max_request_body_size` defaults to 64 KiB, supports named-policy scalar
  overrides and travels in coordinator CacheConfigProto field 26. Oversized
  bodies/trailers bypass caching intact; body read errors return 400. Protected
  POST caches require subject or tenant in the lookup key. Refreshes retain
  context values and replay independent bodies with bounded deadlines.
  Upgrade all router/coordinator readers before publishing POST cache policies;
  disable POST caching during mixed-version rollout or rollback.
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
- Standalone `make lint-security` scans maintained source once, fails on findings
  and excludes generated protobuf files. Reviewed exceptions use rule-specific
  `#nosec` reasons; G114 HTTP timeout checking is enabled in strict lint too.
- Security regressions cover partial request-body failures (400 before upstream),
  oversized-body closer preservation, root-scoped MCP scaffold collection,
  config/private-key overwrite permissions, escaped tenant JSON, DSN diagnostics
  and lease-revocation errors. Scaffold configs use one tracked `.tmpl` source
  and generated PostgreSQL Compose services require an explicit password.
- `make lint`
- `make test`
- `make test-race`
- `make lint-strict` and `make lint-security` when routing/security behavior changes
  touch the router surface

## Authn session schema validation

Personal-token auth validation transports `introspection_endpoint`,
`introspection_tls`, `required_scope`, and `seller_path_param` through the
coordinator snapshot protobuf. Deploy matching coordinators and routers before
relying on these policies: older senders omit the fields and older readers
discard them. Regression coverage serializes a resolved named policy through
the actual protobuf snapshot and reconstructs the router configuration.

The core dependency includes `legacy_users_sync.lock_database_dsn`, required for
enabled PostgreSQL sync apply. Release this matching csar-helper before publishing
that config; router/coordinator source behavior is unchanged in this update.
CI covers the actual default branch master as well as main, and prepares the
existing MCP schema embed input before scanning/building all Go packages.

## Shared cache flight primitive (source only, October 23)
- HTTP cache coalescing now uses `csar-core/readcache.Group` instead of a local
  mutex/map implementation. HTTP keys, stores, TTL and auth ordering stay here.
- Per ResponseCache instance: 1024 live keys, 128 followers/key, 4096 key bytes.
  Excess work returns 503 and Retry-After without issuing an uncoalesced request.
- Stale refresh admission occurs before goroutine creation; an existing refresh
  needs no background follower. Deferred ticket completion unblocks followers
  when a synchronous leader panics. No Redis lease/fencing is introduced.
- Development uses sibling go.work; pin a release containing readcache before
  publishing this consumer outside the workspace.

## Safe credential failures (November 14)

AuthInjector maps coordinator status classes into the shared `apierror` allowlist
for fail-closed HTTP 502 responses. Raw provider errors and token references are
not exposed. A fake token endpoint → Minter → MintingStore → AuthService → router
integration test covers invalid credentials, provider quota, malformed responses
and timeout. Existing stale/fail-closed policy is unchanged.

## Delegated access

The grant-exchange, grant-discovery and grant-resource policies use the shared authntokens contract. The gateway binds a verified grant to the configured audience, purpose and scope. Resource use also binds the matched route parameter and the issuer-provided tenant before authorization and response caching. The deployment chooses the discovery backend. The original seller modes retain their wire contract during migration.
