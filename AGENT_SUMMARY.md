## Matching Authn/Authz helper validation

`csar-helper validate-authn` uses the explicit credential receiver schema and
`validate-authz` the full service-capability receiver schema. CLI validation now
matches the implemented runtimes, including secure separate owner/consent cookies,
transactional issuer audit, pinned client TLS and per-service role ceilings.
Older default schema readers remain fail-closed. Helpers validate configuration;
they neither register runtime endpoints nor activate a deployed feature.

## Namespace-aware delegation v2 (U08/U09, source only)

Distinct grant-exchange-v2/discovery-v2/resource-v2 modes require exact profile,
namespace, audience, scope and matched resource parameters. Core v2 responses
must strictly echo every binding and a classified owner/caller, original grant
revision and fresh deadline; v1 responses, duplicate/unknown fields and incomplete
snapshots deny. Resource use additionally binds the issuer's authorized ScopeRef
to the exact Authz branch that actually checks access before backend/cache use.
All v2 credential introspection is per request; exchange/discovery response caches
are forbidden. Exchange forwards only its fresh proof over verified backend mTLS.

The existing policy capability registry now advertises
`csar.delegation_contract_version=2`. Coordinator subscribers must advertise it
before receiving active v2 routes, including named/selected policies. Full wire
snapshots retain profile/namespace on new coordinator protobuf tags 23/24; all old
tags remain stable. Missing required fields/version metadata retain the last good
router, while explicit versioned removal works. Router rebuilds revalidate v2
bindings and TLS/authz dependencies independently of a helper's validation.
Core is pinned to merged #48. No deployed route/config, Redis state/limits,
credential producer or outbound Telegram-ID JWT bridge is changed.

## Uniform caller envelope compatibility — source only

Pins merged Core34bbe3cf so verified caller/origin envelopes can carry bounded
HTTPS client metadata identifiers without service-local validation copies.
Identity, ownership, tenant authorization and credential audiences retain their
existing checks. This is a receiver compatibility prerequisite before enabling
automatic MCP onboarding; it changes no route, feature flag or deployment.

## Fresh personal-key validation for signed-origin reports

Origin receiver routes renew personal-key validation before minting a proof,
including select-mode branches. The source lease remains capped by the existing
validation TTL and credential expiry; refreshing cannot extend a revoked key or
fall back on issuer failure. This avoids inheriting a nearly expired cached lease.
Ordinary routes retain their current authentication cache, and Redis report caches
remain enabled after authentication/authorization/receipt checks.

## Signed-origin aliases and backend rewrites

Receiver-enabled routes authenticate and hash the original ingress path, then
rewrite a cloned request only for backend dispatch. Cache keys, audit and proofs
retain the alias; existing routes without origin receivers keep their previous
rewrite order. Native TLS/JWT/session forwarding tests cover both root and child
proofs, backend path mapping, cache-hit behavior and mismatched path rejection.

## Manifest compiler schema compatibility

Pins Core1c1da5d9 so the canonical helper validates the explicit Authn
`origin_router_ca_file` opt-in. It also includes the reviewed audit context
helper; no router policy, protocol or startup default changes. Standalone
build/full tests/lint pass. Issuer and receiver activation remain explicit.

# csar Agent Summary

Coordinator SIGTERM drains long-lived Subscribe streams before bounded gRPC
shutdown via csar-core/grpcserver. New subscriptions receive Unavailable; routers
retain the last snapshot and reconnect to healthy peers. Main waits for shutdown
cleanup before returning; token/state stores close after RPC drain. No runtime
route, TLS, credential, Redis or feature-policy change is activated by this fix.

Opt-in x-csar-usage-budget atomically charges caller/owner/owner+tenant/fleet
ingress across compatible routes and credentials before KMS/cache/receipts.
Verified origin supplies attribution on service hops; unknown/platform-only
contexts fail closed. Policies survive store/coordinator/reload and reject
conflicting limits under one name. A separate bounded pool reuses the existing
Redis endpoint with deadlines/retries-off and independently owned push state.
Quota denial is typed 429; Redis failure is 503 without cache fallback. This is
ingress protection, not reporting compute/byte reservations or production rollout.

Opt-in `x-csar-audit-release` requires authn/authz, audit all and a synchronous
receipt client. Every authorized MISS/HIT waits for broker-confirmed release
authorization before cache/backend dispatch; uncertain receipts return retryable
503. Final outcome separately links the release event and cache status. Source
freshness is rechecked after the wait; streaming is rejected. A versioned policy
capability registry preserves this and future opt-in route semantics, including
explicit removal. No production policy or Redis limit is changed.

Route `x-csar-origin-receiver` is preserved in route-store JSON and the existing
coordinator wire contract. Versioned full snapshots preserve explicit removal;
routers reject legacy snapshots while receiver policies are active. Subscribers
advertise preservation capability; coordinators refuse to send enabled policies
to unsupported routers. Router rebuilds bind configured receivers to a local
RootIssuer and fail if it or verified backend mTLS/authn/tenant authz is missing.
The optional router-local `origin_issuer` startup block constructs one Core root
client with verified mTLS and context-aware bounded JWKS resolution. Issuer/TLS
settings require restart and never enter coordinator snapshots. The issuer and
its JWKS cache survive all router rebuilds; owned transports close at process
shutdown. No production policy, certificate or Redis limit is changed.

The opt-in WithOriginForwarding adapter binds exact route keys to backend service
principals independently of access-token audiences. It requires verified backend
mTLS, static HTTPS targets and tenant authz. Root issuance runs only on actual
upstream dispatch after cache lookup; existing signed service proofs are forwarded
without reminting. Source freshness/tenant binding and proof expiry bound dispatch.
Original caller/operation metadata is typed; opaque proof headers are stripped
from public/cache responses, including trailers. Startup and coordinator support
are opt-in; production activation remains disabled.

Root issuance prerequisites use private authn.Source context with owned caller
metadata and an absolute validation deadline. API-key/session cache hits preserve
the original freshness lease instead of renewing it per request. Missing legacy
metadata/expiry provides no source. Production activation remains separate.

W2 final audit events include the verified immediate Caller, authorized signed
OriginCaller and operation/parent/trace correlation. Ordinary operation IDs are
server-generated independently of client request IDs. Actor retains immediate-hop
semantics; successful tenant authz supplies the cabinet scope. Every cold/cache
hit/denial emits its own event under the route's existing audit mode. Rejected
proofs are not promoted to authorized origins; no credential bytes are persisted.
Final outcomes retain the asynchronous recorder; opt-in release authorization is
separately broker-confirmed before dispatch.
Upgraded audit receivers are a rollout dependency; no production change is made.

Separate signed-origin credentials are consumed only alongside verified service
STS JWTs, using the existing issuer/JWKS and explicit service receiver. Legacy
proof-only routes retain single-audience fallback. Sender and original request
digest are checked; actual successful
tenant authz scope and subject must match the resource and signed sender. Validity
is checked again after throttle waits before cache/backend access. Proofs
on unsupported auth modes, platform-only/no tenant scopes or ambiguous audiences
fail closed. Incoming proof headers are consumed; opt-in forwarding supplies the
verified opaque parent only to trusted mTLS backends. STS authority is never
replaced by origin.

JWT and GET/POST session validators now adopt optional verified caller metadata,
reject envelope conflicts and origin-as-access JWTs, and clear forged gateway
headers. Session caches are capped by issuer expiry and the current route TTL.
Missing legacy metadata stays absent. Signed-origin and receipt behavior remains
opt-in; production configuration is not activated here.

W2 opaque API-key/MCP and universal grant validation preserve optional issuer
caller metadata after subject/credential binding checks. Malformed present
metadata fails closed and is not cached; legacy absence remains compatible.
The reserved gateway namespace is stripped before validation. Backend parsing
requires upgraded Core readers. Release confirmation requires upgraded ingest;
no production configuration is changed.

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
