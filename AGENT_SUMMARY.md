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
- `x-csar-authz` policies gate routes before proxying.
- `gatewayctx` is the trusted identity carrier for backends, but it is only safe
  when paired with mTLS, `TrustedMiddleware`, or equivalent network isolation.
- Coordinator admin access is mTLS-protected and profile-guarded.

## Critical Flows
- Request pipeline order matters: authn, authz, throttling, circuit breaking,
  retry/backpressure, response shaping, and proxying.
- Config loading supports file, S3, and HTTP sources with profile validation.
- KMS-backed token injection and coordinator-driven quota/token sync are core
  prod flows.
- Readiness and health sidecars are part of the operational contract.

## Config And Secrets
- `profile:` and `ValidateResolvedKMSProvider` are security-critical; the runtime
  KMS provider must match the active deployment profile.
- `tls`, `coordinator`, `authz`, `audit`, and token source settings are the
  main trust-sensitive knobs.
- `configsource` / manifest-backed inputs should be treated as untrusted until
  validated.

## Audit Hotspots
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
