# Stored credential lifetime and invalidation

With `--stored-token-coherence=true`, stored S3 credentials use inspected lifetime
and exact-ref control-plane state rather than a minute-based S3 download. The
default is false to permit a coordinated reader/writer upgrade. Production mode
requires shared etcd and trusted-router mTLS. Memory state is development-only.

Any credential owner can supply optional `expires_at` for a stored opaque value
through the token API. The coordinator persists it in the shared
`csar-core/s3store.TokenObject`; copying a value preserves its metadata. Owners
inspect provider-specific lifetime outside CSAR. Token refs are arbitrary valid
namespaces: no seller ID, marketplace category, Campaigns API or Aurum convention
is required. Static credentials without expiry remain explicitly unknown.
Neither S3 storage nor injection inspects JWT-looking values to infer lifetime
or authenticity. Minted tokens keep their separate soft refresh/hard expiry policy.

This implementation activates coherence for the existing S3 backend and shared
etcd metadata store. Its storage interfaces are generic, but this does not claim
coherence is already implemented for every other token backend.

## Request path

Every credential request validates only its ref's linearizable etcd revision.
Warm stored values need no S3 IO until an actual mutation, rejection or deadline.
A second metadata check before returning a stored value fences races with local
admin cache updates. This intentionally trades small exact-key etcd reads for
correctness during watch loss; etcd failure fails closed. Watches push eviction
hints to connected routers, but reconnect, dropped hints and compaction cannot
make a cache entry authoritative. Watches never list S3 or prefetch idle refs.

Within one minute of inspected expiry, demand can check for a replacement, at
most once per five seconds per coordinator. A value within 30 seconds of expiry
cannot be issued by the coordinator. An unchanged expired value fails closed. Fetches coalesce
per ref and have a five-second deadline (existing mint timeout widening remains
independent). Failed stored validations have a five-second demand retry delay;
a committed owner rotation clears the old failure immediately through revision
change. ETags are opaque versions, never ordered generations.

## Early provider rejection

Automatic rejection handling is disabled by default, independently of stored-token
coherence. Opt in only where the application contract says an upstream 401 rejects
the injected credential:

```sh
csar --credential-rejection-route 'POST:/v2/jobs/{tenant_id}'
```

The flag is repeatable and selects exact `METHOD:/configured/path` keys, including
the configured path pattern. Startup and route-table reload require each key to
resolve to exactly one route with one injected credential entry. Invalid, absent,
duplicate, ambiguous and multi-credential selections are rejected. The injector
must support rejection feedback. An omitted selection never creates or consults
local quarantine and never reports a 401. For embedded use, the corresponding
explicit setting is `AuthInjectorConfig.RejectOnUnauthorized`.

A generic route could inject ref `apps/reporting/{path.tenant_id}/remote_key` into
`X-Remote-Key`, or use an opaque bearer value in `Authorization`. This policy does
not infer credential validity from a provider name, URL, JWT shape, arbitrary 403,
or a 401 on an unrelated route. Multi-credential APIs continue ordinary injection
without automatic attribution to every ref. A selected route must have unambiguous
rejection semantics; a shared ref's durable rejection affects all uses of that ref.

On an opted-in route, only a real reverse-proxy upstream 401 triggers a report.
Client-supplied headers, CSAR/STS authentication refusals and locally generated
401s are not provenance.
The router reports the exact injected ref, object version and SHA-256 fingerprint
of the high-entropy credential value through `csar.credential.v1.CredentialService`.
The service shares the existing coordinator mTLS peer checks and router allowlist.
No token is included in the report or etcd state. Fingerprints must not be logged.

The coordinator conditionally quarantines that value. A delayed old-version 401
cannot reject a different replacement. Rewriting the same value, changing its
expiry metadata or re-encrypting it does not clear rejection. A pending mutation
or failed compare-and-swap is retried without claiming a matching rejection was
durably published. Replacement checks read only the requested S3 ref. An unchanged,
absent or invalid credential fails closed rather than causing another vendor call.
Copying a rejected source through the owner API is refused.

The router also quarantines the value locally before reporting it. Reports
coalesce, and unavailable reports retry only on demand after five seconds. This
prevents repeated upstream failures while the report RPC is unavailable. Pending
reports never expire into vendor retries; acknowledged local entries can be
reclaimed after five minutes under capacity pressure. Local rejection storage is
bounded to 10,000 entries; exhausted capacity fails closed. `serve_stale` is not
used by coordinator-backed injectors, so it cannot bypass rejection or expiry.

The original upstream failure is returned. Recovery never automatically replays
an external action, including POST, and never generates a replacement stored credential. A later request can use a
replacement stored by the owner. Mint descriptors are left to
their existing lifetime policy rather than treated as stored bearer values.

## Mutation integrity and unknown outcomes

All admin PUT/rotate/delete and service PUT/copy/delete go through
`CoherentTokenStore`. A CAS establishes a per-ref pending fence before the S3
mutation; successful publication clears the fence and advances its revision.
Concurrent mutations do not overlap. Rejection reports use CAS and cannot
overwrite a newer owner mutation. In-flight reads cannot populate an older cache
over a rotation or deletion. Explicit admin invalidation advances the same ref
metadata without clearing a provider rejection.

S3 and etcd are not one transaction. A failed/lost object receipt or failed final
publication returns HTTP 503 with `credential_mutation_outcome_unknown` and keeps
the durable pending fence. It does not report success or automatically clear a
fence on timeout. Retrying the mutation while fenced returns pending without
another S3 write. Resolving an unknown outcome is an explicit operator action:
quiesce the exact writer/ref, establish that the old operation has terminated,
verify the intended authoritative S3 version through the owner, and reconcile
that exact pending operation/revision using CAS. Do not delete metadata, clear
all refs or disable coherence as a repair shortcut. Preserve rejection identity
when reconciling. No production repair is performed by these source changes.

## Upgrade and legacy objects

1. Publish the shared storage and credential protobuf dependencies, then build
   matching coordinator/router readers. Deploy all coordinator writers with
   coherence disabled initially; routers may be upgraded before activation.
2. Quiesce token mutations, enable coherence on every coordinator sharing the
   same etcd prefix, verify health and exact-ref mutation propagation, then resume
   owner writes. Do not leave an active old writer or direct S3 writer: those
   cannot publish the required fence/invalidation.
3. Existing objects without `expires_at` remain legacy/unknown. Use the relevant
   credential owner's reconciliation to add inspected deadlines before claiming
   expiry enforcement for those values. There is no migration scan or secret
   rewrite on startup. Unknown-expiry values still get mutation protection, plus
   401 protection on explicitly selected routes.
4. Enable `--credential-rejection-route` on each intended router only after the
   coordinator's rejection RPC is available. The selection is application policy,
   not an implicit consequence of using a coordinator or of enabling coherence.
5. Keep readers upgraded when publishing expiry metadata. Rollback requires the
   same mutation quiescence and pending-operation reconciliation; do not roll
   back to readers which ignore an unresolved pending fence or rejection.

`--stored-token-refresh-interval` continues to govern legacy mode only. Activation
and production deployment are separate from implementing and testing this feature.
