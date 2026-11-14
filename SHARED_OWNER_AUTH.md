# Shared owner authentication

`mode: select` chooses one terminal authentication policy by credential location:

```yaml
auth_validate_policies:
  owner-read:
    mode: select
    methods: [seller-key, browser-session, service-reader]
```

The referenced policies use existing token, session and JWT validators. Personal
keys use Authorization, STS uses X-Csar-Authorization by default, and sessions
use the policy's named cookie. Distinct locations are required; 2..3 methods are
allowed. Nested selectors, duplicate sources and mixed selector/validator options
are rejected. Session token issuance is not supported inside a selector.

Exactly one credential must be presented. Duplicate headers/cookies, conflicting
credential types, unsupported authorization headers and missing credentials fail
closed. A malformed/expired/unavailable selected credential is never retried as a
session or another credential. After success, Authorization, X-Csar-Authorization
and Cookie are removed before authorization/proxying. Gateway headers are stripped
before validation as on existing routes. Authz, cache and throttle remain after
authentication, and all callers require the route's explicit permission.

Existing single-mode policies retain their behavior. The coordinator's existing
AuthValidateConfigProto gains additive field 21 (methods); both snapshot directions
and named policy maps preserve it. Deploy compatible router/coordinator binaries
before enabling selector configs; old validators reject the new mode. No existing
wire message is relocated by this additive change.

JWT policies with several audiences accept any configured value after signature,
issuer and expiry checks. This permits a narrowly authorized compatibility audience
without removing audience checks. A token's audience is not an authorization grant.
