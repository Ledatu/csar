# Sprint 2: Security and KMS

## Goal
Encrypted API key storage, KMS integration, in-memory cache with TTL, and proto-based AuthService for pluggable token sources. Configurable header injection per route.

## Tasks

### 2.1 Define `auth.proto` AuthService contract
- Create `proto/csar/v1/auth.proto`
- `service AuthService { rpc GetEncryptedToken(...); rpc ListTokenRefs(...); }`
- Any external system can implement this contract
- Provide a local file-based reference implementation for dev/testing

### 2.2 Implement Local KMS provider (for dev/testing)
- Create `internal/kms/local.go` implementing `Provider` interface
- AES-256-GCM encryption using a local master key
- Key derivation from a passphrase for dev convenience

### 2.3 Implement Yandex Cloud KMS provider
- Create `internal/kms/yandex.go`
- Use `github.com/yandex-cloud/go-sdk` for KMS Encrypt/Decrypt
- Envelope encryption: generate DEK locally, wrap with KMS KEK

### 2.4 In-memory key cache with TTL and Singleflight
- Create `internal/kms/cache.go`
- Wraps any `Provider` as a caching decorator
- TTL-based expiration (configurable)
- `golang.org/x/sync/singleflight` to prevent thundering herd on cache miss

### 2.5 Configurable auth injection middleware
- Implement `pkg/middleware/auth.go`
- Route config specifies: `inject_header`, `inject_format`, `token_ref`, `kms_key_id`
- Fetch encrypted blob via AuthService, decrypt via KMS cache
- Inject decrypted token into upstream request header using configurable format
- Zero-State: router never persists secrets to disk

## Dependencies
- `github.com/yandex-cloud/go-sdk`
- `golang.org/x/sync`
- `google.golang.org/grpc` (for AuthService proto)
- `google.golang.org/protobuf`

## Acceptance Criteria
- Local KMS provider encrypts/decrypts correctly
- Auth middleware injects tokens into configurable headers
- Cache prevents redundant KMS calls (singleflight)
- AuthService proto compiles and a local implementation works
