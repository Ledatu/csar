# Sprint 3: Distributed System (gRPC)

## Goal
Split into Coordinator (Control Plane) and Router (Data Plane) communicating via gRPC. Introduce QDB-style StateStore abstraction (inspired by SPQR).

## Tasks

### 3.1 StateStore interface + PostgreSQL implementation
- Create `internal/statestore/statestore.go` with the QDB-style interface
- Methods: GetRoutes, WatchRoutes, RegisterRouter, UnregisterRouter, ListRouters, GetQuotaPolicy, SetQuotaPolicy
- Create `internal/statestore/memory.go` (in-memory impl, already used in Sprint 1-2)
- Create `internal/statestore/postgres.go` (PostgreSQL impl using pgx)

### 3.2 Define `coordinator.proto` + gRPC server
- Create `proto/csar/v1/coordinator.proto`
- `rpc Subscribe(SubscribeRequest) returns (stream ConfigUpdate)` -- config push stream
- `rpc GetSecrets(SecretRequest) returns (SecretResponse)` -- on-demand secret fetch
- `rpc ReportHealth(HealthReport) returns (HealthAck)` -- router health reporting
- Messages for quota allocation, route config, secret distribution

### 3.3 Implement Coordinator gRPC server
- Rewrite `internal/coordinator/coordinator.go`
- gRPC server with Subscribe stream
- Track connected routers, assign quotas
- ConfigEngine: watch StateStore for changes, push hot-reload updates via stream
- Integrate with AuthService proto for secret fetching

### 3.4 Dynamic quota allocator
- Create `internal/coordinator/quota.go`
- Divide total RPS by active router count
- Push quota updates on router connect/disconnect
- Fair distribution with configurable strategies

### 3.5 Convert Router to stateless gRPC client
- Update `internal/router/router.go`
- On startup, connect to Coordinator via gRPC Subscribe
- Receive config, secrets, and quota assignments from stream
- Rebuild throttle limits dynamically when quota changes
- No local config file, no DB access, no KMS keys -- pure stateless

### 3.6 Separate entry points
- Create `cmd/csar-coordinator/main.go`
- Update `cmd/csar/main.go` for router-only mode
- Update Makefile to build both binaries

## Dependencies
- `google.golang.org/grpc`
- `google.golang.org/protobuf`
- `github.com/jackc/pgx/v5`

## Acceptance Criteria
- Coordinator starts, reads from StateStore, serves gRPC
- Router connects to Coordinator, receives config via stream
- Adding/removing routers dynamically redistributes RPS quotas
- StateStore is swappable (memory vs PostgreSQL)
