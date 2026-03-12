package statestore

// PostgresStore placeholder — DEPRIORITIZED in favor of EtcdStore.
//
// After analysis, etcd is the preferred backend for coordinator state because:
//   - Data is pure KV (routes, routers, quotas) — no relational queries needed
//   - etcd Watch API maps directly to WatchRoutes (vs lossy LISTEN/NOTIFY)
//   - etcd leases auto-expire dead routers (vs manual heartbeat GC)
//   - Built-in Raft leader election if coordinator HA is needed
//   - SPQR (our design inspiration) uses etcd for the same purpose
//   - Data volume is <1 MB — well within etcd limits
//
// PostgresStore may still be useful later for audit logs, historical metrics,
// or other data that benefits from SQL queries. Keep the schema reference below
// in case it's needed alongside etcd.
//
// Schema (for reference, if ever needed):
//
//	CREATE TABLE csar_routes (
//	    id TEXT PRIMARY KEY,
//	    path TEXT NOT NULL,
//	    method TEXT NOT NULL,
//	    route_config JSONB NOT NULL,
//	    updated_at TIMESTAMPTZ DEFAULT NOW()
//	);
//
//	CREATE TABLE csar_routers (
//	    id TEXT PRIMARY KEY,
//	    address TEXT NOT NULL,
//	    last_heartbeat TIMESTAMPTZ,
//	    healthy BOOLEAN DEFAULT TRUE,
//	    metadata JSONB,
//	    updated_at TIMESTAMPTZ DEFAULT NOW()
//	);
//
//	CREATE TABLE csar_quotas (
//	    route_id TEXT PRIMARY KEY REFERENCES csar_routes(id),
//	    total_rps DOUBLE PRECISION NOT NULL,
//	    total_burst INT NOT NULL,
//	    max_wait INTERVAL,
//	    updated_at TIMESTAMPTZ DEFAULT NOW()
//	);
type PostgresStore struct {
	connString string
}

// NewPostgresStore creates a new PostgresStore.
// Deprioritized — see EtcdStore for the recommended production backend.
func NewPostgresStore(connString string) (*PostgresStore, error) {
	return &PostgresStore{
		connString: connString,
	}, nil
}
