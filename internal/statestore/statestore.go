package statestore

import (
	"context"
	"time"
)

// StateStore is the QDB-style abstraction for all Control Plane persistent state.
// Inspired by SPQR's qdb package — the interface can be backed by in-memory,
// etcd (recommended for production), PostgreSQL, or any other store.
type StateStore interface {
	// --- Route configuration ---

	// GetRoutes returns all configured routes.
	GetRoutes(ctx context.Context) ([]RouteEntry, error)

	// PutRoute creates or updates a route entry.
	PutRoute(ctx context.Context, route RouteEntry) error

	// DeleteRoute removes a route entry by its ID.
	DeleteRoute(ctx context.Context, routeID string) error

	// WatchRoutes returns a channel that emits the full route list on any change.
	WatchRoutes(ctx context.Context) (<-chan []RouteEntry, error)

	// --- Router registry ---

	// RegisterRouter registers a router instance in the cluster.
	RegisterRouter(ctx context.Context, router RouterInfo) error

	// UnregisterRouter removes a router instance from the cluster.
	UnregisterRouter(ctx context.Context, routerID string) error

	// ListRouters returns all registered router instances.
	ListRouters(ctx context.Context) ([]RouterInfo, error)

	// --- Quota policies ---

	// GetQuotaPolicy returns the quota policy for a given route.
	GetQuotaPolicy(ctx context.Context, routeID string) (*QuotaPolicy, error)

	// SetQuotaPolicy creates or updates a quota policy for a route.
	SetQuotaPolicy(ctx context.Context, routeID string, policy *QuotaPolicy) error

	// Close releases resources.
	Close() error
}

// RouteEntry represents a route stored in the state store.
type RouteEntry struct {
	// ID is the unique route identifier (e.g. "GET:/wb/v1/products").
	ID string

	// Path is the URL path pattern.
	Path string

	// Method is the HTTP method.
	Method string

	// TargetURL is the upstream backend URL.
	TargetURL string

	// Security settings (optional).
	Security *SecurityEntry

	// Traffic settings (optional).
	Traffic *TrafficEntry

	// Resilience settings (optional).
	ResilienceProfile string
}

// SecurityEntry holds security config for a route in the state store.
type SecurityEntry struct {
	KMSKeyID     string
	TokenRef     string
	InjectHeader string
	InjectFormat string
}

// TrafficEntry holds traffic shaping config for a route.
type TrafficEntry struct {
	RPS     float64
	Burst   int
	MaxWait time.Duration
}

// RouterInfo represents a registered router instance.
type RouterInfo struct {
	// ID is the unique router identifier.
	ID string

	// Address is the router's network address (host:port).
	Address string

	// LastHeartbeat is the time of the last health report.
	LastHeartbeat time.Time

	// Healthy indicates whether the router is currently healthy.
	Healthy bool

	// Metadata holds arbitrary key-value pairs.
	Metadata map[string]string
}

// QuotaPolicy defines the rate limit quota for a route.
type QuotaPolicy struct {
	// TotalRPS is the global RPS limit for the route across all routers.
	TotalRPS float64

	// TotalBurst is the global burst limit.
	TotalBurst int

	// MaxWait is the maximum queue wait time.
	MaxWait time.Duration
}
