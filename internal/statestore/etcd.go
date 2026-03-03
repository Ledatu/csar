package statestore

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	clientv3 "go.etcd.io/etcd/client/v3"
)

const (
	// Default key prefix in etcd.
	defaultPrefix = "/csar"

	// Key path segments.
	routeKeySegment  = "/routes/"
	routerKeySegment = "/routers/"
	quotaKeySegment  = "/quotas/"

	// Default lease TTL for router entries (seconds).
	defaultRouterLeaseTTL int64 = 30

	// Default dial timeout for etcd connection.
	defaultDialTimeout = 5 * time.Second
)

// EtcdConfig holds configuration for the etcd state store.
type EtcdConfig struct {
	// Endpoints is a list of etcd server endpoints (e.g. ["localhost:2379"]).
	Endpoints []string

	// Prefix is the key prefix for all CSAR keys (default: "/csar").
	Prefix string

	// RouterLeaseTTL is the lease TTL in seconds for router entries.
	// Router keys auto-expire if not refreshed within this period.
	// Default: 30.
	RouterLeaseTTL int64

	// DialTimeout is the timeout for establishing the etcd connection.
	// Default: 5s.
	DialTimeout time.Duration
}

// EtcdStore implements StateStore backed by etcd v3.
//
// Key layout:
//
//	/csar/routes/{id}       — JSON-encoded RouteEntry
//	/csar/routers/{id}      — JSON-encoded RouterInfo (with lease TTL)
//	/csar/quotas/{route_id} — JSON-encoded QuotaPolicy
//
// WatchRoutes uses etcd's native Watch API on the routes prefix.
// Router entries use etcd leases for automatic expiry of stale registrations.
type EtcdStore struct {
	client   *clientv3.Client
	prefix   string
	leaseTTL int64

	mu     sync.Mutex
	leases map[string]clientv3.LeaseID // routerID → leaseID
}

// NewEtcdStore creates a new EtcdStore connected to the given etcd cluster.
func NewEtcdStore(cfg EtcdConfig) (*EtcdStore, error) {
	if len(cfg.Endpoints) == 0 {
		return nil, fmt.Errorf("etcd endpoints are required")
	}

	prefix := cfg.Prefix
	if prefix == "" {
		prefix = defaultPrefix
	}

	ttl := cfg.RouterLeaseTTL
	if ttl <= 0 {
		ttl = defaultRouterLeaseTTL
	}

	dialTimeout := cfg.DialTimeout
	if dialTimeout <= 0 {
		dialTimeout = defaultDialTimeout
	}

	client, err := clientv3.New(clientv3.Config{
		Endpoints:   cfg.Endpoints,
		DialTimeout: dialTimeout,
	})
	if err != nil {
		return nil, fmt.Errorf("connecting to etcd: %w", err)
	}

	return &EtcdStore{
		client:   client,
		prefix:   prefix,
		leaseTTL: ttl,
		leases:   make(map[string]clientv3.LeaseID),
	}, nil
}

// --- key helpers ---

func (s *EtcdStore) routeKey(id string) string {
	return s.prefix + routeKeySegment + id
}

func (s *EtcdStore) routeKeyPrefix() string {
	return s.prefix + routeKeySegment
}

func (s *EtcdStore) routerKey(id string) string {
	return s.prefix + routerKeySegment + id
}

func (s *EtcdStore) routerKeyPrefix() string {
	return s.prefix + routerKeySegment
}

func (s *EtcdStore) quotaKey(routeID string) string {
	return s.prefix + quotaKeySegment + routeID
}

// --- Route configuration ---

func (s *EtcdStore) GetRoutes(ctx context.Context) ([]RouteEntry, error) {
	resp, err := s.client.Get(ctx, s.routeKeyPrefix(), clientv3.WithPrefix())
	if err != nil {
		return nil, fmt.Errorf("etcd get routes: %w", err)
	}

	routes := make([]RouteEntry, 0, len(resp.Kvs))
	for _, kv := range resp.Kvs {
		var r RouteEntry
		if err := json.Unmarshal(kv.Value, &r); err != nil {
			return nil, fmt.Errorf("unmarshal route %s: %w", string(kv.Key), err)
		}
		routes = append(routes, r)
	}
	return routes, nil
}

func (s *EtcdStore) PutRoute(ctx context.Context, route RouteEntry) error {
	if route.ID == "" {
		return fmt.Errorf("route ID is required")
	}

	data, err := json.Marshal(route)
	if err != nil {
		return fmt.Errorf("marshal route: %w", err)
	}

	_, err = s.client.Put(ctx, s.routeKey(route.ID), string(data))
	if err != nil {
		return fmt.Errorf("etcd put route: %w", err)
	}
	return nil
}

func (s *EtcdStore) DeleteRoute(ctx context.Context, routeID string) error {
	_, err := s.client.Delete(ctx, s.routeKey(routeID))
	if err != nil {
		return fmt.Errorf("etcd delete route: %w", err)
	}
	return nil
}

func (s *EtcdStore) WatchRoutes(ctx context.Context) (<-chan []RouteEntry, error) {
	ch := make(chan []RouteEntry, 16)

	go func() {
		defer close(ch)

		watchCh := s.client.Watch(ctx, s.routeKeyPrefix(), clientv3.WithPrefix())
		for {
			select {
			case <-ctx.Done():
				return
			case resp, ok := <-watchCh:
				if !ok {
					return
				}
				if resp.Err() != nil {
					// Watch error — channel will be re-established by the client.
					continue
				}

				// Fetch the full route list on any change (consistent with
				// MemoryStore which sends complete snapshots).
				routes, err := s.GetRoutes(ctx)
				if err != nil {
					continue // skip notification on transient errors
				}

				select {
				case ch <- routes:
				default:
					// Drop if consumer is slow (same as MemoryStore).
				}
			}
		}
	}()

	return ch, nil
}

// --- Router registry ---

func (s *EtcdStore) RegisterRouter(ctx context.Context, router RouterInfo) error {
	if router.ID == "" {
		return fmt.Errorf("router ID is required")
	}

	data, err := json.Marshal(router)
	if err != nil {
		return fmt.Errorf("marshal router: %w", err)
	}

	// Try to refresh an existing lease; create a new one if none exists or expired.
	leaseID, err := s.ensureLease(ctx, router.ID)
	if err != nil {
		return fmt.Errorf("etcd router lease: %w", err)
	}

	_, err = s.client.Put(ctx, s.routerKey(router.ID), string(data), clientv3.WithLease(leaseID))
	if err != nil {
		return fmt.Errorf("etcd put router: %w", err)
	}
	return nil
}

// ensureLease returns an active lease for the router, creating one if needed.
func (s *EtcdStore) ensureLease(ctx context.Context, routerID string) (clientv3.LeaseID, error) {
	s.mu.Lock()
	leaseID, hasLease := s.leases[routerID]
	s.mu.Unlock()

	if hasLease {
		// Try to keep the existing lease alive.
		_, err := s.client.KeepAliveOnce(ctx, leaseID)
		if err == nil {
			return leaseID, nil
		}
		// Lease expired or error — fall through to create a new one.
	}

	grant, err := s.client.Grant(ctx, s.leaseTTL)
	if err != nil {
		return 0, err
	}

	s.mu.Lock()
	s.leases[routerID] = grant.ID
	s.mu.Unlock()

	return grant.ID, nil
}

func (s *EtcdStore) UnregisterRouter(ctx context.Context, routerID string) error {
	_, err := s.client.Delete(ctx, s.routerKey(routerID))
	if err != nil {
		return fmt.Errorf("etcd delete router: %w", err)
	}

	s.mu.Lock()
	if leaseID, ok := s.leases[routerID]; ok {
		s.client.Revoke(ctx, leaseID) //nolint:errcheck
		delete(s.leases, routerID)
	}
	s.mu.Unlock()

	return nil
}

func (s *EtcdStore) ListRouters(ctx context.Context) ([]RouterInfo, error) {
	resp, err := s.client.Get(ctx, s.routerKeyPrefix(), clientv3.WithPrefix())
	if err != nil {
		return nil, fmt.Errorf("etcd get routers: %w", err)
	}

	routers := make([]RouterInfo, 0, len(resp.Kvs))
	for _, kv := range resp.Kvs {
		var r RouterInfo
		if err := json.Unmarshal(kv.Value, &r); err != nil {
			return nil, fmt.Errorf("unmarshal router %s: %w", string(kv.Key), err)
		}
		routers = append(routers, r)
	}
	return routers, nil
}

// --- Quota policies ---

func (s *EtcdStore) GetQuotaPolicy(ctx context.Context, routeID string) (*QuotaPolicy, error) {
	resp, err := s.client.Get(ctx, s.quotaKey(routeID))
	if err != nil {
		return nil, fmt.Errorf("etcd get quota: %w", err)
	}

	if len(resp.Kvs) == 0 {
		return nil, fmt.Errorf("quota policy for route %q not found", routeID)
	}

	var q QuotaPolicy
	if err := json.Unmarshal(resp.Kvs[0].Value, &q); err != nil {
		return nil, fmt.Errorf("unmarshal quota: %w", err)
	}
	return &q, nil
}

func (s *EtcdStore) SetQuotaPolicy(ctx context.Context, routeID string, policy *QuotaPolicy) error {
	data, err := json.Marshal(policy)
	if err != nil {
		return fmt.Errorf("marshal quota: %w", err)
	}

	_, err = s.client.Put(ctx, s.quotaKey(routeID), string(data))
	if err != nil {
		return fmt.Errorf("etcd put quota: %w", err)
	}
	return nil
}

// Close releases the etcd client connection.
func (s *EtcdStore) Close() error {
	return s.client.Close()
}
