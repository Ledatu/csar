package statestore

import (
	"context"
	"fmt"
	"sync"
)

// MemoryStore implements StateStore using in-memory maps.
// Suitable for development, testing, and single-instance deployments.
type MemoryStore struct {
	mu       sync.RWMutex
	routes   map[string]RouteEntry
	routers  map[string]RouterInfo
	quotas   map[string]*QuotaPolicy
	watchers []chan []RouteEntry
	closed   map[chan []RouteEntry]bool
}

// NewMemoryStore creates a new in-memory StateStore.
func NewMemoryStore() *MemoryStore {
	return &MemoryStore{
		routes:  make(map[string]RouteEntry),
		routers: make(map[string]RouterInfo),
		quotas:  make(map[string]*QuotaPolicy),
		closed:  make(map[chan []RouteEntry]bool),
	}
}

func (m *MemoryStore) GetRoutes(_ context.Context) ([]RouteEntry, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	routes := make([]RouteEntry, 0, len(m.routes))
	for _, r := range m.routes {
		routes = append(routes, r)
	}
	return routes, nil
}

func (m *MemoryStore) PutRoute(_ context.Context, route RouteEntry) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if route.ID == "" {
		return fmt.Errorf("route ID is required")
	}

	m.routes[route.ID] = route
	m.notifyWatchers()
	return nil
}

func (m *MemoryStore) DeleteRoute(_ context.Context, routeID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	delete(m.routes, routeID)
	m.notifyWatchers()
	return nil
}

func (m *MemoryStore) WatchRoutes(ctx context.Context) (<-chan []RouteEntry, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	ch := make(chan []RouteEntry, 16)
	m.watchers = append(m.watchers, ch)

	// Close channel when context is done
	go func() {
		<-ctx.Done()
		m.mu.Lock()
		defer m.mu.Unlock()
		for i, w := range m.watchers {
			if w == ch {
				m.watchers = append(m.watchers[:i], m.watchers[i+1:]...)
				break
			}
		}
		if !m.closed[ch] {
			m.closed[ch] = true
			close(ch)
		}
	}()

	return ch, nil
}

func (m *MemoryStore) RegisterRouter(_ context.Context, router RouterInfo) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if router.ID == "" {
		return fmt.Errorf("router ID is required")
	}

	m.routers[router.ID] = router
	return nil
}

func (m *MemoryStore) UnregisterRouter(_ context.Context, routerID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	delete(m.routers, routerID)
	return nil
}

func (m *MemoryStore) ListRouters(_ context.Context) ([]RouterInfo, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	routers := make([]RouterInfo, 0, len(m.routers))
	for _, r := range m.routers {
		routers = append(routers, r)
	}
	return routers, nil
}

func (m *MemoryStore) GetQuotaPolicy(_ context.Context, routeID string) (*QuotaPolicy, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	q, ok := m.quotas[routeID]
	if !ok {
		return nil, fmt.Errorf("quota policy for route %q not found", routeID)
	}
	return q, nil
}

func (m *MemoryStore) SetQuotaPolicy(_ context.Context, routeID string, policy *QuotaPolicy) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.quotas[routeID] = policy
	return nil
}

func (m *MemoryStore) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	for _, ch := range m.watchers {
		if !m.closed[ch] {
			m.closed[ch] = true
			close(ch)
		}
	}
	m.watchers = nil
	return nil
}

// notifyWatchers sends the current route list to all active watchers.
// Must be called with mu held.
func (m *MemoryStore) notifyWatchers() {
	routes := make([]RouteEntry, 0, len(m.routes))
	for _, r := range m.routes {
		routes = append(routes, r)
	}

	for _, ch := range m.watchers {
		select {
		case ch <- routes:
		default:
			// Drop if watcher is slow
		}
	}
}
