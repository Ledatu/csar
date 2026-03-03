package statestore

import (
	"context"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	clientv3 "go.etcd.io/etcd/client/v3"
)

// etcdEndpoints returns the etcd endpoints to use for testing.
// Set ETCD_ENDPOINTS env var to override the default (localhost:2379).
func etcdEndpoints() []string {
	if ep := os.Getenv("ETCD_ENDPOINTS"); ep != "" {
		return strings.Split(ep, ",")
	}
	return []string{"localhost:2379"}
}

// skipIfNoEtcd skips the test if etcd is not reachable.
func skipIfNoEtcd(t *testing.T) []string {
	t.Helper()
	endpoints := etcdEndpoints()

	cli, err := clientv3.New(clientv3.Config{
		Endpoints:   endpoints,
		DialTimeout: 2 * time.Second,
	})
	if err != nil {
		t.Skipf("etcd not available (connect): %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	_, err = cli.Status(ctx, endpoints[0])
	cli.Close()
	if err != nil {
		t.Skipf("etcd not available (status): %v", err)
	}

	return endpoints
}

// newTestEtcdStore creates an EtcdStore with a unique prefix for test isolation.
func newTestEtcdStore(t *testing.T) *EtcdStore {
	t.Helper()
	endpoints := skipIfNoEtcd(t)

	prefix := fmt.Sprintf("/csar-test-%d", time.Now().UnixNano())

	s, err := NewEtcdStore(EtcdConfig{
		Endpoints:      endpoints,
		Prefix:         prefix,
		RouterLeaseTTL: 10,
		DialTimeout:    5 * time.Second,
	})
	if err != nil {
		t.Fatalf("NewEtcdStore: %v", err)
	}

	// Clean up prefix on test completion.
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		s.client.Delete(ctx, prefix, clientv3.WithPrefix())
		s.Close()
	})

	return s
}

func TestEtcdStore_Routes(t *testing.T) {
	s := newTestEtcdStore(t)
	ctx := context.Background()

	// Empty initially.
	routes, err := s.GetRoutes(ctx)
	if err != nil {
		t.Fatalf("GetRoutes: %v", err)
	}
	if len(routes) != 0 {
		t.Errorf("initial routes = %d, want 0", len(routes))
	}

	// Put a route.
	err = s.PutRoute(ctx, RouteEntry{
		ID:        "GET:/api/v1",
		Path:      "/api/v1",
		Method:    "GET",
		TargetURL: "http://localhost:3000",
		Traffic:   &TrafficEntry{RPS: 10, Burst: 5, MaxWait: 30 * time.Second},
	})
	if err != nil {
		t.Fatalf("PutRoute: %v", err)
	}

	routes, err = s.GetRoutes(ctx)
	if err != nil {
		t.Fatalf("GetRoutes: %v", err)
	}
	if len(routes) != 1 {
		t.Fatalf("routes = %d, want 1", len(routes))
	}
	if routes[0].TargetURL != "http://localhost:3000" {
		t.Errorf("TargetURL = %q", routes[0].TargetURL)
	}
	if routes[0].Traffic == nil {
		t.Fatal("Traffic is nil")
	}
	if routes[0].Traffic.RPS != 10 {
		t.Errorf("Traffic.RPS = %f, want 10", routes[0].Traffic.RPS)
	}

	// Update the route.
	err = s.PutRoute(ctx, RouteEntry{
		ID:        "GET:/api/v1",
		Path:      "/api/v1",
		Method:    "GET",
		TargetURL: "http://localhost:4000",
	})
	if err != nil {
		t.Fatalf("PutRoute update: %v", err)
	}

	routes, _ = s.GetRoutes(ctx)
	if routes[0].TargetURL != "http://localhost:4000" {
		t.Errorf("updated TargetURL = %q, want 4000", routes[0].TargetURL)
	}

	// Delete.
	err = s.DeleteRoute(ctx, "GET:/api/v1")
	if err != nil {
		t.Fatalf("DeleteRoute: %v", err)
	}

	routes, _ = s.GetRoutes(ctx)
	if len(routes) != 0 {
		t.Errorf("routes after delete = %d, want 0", len(routes))
	}
}

func TestEtcdStore_Routes_EmptyID(t *testing.T) {
	s := newTestEtcdStore(t)
	err := s.PutRoute(context.Background(), RouteEntry{})
	if err == nil {
		t.Error("PutRoute with empty ID should fail")
	}
}

func TestEtcdStore_Routes_WithSecurity(t *testing.T) {
	s := newTestEtcdStore(t)
	ctx := context.Background()

	err := s.PutRoute(ctx, RouteEntry{
		ID:        "GET:/secure",
		Path:      "/secure",
		Method:    "GET",
		TargetURL: "http://upstream:8080",
		Security: &SecurityEntry{
			KMSKeyID:     "key-123",
			TokenRef:     "my_token",
			InjectHeader: "Authorization",
			InjectFormat: "Bearer {token}",
		},
	})
	if err != nil {
		t.Fatalf("PutRoute: %v", err)
	}

	routes, err := s.GetRoutes(ctx)
	if err != nil {
		t.Fatalf("GetRoutes: %v", err)
	}
	if len(routes) != 1 {
		t.Fatalf("routes = %d, want 1", len(routes))
	}
	if routes[0].Security == nil {
		t.Fatal("Security is nil")
	}
	if routes[0].Security.KMSKeyID != "key-123" {
		t.Errorf("KMSKeyID = %q, want key-123", routes[0].Security.KMSKeyID)
	}
	if routes[0].Security.InjectFormat != "Bearer {token}" {
		t.Errorf("InjectFormat = %q", routes[0].Security.InjectFormat)
	}
}

func TestEtcdStore_WatchRoutes(t *testing.T) {
	s := newTestEtcdStore(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	ch, err := s.WatchRoutes(ctx)
	if err != nil {
		t.Fatalf("WatchRoutes: %v", err)
	}

	// Add a route — watcher should receive notification.
	err = s.PutRoute(ctx, RouteEntry{
		ID:        "GET:/a",
		Path:      "/a",
		Method:    "GET",
		TargetURL: "http://a",
	})
	if err != nil {
		t.Fatalf("PutRoute: %v", err)
	}

	select {
	case routes := <-ch:
		if len(routes) != 1 {
			t.Errorf("watcher got %d routes, want 1", len(routes))
		}
	case <-time.After(5 * time.Second):
		t.Fatal("watcher did not receive notification")
	}

	// Delete the route — watcher should receive notification.
	err = s.DeleteRoute(ctx, "GET:/a")
	if err != nil {
		t.Fatalf("DeleteRoute: %v", err)
	}

	select {
	case routes := <-ch:
		if len(routes) != 0 {
			t.Errorf("watcher got %d routes after delete, want 0", len(routes))
		}
	case <-time.After(5 * time.Second):
		t.Fatal("watcher did not receive delete notification")
	}

	// Cancel context should close the channel.
	cancel()
	time.Sleep(100 * time.Millisecond)

	// Drain any remaining items.
	for range ch {
	}
}

func TestEtcdStore_Routers(t *testing.T) {
	s := newTestEtcdStore(t)
	ctx := context.Background()

	// Register routers.
	err := s.RegisterRouter(ctx, RouterInfo{
		ID:            "router-1",
		Address:       "10.0.0.1:8080",
		LastHeartbeat: time.Now(),
		Healthy:       true,
		Metadata:      map[string]string{"zone": "us-east-1"},
	})
	if err != nil {
		t.Fatalf("RegisterRouter: %v", err)
	}

	err = s.RegisterRouter(ctx, RouterInfo{
		ID:            "router-2",
		Address:       "10.0.0.2:8080",
		LastHeartbeat: time.Now(),
		Healthy:       true,
	})
	if err != nil {
		t.Fatalf("RegisterRouter: %v", err)
	}

	routers, err := s.ListRouters(ctx)
	if err != nil {
		t.Fatalf("ListRouters: %v", err)
	}
	if len(routers) != 2 {
		t.Errorf("routers = %d, want 2", len(routers))
	}

	// Check metadata roundtrip.
	for _, r := range routers {
		if r.ID == "router-1" {
			if r.Metadata["zone"] != "us-east-1" {
				t.Errorf("router-1 metadata zone = %q, want us-east-1", r.Metadata["zone"])
			}
		}
	}

	// Unregister.
	err = s.UnregisterRouter(ctx, "router-1")
	if err != nil {
		t.Fatalf("UnregisterRouter: %v", err)
	}

	routers, _ = s.ListRouters(ctx)
	if len(routers) != 1 {
		t.Errorf("routers after unregister = %d, want 1", len(routers))
	}
}

func TestEtcdStore_Routers_EmptyID(t *testing.T) {
	s := newTestEtcdStore(t)
	err := s.RegisterRouter(context.Background(), RouterInfo{})
	if err == nil {
		t.Error("RegisterRouter with empty ID should fail")
	}
}

func TestEtcdStore_Routers_HeartbeatRefreshesLease(t *testing.T) {
	s := newTestEtcdStore(t)
	ctx := context.Background()

	// Register a router — creates a lease.
	err := s.RegisterRouter(ctx, RouterInfo{
		ID:      "router-hb",
		Address: "10.0.0.1:8080",
		Healthy: true,
	})
	if err != nil {
		t.Fatalf("RegisterRouter: %v", err)
	}

	s.mu.Lock()
	firstLease := s.leases["router-hb"]
	s.mu.Unlock()

	if firstLease == 0 {
		t.Fatal("expected a lease to be created")
	}

	// Re-register (heartbeat) — should reuse the same lease.
	err = s.RegisterRouter(ctx, RouterInfo{
		ID:      "router-hb",
		Address: "10.0.0.1:8080",
		Healthy: true,
	})
	if err != nil {
		t.Fatalf("RegisterRouter heartbeat: %v", err)
	}

	s.mu.Lock()
	secondLease := s.leases["router-hb"]
	s.mu.Unlock()

	if secondLease != firstLease {
		t.Errorf("lease changed on heartbeat: %d → %d", firstLease, secondLease)
	}
}

func TestEtcdStore_Quotas(t *testing.T) {
	s := newTestEtcdStore(t)
	ctx := context.Background()

	// Set quota.
	err := s.SetQuotaPolicy(ctx, "GET:/api", &QuotaPolicy{
		TotalRPS:   100,
		TotalBurst: 50,
		MaxWait:    30 * time.Second,
	})
	if err != nil {
		t.Fatalf("SetQuotaPolicy: %v", err)
	}

	// Get quota.
	q, err := s.GetQuotaPolicy(ctx, "GET:/api")
	if err != nil {
		t.Fatalf("GetQuotaPolicy: %v", err)
	}
	if q.TotalRPS != 100 {
		t.Errorf("TotalRPS = %f, want 100", q.TotalRPS)
	}
	if q.TotalBurst != 50 {
		t.Errorf("TotalBurst = %d, want 50", q.TotalBurst)
	}
	if q.MaxWait != 30*time.Second {
		t.Errorf("MaxWait = %v, want 30s", q.MaxWait)
	}

	// Get nonexistent.
	_, err = s.GetQuotaPolicy(ctx, "nonexistent")
	if err == nil {
		t.Error("GetQuotaPolicy for nonexistent route should fail")
	}
}

func TestEtcdStore_MultipleRoutes(t *testing.T) {
	s := newTestEtcdStore(t)
	ctx := context.Background()

	// Add multiple routes.
	for i := range 5 {
		err := s.PutRoute(ctx, RouteEntry{
			ID:        fmt.Sprintf("GET:/api/v%d", i),
			Path:      fmt.Sprintf("/api/v%d", i),
			Method:    "GET",
			TargetURL: fmt.Sprintf("http://upstream:%d", 8080+i),
		})
		if err != nil {
			t.Fatalf("PutRoute %d: %v", i, err)
		}
	}

	routes, err := s.GetRoutes(ctx)
	if err != nil {
		t.Fatalf("GetRoutes: %v", err)
	}
	if len(routes) != 5 {
		t.Errorf("routes = %d, want 5", len(routes))
	}

	// Delete one.
	err = s.DeleteRoute(ctx, "GET:/api/v2")
	if err != nil {
		t.Fatalf("DeleteRoute: %v", err)
	}

	routes, _ = s.GetRoutes(ctx)
	if len(routes) != 4 {
		t.Errorf("routes after delete = %d, want 4", len(routes))
	}
}
