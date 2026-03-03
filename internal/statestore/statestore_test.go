package statestore

import (
	"context"
	"testing"
	"time"
)

func TestMemoryStore_Routes(t *testing.T) {
	s := NewMemoryStore()
	ctx := context.Background()

	// Empty initially
	routes, err := s.GetRoutes(ctx)
	if err != nil {
		t.Fatalf("GetRoutes: %v", err)
	}
	if len(routes) != 0 {
		t.Errorf("initial routes = %d, want 0", len(routes))
	}

	// Put a route
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

	// Update the route
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

	// Delete
	err = s.DeleteRoute(ctx, "GET:/api/v1")
	if err != nil {
		t.Fatalf("DeleteRoute: %v", err)
	}

	routes, _ = s.GetRoutes(ctx)
	if len(routes) != 0 {
		t.Errorf("routes after delete = %d, want 0", len(routes))
	}
}

func TestMemoryStore_Routes_EmptyID(t *testing.T) {
	s := NewMemoryStore()
	err := s.PutRoute(context.Background(), RouteEntry{})
	if err == nil {
		t.Error("PutRoute with empty ID should fail")
	}
}

func TestMemoryStore_WatchRoutes(t *testing.T) {
	s := NewMemoryStore()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	ch, err := s.WatchRoutes(ctx)
	if err != nil {
		t.Fatalf("WatchRoutes: %v", err)
	}

	// Add a route — watcher should receive notification
	s.PutRoute(ctx, RouteEntry{ID: "GET:/a", Path: "/a", Method: "GET", TargetURL: "http://a"})

	select {
	case routes := <-ch:
		if len(routes) != 1 {
			t.Errorf("watcher got %d routes, want 1", len(routes))
		}
	case <-time.After(time.Second):
		t.Fatal("watcher did not receive notification")
	}

	// Cancel context should close the channel
	cancel()
	time.Sleep(50 * time.Millisecond)

	_, ok := <-ch
	if ok {
		// Channel might have buffered items, drain and check
		for range ch {
		}
	}
}

func TestMemoryStore_Routers(t *testing.T) {
	s := NewMemoryStore()
	ctx := context.Background()

	// Register routers
	err := s.RegisterRouter(ctx, RouterInfo{
		ID:      "router-1",
		Address: "10.0.0.1:8080",
		Healthy: true,
	})
	if err != nil {
		t.Fatalf("RegisterRouter: %v", err)
	}

	err = s.RegisterRouter(ctx, RouterInfo{
		ID:      "router-2",
		Address: "10.0.0.2:8080",
		Healthy: true,
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

	// Unregister
	err = s.UnregisterRouter(ctx, "router-1")
	if err != nil {
		t.Fatalf("UnregisterRouter: %v", err)
	}

	routers, _ = s.ListRouters(ctx)
	if len(routers) != 1 {
		t.Errorf("routers after unregister = %d, want 1", len(routers))
	}
}

func TestMemoryStore_Routers_EmptyID(t *testing.T) {
	s := NewMemoryStore()
	err := s.RegisterRouter(context.Background(), RouterInfo{})
	if err == nil {
		t.Error("RegisterRouter with empty ID should fail")
	}
}

func TestMemoryStore_Quotas(t *testing.T) {
	s := NewMemoryStore()
	ctx := context.Background()

	// Set quota
	err := s.SetQuotaPolicy(ctx, "GET:/api", &QuotaPolicy{
		TotalRPS:   100,
		TotalBurst: 50,
		MaxWait:    30 * time.Second,
	})
	if err != nil {
		t.Fatalf("SetQuotaPolicy: %v", err)
	}

	// Get quota
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

	// Get nonexistent
	_, err = s.GetQuotaPolicy(ctx, "nonexistent")
	if err == nil {
		t.Error("GetQuotaPolicy for nonexistent route should fail")
	}
}
