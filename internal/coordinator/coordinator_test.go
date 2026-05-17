package coordinator

import (
	"context"
	"io"
	"log/slog"
	"net"
	"testing"
	"time"

	"github.com/ledatu/csar-core/configutil"
	"github.com/ledatu/csar/internal/config"
	"github.com/ledatu/csar/internal/protoconv"
	csarv1 "github.com/ledatu/csar/proto/csar/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	"github.com/ledatu/csar/internal/statestore"
)

func newTestLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// testEnv sets up a coordinator gRPC server and returns a client + cleanup func.
func testEnv(t *testing.T) (csarv1.CoordinatorServiceClient, *Coordinator, func()) {
	t.Helper()

	store := statestore.NewMemoryStore()
	coord := New(store, newTestLogger())

	// Seed routes with full config.
	err := store.PutRoute(context.Background(), statestore.RouteEntry{
		ID:     "GET:/api/v1",
		Path:   "/api/v1",
		Method: "GET",
		Route: config.RouteConfig{
			Backend: config.BackendConfig{TargetURL: "http://upstream:8080"},
			Traffic: &config.TrafficConfig{
				RPS:     100,
				Burst:   50,
				MaxWait: configutil.Duration{Duration: 30 * time.Second},
			},
		},
	})
	if err != nil {
		t.Fatalf("PutRoute: %v", err)
	}

	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

	srv := grpc.NewServer()
	csarv1.RegisterCoordinatorServiceServer(srv, coord)

	go srv.Serve(lis) //nolint:errcheck // test server

	conn, err := grpc.NewClient(
		lis.Addr().String(),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}

	client := csarv1.NewCoordinatorServiceClient(conn)

	cleanup := func() {
		conn.Close()
		srv.GracefulStop()
		lis.Close()
		store.Close()
	}

	return client, coord, cleanup
}

func TestCoordinator_Subscribe_ReceivesFullConfigSnapshot(t *testing.T) {
	client, _, cleanup := testEnv(t)
	defer cleanup()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	stream, err := client.Subscribe(ctx, &csarv1.SubscribeRequest{
		RouterId:      "router-test-1",
		RouterAddress: "127.0.0.1:9000",
	})
	if err != nil {
		t.Fatalf("Subscribe: %v", err)
	}

	// First message should be a FullConfigSnapshot.
	msg, err := stream.Recv()
	if err != nil {
		t.Fatalf("Recv: %v", err)
	}

	snapshot := msg.GetFullConfigSnapshot()
	if snapshot == nil {
		t.Fatal("expected FullConfigSnapshot, got different update type")
	}

	if len(snapshot.Routes) != 1 {
		t.Fatalf("routes = %d, want 1", len(snapshot.Routes))
	}

	r := snapshot.Routes[0]
	if r.RouteId != "GET:/api/v1" {
		t.Errorf("RouteId = %q", r.RouteId)
	}
	if r.TargetUrl != "http://upstream:8080" {
		t.Errorf("TargetUrl = %q", r.TargetUrl)
	}
	if r.Backend == nil {
		t.Fatal("Backend is nil")
	}
	if r.Backend.TargetUrl != "http://upstream:8080" {
		t.Errorf("Backend.TargetUrl = %q", r.Backend.TargetUrl)
	}
	if r.TrafficConfig == nil {
		t.Fatal("TrafficConfig is nil")
	}
	if r.TrafficConfig.Rps != 100 {
		t.Errorf("RPS = %f, want 100", r.TrafficConfig.Rps)
	}
}

func TestCoordinator_Subscribe_ReceivesQuota(t *testing.T) {
	client, _, cleanup := testEnv(t)
	defer cleanup()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	stream, err := client.Subscribe(ctx, &csarv1.SubscribeRequest{
		RouterId:      "router-test-1",
		RouterAddress: "127.0.0.1:9000",
	})
	if err != nil {
		t.Fatalf("Subscribe: %v", err)
	}

	// First message: FullConfigSnapshot
	_, err = stream.Recv()
	if err != nil {
		t.Fatalf("Recv 1: %v", err)
	}

	// Second message: QuotaAssignment
	msg, err := stream.Recv()
	if err != nil {
		t.Fatalf("Recv 2: %v", err)
	}

	quota := msg.GetQuotaAssignment()
	if quota == nil {
		t.Fatal("expected QuotaAssignment, got different update type")
	}

	rq, ok := quota.Quotas["GET:/api/v1"]
	if !ok {
		t.Fatal("missing quota for GET:/api/v1")
	}

	if rq.Rps != 100 {
		t.Errorf("allocated RPS = %f, want 100", rq.Rps)
	}
}

func TestCoordinator_Subscribe_EmptyRouterID(t *testing.T) {
	client, _, cleanup := testEnv(t)
	defer cleanup()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	stream, err := client.Subscribe(ctx, &csarv1.SubscribeRequest{
		RouterId: "",
	})
	if err != nil {
		t.Fatalf("Subscribe: %v", err)
	}

	_, err = stream.Recv()
	if err == nil {
		t.Fatal("should fail with empty router_id")
	}
}

func TestCoordinator_ReportHealth(t *testing.T) {
	client, _, cleanup := testEnv(t)
	defer cleanup()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	ack, err := client.ReportHealth(ctx, &csarv1.HealthReport{
		RouterId: "router-test-1",
		Healthy:  true,
		QueueDepths: map[string]int64{
			"GET:/api/v1": 42,
		},
	})
	if err != nil {
		t.Fatalf("ReportHealth: %v", err)
	}

	if !ack.Acknowledged {
		t.Error("health report not acknowledged")
	}
}

func TestCoordinator_ReportHealth_EmptyID(t *testing.T) {
	client, _, cleanup := testEnv(t)
	defer cleanup()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	_, err := client.ReportHealth(ctx, &csarv1.HealthReport{
		RouterId: "",
	})
	if err == nil {
		t.Fatal("should fail with empty router_id")
	}
}

func TestCoordinator_SubscriberCount(t *testing.T) {
	client, coord, cleanup := testEnv(t)
	defer cleanup()

	if coord.SubscriberCount() != 0 {
		t.Fatalf("initial subscribers = %d, want 0", coord.SubscriberCount())
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	stream, err := client.Subscribe(ctx, &csarv1.SubscribeRequest{
		RouterId:      "router-1",
		RouterAddress: "127.0.0.1:9000",
	})
	if err != nil {
		t.Fatalf("Subscribe: %v", err)
	}

	// Drain the initial messages
	stream.Recv() //nolint:errcheck // drain initial snapshot
	stream.Recv() //nolint:errcheck // drain initial quota

	time.Sleep(100 * time.Millisecond)

	deadline := time.After(2 * time.Second)
	for coord.SubscriberCount() != 1 {
		select {
		case <-deadline:
			t.Fatalf("subscriber count = %d, want 1", coord.SubscriberCount())
		default:
			time.Sleep(20 * time.Millisecond)
		}
	}
}

func TestRouteEntryToProto_PreservesAuditAndCacheInvalidate(t *testing.T) {
	auditFalse := false
	entry := statestore.RouteEntry{
		ID:     "POST:/svc/s3",
		Path:   "/svc/s3",
		Method: "POST",
		Route: config.RouteConfig{
			Backend: config.BackendConfig{TargetURL: "https://s3:8087"},
			Audit:   &auditFalse,
			CacheInvalidate: &config.CacheInvalidationConfig{
				Tags: []string{"t1"},
			},
		},
	}

	pb := routeEntryToProto(&entry)
	if !pb.AuditSet || pb.Audit {
		t.Fatalf("audit wire: AuditSet=%v Audit=%v, want true,false", pb.AuditSet, pb.Audit)
	}
	if pb.CacheInvalidate == nil || len(pb.CacheInvalidate.Tags) != 1 || pb.CacheInvalidate.Tags[0] != "t1" {
		t.Fatalf("cache_invalidate = %v", pb.CacheInvalidate)
	}
}

func TestCacheConfigFullSnapshotRoundTrip(t *testing.T) {
	enabled := true
	want := &config.CacheConfig{
		Enabled:              &enabled,
		Store:                "redis",
		Key:                  "k:{tenant}",
		TTL:                  configutil.Duration{Duration: time.Minute},
		TTLJitter:            "10%",
		MaxEntries:           2048,
		MaxBodySize:          2 << 20,
		Methods:              []string{"GET"},
		Namespaces:           []string{"ns:{tenant}"},
		Tags:                 []string{"tag:{path.id}"},
		VaryHeaders:          []string{"Accept-Language"},
		CacheStatuses:        []string{"200", "2xx"},
		OperationTimeout:     configutil.Duration{Duration: 50 * time.Millisecond},
		FailMode:             "bypass",
		StaleIfError:         configutil.Duration{Duration: 30 * time.Second},
		StaleWhileRevalidate: configutil.Duration{Duration: 5 * time.Second},
		ContentTypes:         []string{"application/json"},
		TTLRules: []config.CacheTTLRule{
			{
				When: "query.date_range_contains_today",
				From: "a",
				To:   "b",
				TTL:  configutil.Duration{Duration: 2 * time.Minute},
			},
		},
		KeyQuery: &config.CacheKeyQueryConfig{
			Include: []string{"q"},
			Sort:    true,
		},
		ResponseTTLRules: []config.CacheResponseTTLRule{
			{
				When:   "header_equals",
				Header: "x",
				Value:  "y",
				TTL:    configutil.Duration{Duration: time.Hour},
			},
		},
		ResponseTags: []config.CacheResponseTag{
			{Header: "ETag", Prefix: "e:"},
		},
		Bypass: &config.CacheBypassConfig{
			Headers: []config.CacheBypassHeader{
				{Name: "X-Bypass", Value: "1", RequireGatewayScope: "cache.bypass"},
			},
		},
		Coalesce: &config.CacheCoalesceConfig{
			Enabled:           true,
			Wait:              configutil.Duration{Duration: 100 * time.Millisecond},
			WaitTimeoutStatus: 504,
		},
	}

	snap := &csarv1.FullConfigSnapshot{
		Routes: []*csarv1.RouteConfig{
			{
				Path:    "/api/x",
				Method:  "GET",
				Backend: &csarv1.BackendConfigProto{TargetUrl: "http://upstream"},
				Cache:   cacheToProto(want),
			},
		},
	}

	cfg := protoconv.FullSnapshotToConfig(snap)
	rt, ok := cfg.Paths["/api/x"]["get"]
	if !ok {
		t.Fatal("expected route /api/x GET")
	}
	if rt.Cache == nil {
		t.Fatal("expected Cache on route")
	}
	got := rt.Cache

	if got.Store != want.Store || got.Key != want.Key || got.FailMode != want.FailMode || got.TTLJitter != want.TTLJitter {
		t.Fatalf("scalar fields: got %+v", got)
	}
	if got.TTL.Duration != want.TTL.Duration || got.OperationTimeout.Duration != want.OperationTimeout.Duration {
		t.Fatalf("durations: ttl=%v op=%v", got.TTL, got.OperationTimeout)
	}
	if got.MaxEntries != want.MaxEntries || got.MaxBodySize != want.MaxBodySize {
		t.Fatalf("limits: %+v", got)
	}
	if len(got.Methods) != 1 || got.Methods[0] != "GET" {
		t.Fatalf("methods: %v", got.Methods)
	}
	if len(got.Namespaces) != 1 || len(got.Tags) != 1 || len(got.VaryHeaders) != 1 || len(got.CacheStatuses) != 2 {
		t.Fatalf("slices: ns=%v tags=%v vary=%v cs=%v", got.Namespaces, got.Tags, got.VaryHeaders, got.CacheStatuses)
	}
	if len(got.TTLRules) != 1 || got.TTLRules[0].When != want.TTLRules[0].When || got.TTLRules[0].TTL.Duration != want.TTLRules[0].TTL.Duration {
		t.Fatalf("ttl rules: %+v", got.TTLRules)
	}
	if got.KeyQuery == nil || !got.KeyQuery.Sort || len(got.KeyQuery.Include) != 1 {
		t.Fatalf("key_query: %+v", got.KeyQuery)
	}
	if got.StaleIfError.Duration != want.StaleIfError.Duration || got.StaleWhileRevalidate.Duration != want.StaleWhileRevalidate.Duration {
		t.Fatalf("stale: %+v %+v", got.StaleIfError, got.StaleWhileRevalidate)
	}
	if len(got.ContentTypes) != 1 || got.ContentTypes[0] != "application/json" {
		t.Fatalf("content types: %v", got.ContentTypes)
	}
	if len(got.ResponseTTLRules) != 1 || got.ResponseTTLRules[0].TTL.Duration != want.ResponseTTLRules[0].TTL.Duration {
		t.Fatalf("response ttl rules: %+v", got.ResponseTTLRules)
	}
	if len(got.ResponseTags) != 1 || got.ResponseTags[0].Header != "ETag" {
		t.Fatalf("response tags: %+v", got.ResponseTags)
	}
	if got.Bypass == nil || len(got.Bypass.Headers) != 1 || got.Bypass.Headers[0].RequireGatewayScope != "cache.bypass" {
		t.Fatalf("bypass: %+v", got.Bypass)
	}
	if got.Coalesce == nil || !got.Coalesce.Enabled || got.Coalesce.WaitTimeoutStatus != 504 {
		t.Fatalf("coalesce: %+v", got.Coalesce)
	}
	if got.Coalesce.Wait.Duration != want.Coalesce.Wait.Duration {
		t.Fatalf("coalesce wait: %v", got.Coalesce.Wait)
	}
	if got.Enabled == nil || !*got.Enabled {
		t.Fatalf("enabled: %v", got.Enabled)
	}
}
