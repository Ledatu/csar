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
