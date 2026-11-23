package coordinator

import (
	"context"
	"io"
	"testing"
	"time"

	"github.com/ledatu/csar/internal/statestore"
	csarv1 "github.com/ledatu/csar/proto/csar/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestDrainEndsExistingSubscriptionAndRejectsNewOnes(t *testing.T) {
	client, coord, cleanup := testEnv(t)
	defer cleanup()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	stream, err := client.Subscribe(ctx, &csarv1.SubscribeRequest{RouterId: "drain-existing"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := stream.Recv(); err != nil {
		t.Fatal(err)
	}
	coord.Drain()
	coord.Drain() // repeated signals/callers must not panic
	for {
		_, err := stream.Recv()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("draining subscription: %v", err)
		}
	}
	if got := coord.SubscriberCount(); got != 0 {
		t.Fatalf("subscribers after drain = %d", got)
	}
	stream, err = client.Subscribe(ctx, &csarv1.SubscribeRequest{RouterId: "drain-new"})
	if err == nil {
		_, err = stream.Recv()
	}
	if status.Code(err) != codes.Unavailable {
		t.Fatalf("new subscription error = %v", err)
	}
}

func TestDrainInterruptsSnapshotDebounce(t *testing.T) {
	_, coord, cleanup := testEnv(t)
	defer cleanup()
	coord.SetSnapshotDebounce(time.Hour)
	coord.Drain()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if coord.waitForQuietRoutes(ctx, make(chan []statestore.RouteEntry), make(chan struct{})) {
		t.Fatal("drained coordinator continued snapshot debounce")
	}
	if ctx.Err() != nil {
		t.Fatal("drain waited until caller timeout")
	}
}
