package coordclient

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"reflect"
	"testing"
	"time"

	"github.com/ledatu/csar/internal/config"
	"github.com/ledatu/csar/internal/throttle"
	csarv1 "github.com/ledatu/csar/proto/csar/v1"
	"google.golang.org/grpc"
)

type scriptedStream struct {
	grpc.ClientStream
	msgs []*csarv1.ConfigUpdate
}

func (s *scriptedStream) Recv() (*csarv1.ConfigUpdate, error) {
	if len(s.msgs) == 0 {
		return nil, io.EOF
	}
	msg := s.msgs[0]
	s.msgs = s.msgs[1:]
	return msg, nil
}

type scriptedCoordinator struct {
	csarv1.CoordinatorServiceClient
	subscribe func() (grpc.ServerStreamingClient[csarv1.ConfigUpdate], error)
}

func (f *scriptedCoordinator) Subscribe(context.Context, *csarv1.SubscribeRequest, ...grpc.CallOption) (grpc.ServerStreamingClient[csarv1.ConfigUpdate], error) {
	return f.subscribe()
}

func quotaUpdate() *csarv1.ConfigUpdate {
	return &csarv1.ConfigUpdate{
		Version: 1,
		Update:  &csarv1.ConfigUpdate_QuotaAssignment{QuotaAssignment: &csarv1.QuotaAssignment{}},
	}
}

func recordBackoffs(t *testing.T, coord csarv1.CoordinatorServiceClient, reconnects int) []time.Duration {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	c := New(coord, "router-1", ":8080", throttle.NewManager(), slog.New(slog.NewTextHandler(io.Discard, nil)))
	var waits []time.Duration
	c.wait = func(_ context.Context, d time.Duration) bool {
		waits = append(waits, d)
		if len(waits) == reconnects {
			cancel()
			return false
		}
		return true
	}
	c.Run(ctx)
	return waits
}

func TestRun_BackoffStartsOverAfterAStreamDeliveredMessages(t *testing.T) {
	coord := &scriptedCoordinator{subscribe: func() (grpc.ServerStreamingClient[csarv1.ConfigUpdate], error) {
		return &scriptedStream{msgs: []*csarv1.ConfigUpdate{quotaUpdate()}}, nil
	}}
	got := recordBackoffs(t, coord, 4)
	want := []time.Duration{time.Second, time.Second, time.Second, time.Second}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("backoffs = %v, want %v", got, want)
	}
}

func TestRun_BackoffGrowsAndCapsWhileSubscribeKeepsFailing(t *testing.T) {
	coord := &scriptedCoordinator{subscribe: func() (grpc.ServerStreamingClient[csarv1.ConfigUpdate], error) {
		return nil, errors.New("connection refused")
	}}
	got := recordBackoffs(t, coord, 8)
	want := []time.Duration{
		time.Second, 2 * time.Second, 4 * time.Second, 8 * time.Second,
		16 * time.Second, 32 * time.Second, 60 * time.Second, 60 * time.Second,
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("backoffs = %v, want %v", got, want)
	}
}

func TestRun_EmptyStreamDoesNotResetBackoff(t *testing.T) {
	coord := &scriptedCoordinator{subscribe: func() (grpc.ServerStreamingClient[csarv1.ConfigUpdate], error) {
		return &scriptedStream{}, nil
	}}
	got := recordBackoffs(t, coord, 3)
	want := []time.Duration{time.Second, 2 * time.Second, 4 * time.Second}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("backoffs = %v, want %v", got, want)
	}
}

type countingApplier struct {
	calls int
	err   error
}

func (a *countingApplier) Apply(*config.Config) error {
	a.calls++
	return a.err
}

func snapshotWithTarget(target string) *csarv1.FullConfigSnapshot {
	return &csarv1.FullConfigSnapshot{Routes: []*csarv1.RouteConfig{{
		RouteId:   "GET:/api/v1",
		Path:      "/api/v1",
		Method:    "GET",
		TargetUrl: target,
	}}}
}

func newApplyingClient(a ConfigApplier) *Client {
	return New(nil, "router-1", ":8080", throttle.NewManager(),
		slog.New(slog.NewTextHandler(io.Discard, nil)), WithConfigApplier(a))
}

func TestHandleFullConfigSnapshot_SkipsRebuildForIdenticalSnapshot(t *testing.T) {
	applier := &countingApplier{}
	c := newApplyingClient(applier)

	c.handleFullConfigSnapshot(snapshotWithTarget("http://a:8080"), 1)
	c.handleFullConfigSnapshot(snapshotWithTarget("http://a:8080"), 2)
	if applier.calls != 1 {
		t.Fatalf("Apply calls after a repeated snapshot = %d, want 1", applier.calls)
	}

	c.handleFullConfigSnapshot(snapshotWithTarget("http://b:8080"), 3)
	if applier.calls != 2 {
		t.Fatalf("Apply calls after a changed snapshot = %d, want 2", applier.calls)
	}
}

func TestHandleFullConfigSnapshot_RetriesAfterFailedApply(t *testing.T) {
	applier := &countingApplier{err: errors.New("router rebuild failed")}
	c := newApplyingClient(applier)

	c.handleFullConfigSnapshot(snapshotWithTarget("http://a:8080"), 1)
	applier.err = nil
	c.handleFullConfigSnapshot(snapshotWithTarget("http://a:8080"), 2)
	if applier.calls != 2 {
		t.Fatalf("Apply calls = %d, want 2: a snapshot whose apply failed must be applied again", applier.calls)
	}

	c.handleFullConfigSnapshot(snapshotWithTarget("http://a:8080"), 3)
	if applier.calls != 2 {
		t.Fatalf("Apply calls = %d, want 2 once the snapshot is applied", applier.calls)
	}
}
