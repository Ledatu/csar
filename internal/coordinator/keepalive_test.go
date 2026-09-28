package coordinator

import (
	"context"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ledatu/csar/internal/config"
	"github.com/ledatu/csar/internal/statestore"
	csarv1 "github.com/ledatu/csar/proto/csar/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

// idleClosingProxy forwards TCP connections to upstream and closes both sides
// once no bytes have flowed in either direction for idle, like the HAProxy
// "timeout client/server" in front of the coordinator.
func idleClosingProxy(t *testing.T, upstream string, idle time.Duration) string {
	t.Helper()
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("proxy listen: %v", err)
	}
	var wg sync.WaitGroup
	t.Cleanup(func() {
		_ = lis.Close()
		wg.Wait()
	})
	go func() {
		for {
			down, err := lis.Accept()
			if err != nil {
				return
			}
			up, err := net.Dial("tcp", upstream)
			if err != nil {
				_ = down.Close()
				continue
			}
			var last atomic.Int64
			last.Store(time.Now().UnixNano())
			closeBoth := sync.OnceFunc(func() {
				_ = down.Close()
				_ = up.Close()
			})
			pipe := func(dst, src net.Conn) {
				defer wg.Done()
				defer closeBoth()
				buf := make([]byte, 32*1024)
				for {
					n, err := src.Read(buf)
					if n > 0 {
						last.Store(time.Now().UnixNano())
						if _, werr := dst.Write(buf[:n]); werr != nil {
							return
						}
					}
					if err != nil {
						return
					}
				}
			}
			wg.Add(3)
			go pipe(up, down)
			go pipe(down, up)
			go func() {
				defer wg.Done()
				ticker := time.NewTicker(100 * time.Millisecond)
				defer ticker.Stop()
				for range ticker.C {
					if time.Since(time.Unix(0, last.Load())) > idle {
						closeBoth()
						return
					}
					if _, err := down.Write(nil); err != nil {
						return
					}
				}
			}()
		}
	}()
	return lis.Addr().String()
}

func startCoordinator(t *testing.T, opts ...grpc.ServerOption) string {
	t.Helper()
	store := statestore.NewMemoryStore()
	if err := store.PutRoute(context.Background(), statestore.RouteEntry{
		ID: "GET:/api/v1", Path: "/api/v1", Method: "GET",
		Route: config.RouteConfig{Backend: config.BackendConfig{TargetURL: "http://upstream:8080"}},
	}); err != nil {
		t.Fatalf("PutRoute: %v", err)
	}
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	srv := grpc.NewServer(opts...)
	csarv1.RegisterCoordinatorServiceServer(srv, New(store, newTestLogger()))
	go srv.Serve(lis) //nolint:errcheck // test server
	t.Cleanup(func() {
		srv.Stop()
		store.Close()
	})
	return lis.Addr().String()
}

// idleStreamSurvives subscribes through an idle-closing proxy, lets the stream
// sit silent for wait, and reports whether it is still open.
func idleStreamSurvives(t *testing.T, serverOpts []grpc.ServerOption, idle, wait time.Duration) bool {
	t.Helper()
	proxy := idleClosingProxy(t, startCoordinator(t, serverOpts...), idle)
	conn, err := grpc.NewClient(proxy, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	stream, err := csarv1.NewCoordinatorServiceClient(conn).Subscribe(ctx, &csarv1.SubscribeRequest{RouterId: "router-1"})
	if err != nil {
		t.Fatalf("Subscribe: %v", err)
	}
	if _, err := stream.Recv(); err != nil {
		t.Fatalf("first Recv: %v", err)
	}

	broken := make(chan error, 1)
	go func() {
		for {
			if _, err := stream.Recv(); err != nil {
				if err != io.EOF || ctx.Err() == nil {
					broken <- err
				}
				return
			}
		}
	}()
	select {
	case <-broken:
		return false
	case <-time.After(wait):
		return true
	}
}

func TestServerKeepalive_KeepsIdleStreamOpenThroughIdleClosingProxy(t *testing.T) {
	if testing.Short() {
		t.Skip("waits for the proxy idle timeout")
	}
	opts := ServerKeepalive{Time: time.Second, Timeout: time.Second}.ServerOptions()
	if !idleStreamSurvives(t, opts, 3*time.Second, 7*time.Second) {
		t.Fatal("stream was closed by the idle proxy despite server keepalive")
	}
}

func TestServerKeepalive_WithoutKeepaliveTheProxyClosesIdleStream(t *testing.T) {
	if testing.Short() {
		t.Skip("waits for the proxy idle timeout")
	}
	if idleStreamSurvives(t, nil, 3*time.Second, 7*time.Second) {
		t.Fatal("control failed: the idle proxy did not close a stream without keepalive")
	}
}

func TestClientPingPolicy_AllowsRouterPings(t *testing.T) {
	p := clientPingPolicy()
	if p.MinTime > 10*time.Second {
		t.Errorf("MinTime = %s; clients pinging every 10s would get GOAWAY too_many_pings", p.MinTime)
	}
	if !p.PermitWithoutStream {
		t.Error("PermitWithoutStream = false; the router's token connection has no active stream between fetches")
	}
}

func TestSubscribe_DebounceCoalescesRouteChangesIntoOneSnapshot(t *testing.T) {
	snapshotsAfterBurst := func(debounce time.Duration) []*csarv1.FullConfigSnapshot {
		store := statestore.NewMemoryStore()
		t.Cleanup(func() { store.Close() })
		coord := New(store, newTestLogger())
		coord.SetSnapshotDebounce(debounce)

		lis, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("listen: %v", err)
		}
		srv := grpc.NewServer()
		csarv1.RegisterCoordinatorServiceServer(srv, coord)
		go srv.Serve(lis) //nolint:errcheck // test server
		t.Cleanup(srv.Stop)

		conn, err := grpc.NewClient(lis.Addr().String(), grpc.WithTransportCredentials(insecure.NewCredentials()))
		if err != nil {
			t.Fatalf("dial: %v", err)
		}
		t.Cleanup(func() { _ = conn.Close() })
		ctx, cancel := context.WithCancel(context.Background())
		t.Cleanup(cancel)
		stream, err := csarv1.NewCoordinatorServiceClient(conn).Subscribe(ctx, &csarv1.SubscribeRequest{RouterId: "router-1"})
		if err != nil {
			t.Fatalf("Subscribe: %v", err)
		}

		msgs := make(chan *csarv1.ConfigUpdate, 64)
		go func() {
			for {
				msg, err := stream.Recv()
				if err != nil {
					return
				}
				msgs <- msg
			}
		}()
		first := <-msgs
		if first.GetFullConfigSnapshot() == nil {
			t.Fatal("first message is not a full config snapshot")
		}

		for _, p := range []string{"/a", "/b", "/c", "/d", "/e"} {
			if err := store.PutRoute(context.Background(), statestore.RouteEntry{
				ID: "GET:" + p, Path: p, Method: "GET",
				Route: config.RouteConfig{Backend: config.BackendConfig{TargetURL: "http://upstream:8080"}},
			}); err != nil {
				t.Fatalf("PutRoute: %v", err)
			}
		}

		var snaps []*csarv1.FullConfigSnapshot
		window := time.After(debounce + 1500*time.Millisecond)
		for {
			select {
			case msg := <-msgs:
				if s := msg.GetFullConfigSnapshot(); s != nil {
					snaps = append(snaps, s)
				}
			case <-window:
				return snaps
			}
		}
	}

	coalesced := snapshotsAfterBurst(300 * time.Millisecond)
	if len(coalesced) != 1 {
		t.Fatalf("snapshots after a burst of 5 route changes = %d, want 1", len(coalesced))
	}
	if got := len(coalesced[0].GetRoutes()); got != 5 {
		t.Fatalf("coalesced snapshot has %d routes, want all 5", got)
	}

	if uncoalesced := snapshotsAfterBurst(0); len(uncoalesced) < 2 {
		t.Fatalf("control: debounce 0 sent %d snapshots, want one per change", len(uncoalesced))
	}
}
