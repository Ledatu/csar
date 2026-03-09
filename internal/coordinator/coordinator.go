package coordinator

import (
	"context"
	"log/slog"
	"sync"
	"time"

	csarv1 "github.com/ledatu/csar/proto/csar/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/durationpb"

	"github.com/ledatu/csar/internal/statestore"
)

// Coordinator is the gRPC control plane server.
// It manages configuration distribution, secret delivery, and quota allocation.
type Coordinator struct {
	csarv1.UnimplementedCoordinatorServiceServer

	store  statestore.StateStore
	logger *slog.Logger

	mu          sync.RWMutex
	subscribers map[string]*subscriber // routerID -> subscriber
	version     uint64

	// invalidationOutbox is a ring buffer of recent token invalidation events.
	// On router reconnect, missed events (version > last_seen_version) are replayed.
	invalidationOutbox *InvalidationOutbox
}

// InvalidationOutbox is a bounded ring buffer of token invalidation events
// for durable replay on router reconnect.
type InvalidationOutbox struct {
	mu      sync.RWMutex
	entries []invalidationEntry
	size    int
	head    int // next write position
}

type invalidationEntry struct {
	version   uint64
	tokenRefs []string
}

// NewInvalidationOutbox creates an outbox with the given capacity.
func NewInvalidationOutbox(size int) *InvalidationOutbox {
	if size < 100 {
		size = 100
	}
	return &InvalidationOutbox{
		entries: make([]invalidationEntry, size),
		size:    size,
	}
}

// Append records an invalidation event.
func (o *InvalidationOutbox) Append(version uint64, tokenRefs []string) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.entries[o.head] = invalidationEntry{version: version, tokenRefs: tokenRefs}
	o.head = (o.head + 1) % o.size
}

// ReplaySince returns all invalidation events with version > sinceVersion,
// ordered from oldest to newest.
func (o *InvalidationOutbox) ReplaySince(sinceVersion uint64) []invalidationEntry {
	o.mu.RLock()
	defer o.mu.RUnlock()

	var result []invalidationEntry
	for i := 0; i < o.size; i++ {
		idx := (o.head + i) % o.size
		e := o.entries[idx]
		if e.version > sinceVersion && e.version != 0 {
			result = append(result, e)
		}
	}
	return result
}

// subscriber tracks a connected router and its gRPC stream.
type subscriber struct {
	routerID string
	address  string
	stream   csarv1.CoordinatorService_SubscribeServer
	metadata map[string]string
}

// New creates a new Coordinator with the given state store.
func New(store statestore.StateStore, logger *slog.Logger) *Coordinator {
	return &Coordinator{
		store:              store,
		logger:             logger,
		subscribers:        make(map[string]*subscriber),
		invalidationOutbox: NewInvalidationOutbox(1000),
	}
}

// SetInvalidationBufferSize replaces the outbox with a new one of the given size.
// Must be called before any subscribers connect.
func (c *Coordinator) SetInvalidationBufferSize(size int) {
	c.invalidationOutbox = NewInvalidationOutbox(size)
}

// Subscribe implements the gRPC Subscribe stream.
// When a router connects, it registers, receives the current config snapshot,
// and then receives updates as they occur.
func (c *Coordinator) Subscribe(req *csarv1.SubscribeRequest, stream csarv1.CoordinatorService_SubscribeServer) error {
	if req.RouterId == "" {
		return status.Error(codes.InvalidArgument, "router_id is required")
	}

	c.logger.Info("router subscribing",
		"router_id", req.RouterId,
		"router_address", req.RouterAddress,
	)

	// Register in state store
	err := c.store.RegisterRouter(stream.Context(), statestore.RouterInfo{
		ID:            req.RouterId,
		Address:       req.RouterAddress,
		LastHeartbeat: time.Now(),
		Healthy:       true,
		Metadata:      req.Metadata,
	})
	if err != nil {
		return status.Errorf(codes.Internal, "failed to register router: %v", err)
	}

	// Register subscriber
	sub := &subscriber{
		routerID: req.RouterId,
		address:  req.RouterAddress,
		stream:   stream,
		metadata: req.Metadata,
	}

	c.mu.Lock()
	c.subscribers[req.RouterId] = sub
	c.mu.Unlock()

	// Clean up on disconnect. Use a bounded timeout for the store
	// operation instead of context.Background() (audit §6).
	defer func() {
		c.mu.Lock()
		delete(c.subscribers, req.RouterId)
		c.mu.Unlock()

		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cleanupCancel()
		c.store.UnregisterRouter(cleanupCtx, req.RouterId) //nolint:errcheck
		c.logger.Info("router disconnected", "router_id", req.RouterId)

		// Redistribute quotas when a router leaves
		c.redistributeQuotas()
	}()

	// Send initial config snapshot
	if err := c.sendRouteSnapshot(stream); err != nil {
		return err
	}

	// Send initial quota assignment
	if err := c.sendQuotaAssignment(req.RouterId, stream); err != nil {
		return err
	}

	// Replay missed invalidation events since the router's last watermark.
	if req.LastSeenVersion > 0 {
		missed := c.invalidationOutbox.ReplaySince(req.LastSeenVersion)
		for _, entry := range missed {
			msg := &csarv1.ConfigUpdate{
				Version: entry.version,
				Update: &csarv1.ConfigUpdate_TokenInvalidation{
					TokenInvalidation: &csarv1.TokenInvalidation{
						TokenRefs:           entry.tokenRefs,
						InvalidationVersion: entry.version,
					},
				},
			}
			if err := stream.Send(msg); err != nil {
				c.logger.Error("failed to replay invalidation",
					"router_id", req.RouterId,
					"version", entry.version,
					"error", err,
				)
				return err
			}
		}
		if len(missed) > 0 {
			c.logger.Info("replayed missed invalidations",
				"router_id", req.RouterId,
				"last_seen_version", req.LastSeenVersion,
				"replayed", len(missed),
			)
		}
	}

	// Redistribute quotas now that a new router joined
	c.redistributeQuotas()

	// Watch for config changes and forward to this subscriber
	watchCtx, watchCancel := context.WithCancel(stream.Context())
	defer watchCancel()

	routeCh, err := c.store.WatchRoutes(watchCtx)
	if err != nil {
		return status.Errorf(codes.Internal, "failed to watch routes: %v", err)
	}

	// Block until disconnect or context cancellation
	for {
		select {
		case <-stream.Context().Done():
			return nil
		case _, ok := <-routeCh:
			if !ok {
				return nil
			}
			if err := c.sendRouteSnapshot(stream); err != nil {
				c.logger.Error("failed to send route update",
					"router_id", req.RouterId,
					"error", err,
				)
				return err
			}
		}
	}
}

// ReportHealth handles health reports from routers.
// Uses the incoming RPC context so store operations respect caller
// cancellation and deadlines (audit §6).
func (c *Coordinator) ReportHealth(ctx context.Context, req *csarv1.HealthReport) (*csarv1.HealthAck, error) {
	if req.RouterId == "" {
		return nil, status.Error(codes.InvalidArgument, "router_id is required")
	}

	c.logger.Debug("health report",
		"router_id", req.RouterId,
		"healthy", req.Healthy,
	)

	// Update router health in state store using the request context.
	err := c.store.RegisterRouter(ctx, statestore.RouterInfo{
		ID:            req.RouterId,
		LastHeartbeat: time.Now(),
		Healthy:       req.Healthy,
	})
	if err != nil {
		c.logger.Warn("failed to update router health",
			"router_id", req.RouterId,
			"error", err,
		)
	}

	return &csarv1.HealthAck{Acknowledged: true}, nil
}

// BroadcastTokenInvalidation pushes a token invalidation event to all
// connected routers. Call this when tokens are rotated in etcd (audit §1.2).
// If tokenRefs is empty, all tokens are invalidated.
func (c *Coordinator) BroadcastTokenInvalidation(tokenRefs []string) {
	c.mu.Lock()
	c.version++
	version := c.version
	subs := make([]*subscriber, 0, len(c.subscribers))
	for _, s := range c.subscribers {
		subs = append(subs, s)
	}
	c.mu.Unlock()

	// Record in durable outbox for replay on reconnect.
	c.invalidationOutbox.Append(version, tokenRefs)

	msg := &csarv1.ConfigUpdate{
		Version: version,
		Update: &csarv1.ConfigUpdate_TokenInvalidation{
			TokenInvalidation: &csarv1.TokenInvalidation{
				TokenRefs:           tokenRefs,
				InvalidationVersion: version,
			},
		},
	}

	for _, sub := range subs {
		if err := sub.stream.Send(msg); err != nil {
			c.logger.Error("failed to send token invalidation",
				"router_id", sub.routerID,
				"error", err,
			)
		} else {
			c.logger.Info("sent token invalidation",
				"router_id", sub.routerID,
				"token_refs", tokenRefs,
			)
		}
	}
}

// sendRouteSnapshot sends the full route config to a subscriber.
func (c *Coordinator) sendRouteSnapshot(stream csarv1.CoordinatorService_SubscribeServer) error {
	routes, err := c.store.GetRoutes(stream.Context())
	if err != nil {
		return status.Errorf(codes.Internal, "failed to get routes: %v", err)
	}

	var protoRoutes []*csarv1.RouteConfig
	for _, r := range routes {
		rc := &csarv1.RouteConfig{
			RouteId:           r.ID,
			Path:              r.Path,
			Method:            r.Method,
			TargetUrl:         r.TargetURL,
			ResilienceProfile: r.ResilienceProfile,
		}

		if r.Security != nil {
			rc.Security = &csarv1.SecurityConfig{
				TokenRef:     r.Security.TokenRef,
				InjectHeader: r.Security.InjectHeader,
				InjectFormat: r.Security.InjectFormat,
			}
		}

		if r.Traffic != nil {
			rc.Traffic = &csarv1.TrafficConfig{
				Rps:     r.Traffic.RPS,
				Burst:   int32(r.Traffic.Burst),
				MaxWait: durationpb.New(r.Traffic.MaxWait),
			}
		}

		protoRoutes = append(protoRoutes, rc)
	}

	c.mu.Lock()
	c.version++
	version := c.version
	c.mu.Unlock()

	return stream.Send(&csarv1.ConfigUpdate{
		Version: version,
		Update: &csarv1.ConfigUpdate_RouteSnapshot{
			RouteSnapshot: &csarv1.RouteSnapshot{
				Routes: protoRoutes,
			},
		},
	})
}

// sendQuotaAssignment sends the current quota allocation to a specific router.
func (c *Coordinator) sendQuotaAssignment(routerID string, stream csarv1.CoordinatorService_SubscribeServer) error {
	routes, err := c.store.GetRoutes(stream.Context())
	if err != nil {
		return status.Errorf(codes.Internal, "failed to get routes: %v", err)
	}

	routers, err := c.store.ListRouters(stream.Context())
	if err != nil {
		return status.Errorf(codes.Internal, "failed to list routers: %v", err)
	}

	activeRouters := 0
	for _, r := range routers {
		if r.Healthy {
			activeRouters++
		}
	}
	if activeRouters == 0 {
		activeRouters = 1
	}

	quotas := make(map[string]*csarv1.RouteQuota)
	for _, route := range routes {
		if route.Traffic != nil {
			quotas[route.ID] = &csarv1.RouteQuota{
				Rps:   route.Traffic.RPS / float64(activeRouters),
				Burst: int32(route.Traffic.Burst / activeRouters),
			}
			// Ensure at least burst of 1
			if quotas[route.ID].Burst < 1 {
				quotas[route.ID].Burst = 1
			}
		}
	}

	c.mu.Lock()
	c.version++
	version := c.version
	c.mu.Unlock()

	return stream.Send(&csarv1.ConfigUpdate{
		Version: version,
		Update: &csarv1.ConfigUpdate_QuotaAssignment{
			QuotaAssignment: &csarv1.QuotaAssignment{
				Quotas: quotas,
			},
		},
	})
}

// redistributeQuotas recalculates and sends quota assignments to all connected routers.
func (c *Coordinator) redistributeQuotas() {
	c.mu.RLock()
	subs := make([]*subscriber, 0, len(c.subscribers))
	for _, s := range c.subscribers {
		subs = append(subs, s)
	}
	c.mu.RUnlock()

	for _, sub := range subs {
		if err := c.sendQuotaAssignment(sub.routerID, sub.stream); err != nil {
			c.logger.Warn("failed to redistribute quota",
				"router_id", sub.routerID,
				"error", err,
			)
		}
	}
}

// SubscriberCount returns the number of connected routers.
func (c *Coordinator) SubscriberCount() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.subscribers)
}
