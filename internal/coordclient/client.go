// Package coordclient provides a coordinator subscription client for CSAR routers.
//
// It subscribes to the coordinator's gRPC stream and applies quota assignments
// to local throttlers, processes token invalidation events, applies full config
// snapshots to rebuild the router, and reconnects automatically with exponential
// backoff on stream errors.
package coordclient

import (
	"context"
	"log/slog"
	"math"
	"time"

	"github.com/ledatu/csar/internal/config"
	"github.com/ledatu/csar/internal/protoconv"
	"github.com/ledatu/csar/internal/throttle"
	"github.com/ledatu/csar/pkg/middleware"
	csarv1 "github.com/ledatu/csar/proto/csar/v1"
)

// ConfigApplier is called when a full config snapshot is received from the
// coordinator. The implementation should rebuild the router and hot-swap it.
type ConfigApplier interface {
	Apply(cfg *config.Config) error
}

// Client subscribes to the coordinator gRPC stream and dispatches
// configuration updates to the router's throttle manager and auth injector.
type Client struct {
	coordClient  csarv1.CoordinatorServiceClient
	routerID     string
	routerAddr   string
	logger       *slog.Logger
	throttleMgr  *throttle.ThrottleManager
	authInjector *middleware.AuthInjector
	applier      ConfigApplier

	// lastSeenVersion tracks the watermark for durable invalidation replay.
	lastSeenVersion uint64

	// Backoff config
	initialBackoff time.Duration
	maxBackoff     time.Duration
}

// Option configures the coordinator client.
type Option func(*Client)

// WithAuthInjector sets the auth injector for token invalidation events.
func WithAuthInjector(a *middleware.AuthInjector) Option {
	return func(c *Client) { c.authInjector = a }
}

// WithConfigApplier sets the callback for applying full config snapshots
// received from the coordinator. When set, route snapshots trigger a
// full router rebuild and hot-swap.
func WithConfigApplier(a ConfigApplier) Option {
	return func(c *Client) { c.applier = a }
}

// New creates a new coordinator subscription client.
func New(
	coordClient csarv1.CoordinatorServiceClient,
	routerID, routerAddr string,
	throttleMgr *throttle.ThrottleManager,
	logger *slog.Logger,
	opts ...Option,
) *Client {
	c := &Client{
		coordClient:    coordClient,
		routerID:       routerID,
		routerAddr:     routerAddr,
		logger:         logger,
		throttleMgr:    throttleMgr,
		initialBackoff: 1 * time.Second,
		maxBackoff:     60 * time.Second,
	}
	for _, opt := range opts {
		opt(c)
	}
	return c
}

// Run starts the subscription loop. It blocks until ctx is cancelled.
// On stream errors it reconnects with exponential backoff.
func (c *Client) Run(ctx context.Context) {
	backoff := c.initialBackoff

	for {
		select {
		case <-ctx.Done():
			c.logger.Info("coordinator client shutting down")
			return
		default:
		}

		err := c.subscribe(ctx)
		if ctx.Err() != nil {
			return // context cancelled — clean shutdown
		}

		c.logger.Warn("coordinator stream disconnected, reconnecting",
			"error", err,
			"backoff", backoff,
		)

		select {
		case <-ctx.Done():
			return
		case <-time.After(backoff):
		}

		// Exponential backoff with cap
		backoff = time.Duration(math.Min(
			float64(backoff)*2,
			float64(c.maxBackoff),
		))
	}
}

// subscribe opens a single subscription stream and processes messages until error.
func (c *Client) subscribe(ctx context.Context) error {
	stream, err := c.coordClient.Subscribe(ctx, &csarv1.SubscribeRequest{
		RouterId:        c.routerID,
		RouterAddress:   c.routerAddr,
		LastSeenVersion: c.lastSeenVersion,
	})
	if err != nil {
		return err
	}

	c.logger.Info("subscribed to coordinator",
		"router_id", c.routerID,
		"last_seen_version", c.lastSeenVersion,
	)

	for {
		msg, err := stream.Recv()
		if err != nil {
			return err
		}

		// Track watermark for replay on reconnect.
		if msg.Version > c.lastSeenVersion {
			c.lastSeenVersion = msg.Version
		}

		c.logger.Debug("received coordinator update",
			"version", msg.Version,
		)

		switch u := msg.Update.(type) {
		case *csarv1.ConfigUpdate_QuotaAssignment:
			c.handleQuotaAssignment(u.QuotaAssignment)

		case *csarv1.ConfigUpdate_TokenInvalidation:
			c.handleTokenInvalidation(u.TokenInvalidation)

		case *csarv1.ConfigUpdate_FullConfigSnapshot:
			c.handleFullConfigSnapshot(u.FullConfigSnapshot, msg.Version)

		case *csarv1.ConfigUpdate_RouteSnapshot:
			c.logger.Info("received legacy route snapshot (ignored, use FullConfigSnapshot)",
				"routes", len(u.RouteSnapshot.GetRoutes()),
				"version", msg.Version,
			)
		}
	}
}

// handleFullConfigSnapshot converts a FullConfigSnapshot to a config.Config
// and applies it via the ConfigApplier to rebuild the router.
func (c *Client) handleFullConfigSnapshot(snap *csarv1.FullConfigSnapshot, version uint64) {
	if snap == nil {
		return
	}

	c.logger.Info("received full config snapshot",
		"routes", len(snap.GetRoutes()),
		"version", version,
	)

	if c.applier == nil {
		c.logger.Debug("full config snapshot received but no ConfigApplier configured")
		return
	}

	cfg := protoconv.FullSnapshotToConfig(snap)

	if err := c.applier.Apply(cfg); err != nil {
		c.logger.Error("failed to apply config snapshot",
			"version", version,
			"error", err,
		)
	} else {
		c.logger.Info("config snapshot applied successfully",
			"version", version,
			"routes", len(cfg.Paths),
		)
	}
}

// handleQuotaAssignment applies coordinator-assigned quotas to local throttlers.
func (c *Client) handleQuotaAssignment(qa *csarv1.QuotaAssignment) {
	if qa == nil {
		return
	}

	updated := 0
	for routeID, quota := range qa.GetQuotas() {
		if c.throttleMgr.UpdateQuota(routeID, quota.Rps, int(quota.Burst)) {
			updated++
			c.logger.Debug("quota updated",
				"route_id", routeID,
				"rps", quota.Rps,
				"burst", quota.Burst,
			)
		}
	}
	c.logger.Info("quota assignment applied",
		"total_quotas", len(qa.GetQuotas()),
		"updated", updated,
	)
}

// handleTokenInvalidation clears stale-cached tokens as instructed by the coordinator.
func (c *Client) handleTokenInvalidation(ti *csarv1.TokenInvalidation) {
	if c.authInjector == nil {
		c.logger.Debug("token invalidation received but no auth injector configured")
		return
	}
	if ti == nil {
		return
	}

	refs := ti.GetTokenRefs()
	if len(refs) == 0 {
		// Empty list means invalidate all tokens.
		c.authInjector.InvalidateAllTokens()
		c.logger.Info("all tokens invalidated by coordinator")
	} else {
		for _, ref := range refs {
			c.authInjector.InvalidateToken(ref)
		}
		c.logger.Info("tokens invalidated by coordinator", "count", len(refs))
	}
}
