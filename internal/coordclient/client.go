// Package coordclient provides a coordinator subscription client for CSAR routers.
//
// It subscribes to the coordinator's gRPC stream and applies quota assignments
// to local throttlers, processes token invalidation events, and reconnects
// automatically with exponential backoff on stream errors.
package coordclient

import (
	"context"
	"log/slog"
	"math"
	"time"

	"github.com/ledatu/csar/internal/throttle"
	"github.com/ledatu/csar/pkg/middleware"
	csarv1 "github.com/ledatu/csar/proto/csar/v1"
)

// Client subscribes to the coordinator gRPC stream and dispatches
// configuration updates to the router's throttle manager and auth injector.
type Client struct {
	coordClient  csarv1.CoordinatorServiceClient
	routerID     string
	routerAddr   string
	logger       *slog.Logger
	throttleMgr  *throttle.ThrottleManager
	authInjector *middleware.AuthInjector // may be nil if no auth is configured

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

	// Reset backoff on successful connection
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

		case *csarv1.ConfigUpdate_RouteSnapshot:
			c.logger.Info("received route snapshot",
				"routes", len(u.RouteSnapshot.GetRoutes()),
				"version", msg.Version,
			)
			// Route snapshots are handled by SIGHUP-based config reload;
			// the coordinator client focuses on quota and token updates.
		}
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
