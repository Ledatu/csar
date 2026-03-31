package coordinator

import (
	"context"
	"log/slog"
	"math"
	"sync"
	"time"

	"github.com/ledatu/csar/internal/config"
	"github.com/ledatu/csar/internal/statestore"
	csarv1 "github.com/ledatu/csar/proto/csar/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/durationpb"
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

	// topLevelConfig holds top-level policy maps pushed alongside routes.
	topLevelConfig *config.Config
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

// SetTopLevelConfig stores the top-level config (policies, global settings)
// so they can be included in FullConfigSnapshot messages pushed to routers.
func (c *Coordinator) SetTopLevelConfig(cfg *config.Config) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.topLevelConfig = cfg
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

	sub := &subscriber{
		routerID: req.RouterId,
		address:  req.RouterAddress,
		stream:   stream,
		metadata: req.Metadata,
	}

	c.mu.Lock()
	c.subscribers[req.RouterId] = sub
	c.mu.Unlock()

	defer func() {
		c.mu.Lock()
		delete(c.subscribers, req.RouterId)
		c.mu.Unlock()

		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cleanupCancel()
		c.store.UnregisterRouter(cleanupCtx, req.RouterId) //nolint:errcheck // best-effort cleanup on disconnect
		c.logger.Info("router disconnected", "router_id", req.RouterId)

		c.redistributeQuotas()
	}()

	if err := c.sendFullConfigSnapshot(stream); err != nil {
		return err
	}

	if err := c.sendQuotaAssignment(req.RouterId, stream); err != nil {
		return err
	}

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

	c.redistributeQuotas()

	watchCtx, watchCancel := context.WithCancel(stream.Context())
	defer watchCancel()

	routeCh, err := c.store.WatchRoutes(watchCtx)
	if err != nil {
		return status.Errorf(codes.Internal, "failed to watch routes: %v", err)
	}

	for {
		select {
		case <-stream.Context().Done():
			return nil
		case _, ok := <-routeCh:
			if !ok {
				return nil
			}
			if err := c.sendFullConfigSnapshot(stream); err != nil {
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
func (c *Coordinator) ReportHealth(ctx context.Context, req *csarv1.HealthReport) (*csarv1.HealthAck, error) {
	if req.RouterId == "" {
		return nil, status.Error(codes.InvalidArgument, "router_id is required")
	}

	c.logger.Debug("health report",
		"router_id", req.RouterId,
		"healthy", req.Healthy,
	)

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
func (c *Coordinator) BroadcastTokenInvalidation(tokenRefs []string) {
	c.mu.Lock()
	c.version++
	version := c.version
	subs := make([]*subscriber, 0, len(c.subscribers))
	for _, s := range c.subscribers {
		subs = append(subs, s)
	}
	c.mu.Unlock()

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

// sendFullConfigSnapshot sends routes plus top-level policies to a subscriber.
func (c *Coordinator) sendFullConfigSnapshot(stream csarv1.CoordinatorService_SubscribeServer) error {
	routes, err := c.store.GetRoutes(stream.Context())
	if err != nil {
		return status.Errorf(codes.Internal, "failed to get routes: %v", err)
	}

	protoRoutes := make([]*csarv1.RouteConfig, 0, len(routes))
	for i := range routes {
		protoRoutes = append(protoRoutes, routeEntryToProto(&routes[i]))
	}

	snapshot := &csarv1.FullConfigSnapshot{Routes: protoRoutes}

	c.mu.RLock()
	cfg := c.topLevelConfig
	c.mu.RUnlock()

	if cfg != nil {
		snapshot.CircuitBreakers = circuitBreakersToProto(cfg.CircuitBreakers)
		snapshot.SecurityProfiles = securityProfilesToProto(cfg.SecurityProfiles)
		snapshot.ThrottlingPolicies = throttlingPoliciesToProto(cfg.ThrottlingPolicies)
		snapshot.CorsPolicies = corsPoliciesMapToProto(cfg.CORSPolicies)
		snapshot.RetryPolicies = retryPoliciesMapToProto(cfg.RetryPolicies)
		snapshot.RedactPolicies = redactPoliciesMapToProto(cfg.RedactPolicies)
		snapshot.AuthValidatePolicies = authValidatePoliciesMapToProto(cfg.AuthValidatePolicies)
		snapshot.AuthzPolicies = authzPoliciesMapToProto(cfg.AuthzPolicies)
		snapshot.BackendTlsPolicies = backendTLSPoliciesToProto(cfg.BackendTLSPolicies)

		if cfg.GlobalThrottle != nil {
			snapshot.GlobalThrottle = &csarv1.GlobalThrottleProto{
				Rps:     cfg.GlobalThrottle.RPS,
				Burst:   safeInt32(cfg.GlobalThrottle.Burst),
				MaxWait: durationpb.New(cfg.GlobalThrottle.MaxWait.Duration),
			}
		}
		if cfg.DebugHeaders != nil {
			snapshot.DebugHeaders = debugHeadersToProto(cfg.DebugHeaders)
		}
		if cfg.AccessControl != nil {
			snapshot.GlobalAccessControl = accessControlToProto(cfg.AccessControl)
		}
	}

	c.mu.Lock()
	c.version++
	version := c.version
	c.mu.Unlock()

	return stream.Send(&csarv1.ConfigUpdate{
		Version: version,
		Update: &csarv1.ConfigUpdate_FullConfigSnapshot{
			FullConfigSnapshot: snapshot,
		},
	})
}

// sendQuotaAssignment sends the current quota allocation to a specific router.
func (c *Coordinator) sendQuotaAssignment(_ string, stream csarv1.CoordinatorService_SubscribeServer) error {
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
	for i := range routes {
		if routes[i].Route.Traffic != nil {
			burst := routes[i].Route.Traffic.Burst / activeRouters
			if burst > math.MaxInt32 {
				burst = math.MaxInt32
			}
			quotas[routes[i].ID] = &csarv1.RouteQuota{
				Rps:   routes[i].Route.Traffic.RPS / float64(activeRouters),
				Burst: safeInt32(burst),
			}
			if quotas[routes[i].ID].Burst < 1 {
				quotas[routes[i].ID].Burst = 1
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

// safeInt32 converts an int to int32, clamping to math.MaxInt32 on overflow.
func safeInt32(v int) int32 {
	if v > math.MaxInt32 {
		return math.MaxInt32
	}
	if v < math.MinInt32 {
		return math.MinInt32
	}
	return int32(v) //nolint:gosec // overflow guarded by clamp above
}

// ---------------------------------------------------------------------------
// Config → Proto converters
// ---------------------------------------------------------------------------

func routeEntryToProto(r *statestore.RouteEntry) *csarv1.RouteConfig {
	rc := &csarv1.RouteConfig{
		RouteId:   r.ID,
		Path:      r.Path,
		Method:    r.Method,
		TargetUrl: r.Route.Backend.TargetURL,
	}

	if r.Route.Resilience != nil {
		rc.ResilienceProfile = r.Route.Resilience.CircuitBreaker
	}

	rc.Backend = backendToProto(&r.Route.Backend)

	if len(r.Route.Security) > 0 {
		rc.Securities = make([]*csarv1.SecurityConfigProto, 0, len(r.Route.Security))
		for i := range r.Route.Security {
			rc.Securities = append(rc.Securities, securityToProto(&r.Route.Security[i]))
		}
		rc.Security = rc.Securities[0]
	}

	if r.Route.Traffic != nil {
		rc.TrafficConfig = trafficToProto(r.Route.Traffic)
		rc.Traffic = rc.TrafficConfig
	}

	if r.Route.Retry != nil {
		rc.Retry = retryToProto(r.Route.Retry)
	}
	if r.Route.Redact != nil {
		rc.Redact = redactToProto(r.Route.Redact)
	}
	if r.Route.CORS != nil {
		rc.Cors = corsToProto(r.Route.CORS)
	}
	if r.Route.Tenant != nil {
		rc.Tenant = tenantToProto(r.Route.Tenant)
	}
	if r.Route.Cache != nil {
		rc.Cache = cacheToProto(r.Route.Cache)
	}
	if r.Route.AuthValidate != nil {
		rc.AuthValidate = authValidateToProto(r.Route.AuthValidate)
	}
	if r.Route.Access != nil {
		rc.Access = accessControlToProto(r.Route.Access)
	}
	if r.Route.Resilience != nil {
		rc.Resilience = &csarv1.ResilienceConfigProto{
			CircuitBreaker: r.Route.Resilience.CircuitBreaker,
		}
	}
	if len(r.Route.Headers) > 0 {
		rc.Headers = r.Route.Headers
	}
	rc.MaxResponseSize = r.Route.MaxResponseSize
	if r.Route.Protocol != nil {
		rc.Protocol = protocolToProto(r.Route.Protocol)
	}
	if r.Route.Authz != nil {
		rc.Authz = authzToProto(r.Route.Authz)
	}

	return rc
}

func backendToProto(b *config.BackendConfig) *csarv1.BackendConfigProto {
	pb := &csarv1.BackendConfigProto{
		TargetUrl:    b.TargetURL,
		Targets:      b.Targets,
		LoadBalancer: b.LoadBalancer,
		PathRewrite:  b.PathRewrite,
		PathMode:     b.PathMode,
	}
	if b.HealthCheck != nil {
		pb.HealthCheck = &csarv1.HealthCheckConfigProto{
			Enabled:            b.HealthCheck.Enabled,
			Mode:               b.HealthCheck.Mode,
			Path:               b.HealthCheck.Path,
			Interval:           durationpb.New(b.HealthCheck.Interval.Duration),
			Timeout:            durationpb.New(b.HealthCheck.Timeout.Duration),
			UnhealthyThreshold: safeInt32(b.HealthCheck.UnhealthyThreshold),
			HealthyThreshold:   safeInt32(b.HealthCheck.HealthyThreshold),
		}
	}
	if b.TLS != nil {
		pb.Tls = &csarv1.BackendTLSConfigProto{
			InsecureSkipVerify: b.TLS.InsecureSkipVerify,
			CaFile:             b.TLS.CAFile,
			CertFile:           b.TLS.CertFile,
			KeyFile:            b.TLS.KeyFile,
		}
	}
	return pb
}

func securityToProto(s *config.SecurityConfig) *csarv1.SecurityConfigProto {
	pb := &csarv1.SecurityConfigProto{
		Profile:      s.Profile,
		KmsKeyId:     s.KMSKeyID,
		TokenRef:     s.TokenRef,
		TokenVersion: s.TokenVersion,
		InjectHeader: s.InjectHeader,
		InjectFormat: s.InjectFormat,
		OnKmsError:   s.OnKMSError,
	}
	if s.StripTokenParams != nil {
		pb.StripTokenParams = *s.StripTokenParams
		pb.StripTokenParamsSet = true
	}
	return pb
}

func trafficToProto(t *config.TrafficConfig) *csarv1.TrafficConfigProto {
	pb := &csarv1.TrafficConfigProto{
		Use:             t.Use,
		Rps:             t.RPS,
		Burst:           safeInt32(t.Burst),
		MaxWait:         durationpb.New(t.MaxWait.Duration),
		Backend:         t.Backend,
		Key:             t.Key,
		ExcludeIps:      t.ExcludeIPs,
		ClientLimitMode: t.ClientLimitMode,
	}
	if len(t.VIPOverrides) > 0 {
		pb.VipOverrides = make([]*csarv1.VIPOverrideProto, 0, len(t.VIPOverrides))
		for _, v := range t.VIPOverrides {
			pb.VipOverrides = append(pb.VipOverrides, &csarv1.VIPOverrideProto{
				Header: v.Header,
				Values: v.Values,
			})
		}
	}
	if t.AdaptiveBackpressure != nil {
		pb.AdaptiveBackpressure = &csarv1.AdaptiveBackpressureProto{
			Enabled:        t.AdaptiveBackpressure.Enabled,
			RespectHeaders: t.AdaptiveBackpressure.RespectHeaders,
			SuspendBucket:  t.AdaptiveBackpressure.SuspendBucket,
			MaxBodyBuffer:  t.AdaptiveBackpressure.MaxBodyBuffer,
		}
	}
	return pb
}

func retryToProto(r *config.RetryConfig) *csarv1.RetryConfigProto {
	pb := &csarv1.RetryConfigProto{
		Use:             r.Use,
		MaxAttempts:     safeInt32(r.MaxAttempts),
		Backoff:         durationpb.New(r.Backoff.Duration),
		MaxBackoff:      durationpb.New(r.MaxBackoff.Duration),
		AutoRetry_429:   r.AutoRetry429,
		MaxInternalWait: durationpb.New(r.MaxInternalWait.Duration),
	}
	if len(r.RetryableStatusCodes) > 0 {
		pb.RetryableStatusCodes = make([]int32, len(r.RetryableStatusCodes))
		for i, code := range r.RetryableStatusCodes {
			pb.RetryableStatusCodes[i] = safeInt32(code)
		}
	}
	pb.RetryableMethods = r.RetryableMethods
	return pb
}

func redactToProto(r *config.RedactConfig) *csarv1.RedactConfigProto {
	pb := &csarv1.RedactConfigProto{
		Use:    r.Use,
		Fields: r.Fields,
		Mask:   r.Mask,
	}
	if r.Enabled != nil {
		pb.Enabled = *r.Enabled
		pb.EnabledSet = true
	}
	return pb
}

func corsToProto(cc *config.CORSConfig) *csarv1.CORSConfigProto {
	return &csarv1.CORSConfigProto{
		Use:              cc.Use,
		AllowedOrigins:   cc.AllowedOrigins,
		AllowedMethods:   cc.AllowedMethods,
		AllowedHeaders:   cc.AllowedHeaders,
		ExposedHeaders:   cc.ExposedHeaders,
		AllowCredentials: cc.AllowCredentials,
		MaxAge:           safeInt32(cc.MaxAge),
	}
}

func tenantToProto(t *config.TenantConfig) *csarv1.TenantConfigProto {
	return &csarv1.TenantConfigProto{
		Header:         t.Header,
		Backends:       t.Backends,
		DefaultBackend: t.Default,
	}
}

func cacheToProto(cc *config.CacheConfig) *csarv1.CacheConfigProto {
	pb := &csarv1.CacheConfigProto{
		Ttl:         durationpb.New(cc.TTL.Duration),
		MaxEntries:  safeInt32(cc.MaxEntries),
		MaxBodySize: cc.MaxBodySize,
		Methods:     cc.Methods,
	}
	if cc.Enabled != nil {
		pb.Enabled = *cc.Enabled
		pb.EnabledSet = true
	}
	return pb
}

func authValidateToProto(a *config.AuthValidateConfig) *csarv1.AuthValidateConfigProto {
	return &csarv1.AuthValidateConfigProto{
		Use:             a.Use,
		Mode:            a.Mode,
		JwksUrl:         a.JWKSURL,
		JwksTls:         a.JWKSTLS,
		SessionEndpoint: a.SessionEndpoint,
		SessionTls:      a.SessionTLS,
		ForwardHeaders:  a.ForwardHeaders,
		Issuer:          a.Issuer,
		Audiences:       a.Audiences,
		HeaderName:      a.HeaderName,
		TokenPrefix:     a.TokenPrefix,
		CacheTtl:        durationpb.New(a.CacheTTL.Duration),
		RequiredClaims:  a.RequiredClaims,
		ForwardClaims:   a.ForwardClaims,
		CookieName:      a.CookieName,
	}
}

func accessControlToProto(a *config.AccessControlConfig) *csarv1.AccessControlProto {
	return &csarv1.AccessControlProto{
		AllowCidrs: a.AllowCIDRs,
		TrustProxy: a.TrustProxy,
	}
}

func protocolToProto(p *config.ProtocolPolicy) *csarv1.ProtocolPolicyProto {
	pb := &csarv1.ProtocolPolicyProto{}
	if p.EmitWaitMS != nil {
		pb.EmitWaitMs = *p.EmitWaitMS
		pb.EmitWaitMsSet = true
	}
	if p.TransparentRetry != nil {
		pb.TransparentRetry = *p.TransparentRetry
		pb.TransparentRetrySet = true
	}
	if p.EmitClientHint != nil {
		pb.EmitClientHint = *p.EmitClientHint
		pb.EmitClientHintSet = true
	}
	return pb
}

func debugHeadersToProto(d *config.DebugHeadersConfig) *csarv1.DebugHeadersProto {
	pb := &csarv1.DebugHeadersProto{
		Enabled:         d.Enabled,
		RequestIdHeader: d.RequestIDHeader,
	}
	if d.EmitRouteID != nil {
		pb.EmitRouteId = *d.EmitRouteID
		pb.EmitRouteIdSet = true
	}
	return pb
}

// ---------------------------------------------------------------------------
// Top-level policy map converters
// ---------------------------------------------------------------------------

func circuitBreakersToProto(cbs map[string]config.CircuitBreakerProfile) map[string]*csarv1.CircuitBreakerProfileProto {
	if len(cbs) == 0 {
		return nil
	}
	out := make(map[string]*csarv1.CircuitBreakerProfileProto, len(cbs))
	for name, cb := range cbs {
		out[name] = &csarv1.CircuitBreakerProfileProto{
			MaxRequests:      cb.MaxRequests,
			Interval:         durationpb.New(cb.Interval.Duration),
			Timeout:          durationpb.New(cb.Timeout.Duration),
			FailureThreshold: cb.FailureThreshold,
		}
	}
	return out
}

func securityProfilesToProto(profiles map[string]config.SecurityConfig) map[string]*csarv1.SecurityConfigProto {
	if len(profiles) == 0 {
		return nil
	}
	out := make(map[string]*csarv1.SecurityConfigProto, len(profiles))
	for name := range profiles {
		s := profiles[name]
		out[name] = securityToProto(&s)
	}
	return out
}

func throttlingPoliciesToProto(policies map[string]config.ThrottlingPolicy) map[string]*csarv1.ThrottlingPolicyProto {
	if len(policies) == 0 {
		return nil
	}
	out := make(map[string]*csarv1.ThrottlingPolicyProto, len(policies))
	for name, p := range policies {
		tp := &csarv1.ThrottlingPolicyProto{
			Rps:             p.RPS,
			Burst:           safeInt32(p.Burst),
			MaxWait:         durationpb.New(p.MaxWait.Duration),
			Backend:         p.Backend,
			Key:             p.Key,
			ExcludeIps:      p.ExcludeIPs,
			ClientLimitMode: p.ClientLimitMode,
		}
		if len(p.VIPOverrides) > 0 {
			tp.VipOverrides = make([]*csarv1.VIPOverrideProto, 0, len(p.VIPOverrides))
			for _, v := range p.VIPOverrides {
				tp.VipOverrides = append(tp.VipOverrides, &csarv1.VIPOverrideProto{
					Header: v.Header,
					Values: v.Values,
				})
			}
		}
		out[name] = tp
	}
	return out
}

func corsPoliciesMapToProto(policies map[string]config.CORSConfig) map[string]*csarv1.CORSConfigProto {
	if len(policies) == 0 {
		return nil
	}
	out := make(map[string]*csarv1.CORSConfigProto, len(policies))
	for name := range policies {
		c := policies[name]
		out[name] = corsToProto(&c)
	}
	return out
}

func retryPoliciesMapToProto(policies map[string]config.RetryConfig) map[string]*csarv1.RetryConfigProto {
	if len(policies) == 0 {
		return nil
	}
	out := make(map[string]*csarv1.RetryConfigProto, len(policies))
	for name := range policies {
		r := policies[name]
		out[name] = retryToProto(&r)
	}
	return out
}

func redactPoliciesMapToProto(policies map[string]config.RedactConfig) map[string]*csarv1.RedactConfigProto {
	if len(policies) == 0 {
		return nil
	}
	out := make(map[string]*csarv1.RedactConfigProto, len(policies))
	for name := range policies {
		r := policies[name]
		out[name] = redactToProto(&r)
	}
	return out
}

func authValidatePoliciesMapToProto(policies map[string]config.AuthValidateConfig) map[string]*csarv1.AuthValidateConfigProto {
	if len(policies) == 0 {
		return nil
	}
	out := make(map[string]*csarv1.AuthValidateConfigProto, len(policies))
	for name := range policies {
		a := policies[name]
		out[name] = authValidateToProto(&a)
	}
	return out
}

func authzToProto(a *config.AuthzRouteConfig) *csarv1.AuthzRouteConfigProto {
	return &csarv1.AuthzRouteConfigProto{
		Use:          a.Use,
		Subject:      a.Subject,
		Resource:     a.Resource,
		Action:       a.Action,
		ScopeType:    a.ScopeType,
		ScopeId:      a.ScopeID,
		StripHeaders: a.StripHeaders,
	}
}

func authzPoliciesMapToProto(policies map[string]config.AuthzRouteConfig) map[string]*csarv1.AuthzRouteConfigProto {
	if len(policies) == 0 {
		return nil
	}
	out := make(map[string]*csarv1.AuthzRouteConfigProto, len(policies))
	for name := range policies {
		a := policies[name]
		out[name] = authzToProto(&a)
	}
	return out
}

func backendTLSPoliciesToProto(policies map[string]config.BackendTLSPolicy) map[string]*csarv1.BackendTLSConfigProto {
	if len(policies) == 0 {
		return nil
	}
	out := make(map[string]*csarv1.BackendTLSConfigProto, len(policies))
	for name, p := range policies {
		out[name] = &csarv1.BackendTLSConfigProto{
			InsecureSkipVerify: p.InsecureSkipVerify,
			CaFile:             p.CAFile,
			CertFile:           p.CertFile,
			KeyFile:            p.KeyFile,
		}
	}
	return out
}
