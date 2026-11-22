package router

import (
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/ledatu/csar-core/caller"
	"github.com/ledatu/csar-core/usagebudget"
	"github.com/ledatu/csar/internal/apierror"
	"github.com/ledatu/csar/internal/config"
	"github.com/ledatu/csar/internal/redisx"
	"github.com/ledatu/csar/pkg/middleware/authzmw"
	"github.com/redis/go-redis/v9"
)

func (r *Router) setupUsage(cfg *config.Config) error {
	policies := make(map[string]config.UsageBudgetConfig)
	routes := cfg.FlatRoutes()
	for i := range routes {
		policy := routes[i].Route.UsageBudget
		if policy == nil {
			continue
		}
		if policy.Validate() != nil || routes[i].Route.AuthValidate == nil || routes[i].Route.Authz == nil {
			return fmt.Errorf("route %s: usage budget requires valid policy, authn and authz", routes[i].Path)
		}
		if prior, ok := policies[policy.Name]; ok && prior != *policy {
			return fmt.Errorf("usage policy %s has conflicting route limits", policy.Name)
		}
		policies[policy.Name] = *policy
	}
	if len(policies) == 0 {
		return nil
	}
	if r.redisClient == nil {
		return fmt.Errorf("usage budgets require Redis")
	}
	// Reuse endpoint/credentials/TLS, but isolate admission in a bounded pool with
	// context-aware socket IO and no ambiguous command replay. Legacy pools stay unchanged.
	options := *r.redisClient.Options()
	// Options() contains the existing client's live push processor. A new pool
	// needs its own processor rather than re-registering handlers on that object.
	options.PushNotificationProcessor = nil
	options.ContextTimeoutEnabled = true
	options.MaxRetries = -1
	options.PoolSize = 8
	options.MaxActiveConns = 8
	options.MinIdleConns = 0
	options.DialTimeout = 250 * time.Millisecond
	options.ReadTimeout = 250 * time.Millisecond
	options.WriteTimeout = 250 * time.Millisecond
	options.PoolTimeout = 250 * time.Millisecond
	r.usageRedis = redis.NewClient(&options)
	if r.metrics != nil {
		r.usageRedis.AddHook(redisx.NewErrorHook(r.metrics.RecordRedisCommandError))
	}
	prefix := "csar:usage:"
	if cfg.Redis != nil {
		prefix = cfg.Redis.KeyPrefix + prefix
	}
	var err error
	r.usageLimiter, err = usagebudget.New(r.usageRedis, prefix, 250*time.Millisecond)
	return err
}

func (r *Router) admitUsage(w http.ResponseWriter, req *http.Request, rt *route) bool {
	policy := rt.config.UsageBudget
	if policy == nil {
		return true
	}
	auditStage(req, "usage_admission")
	state := auditState(req)
	scope, allowed := authzmw.ScopeFromContext(req.Context())
	if state == nil || !state.verified || !allowed || scope.Type != "tenant" || scope.ID == "" || !caller.ValidReference(scope.ID) {
		apierror.New("caller_context_required", http.StatusForbidden, "usage admission requires verified tenant context").Write(w)
		return false
	}
	principal := state.identity.Caller
	if state.originCaller != nil {
		principal = state.originCaller
	}
	if principal == nil || principal.CallerID == "" || principal.Assurance != caller.Verified {
		apierror.New("caller_context_required", http.StatusForbidden, "usage admission requires registered caller metadata").Write(w)
		return false
	}
	owner := principal.OwnerSubject
	if owner == "" && principal.CallerKind == caller.Service {
		owner = principal.EffectiveSubject
	}
	if owner == "" || !caller.ValidReference(owner) {
		apierror.New("caller_context_required", http.StatusForbidden, "usage admission requires verified owner").Write(w)
		return false
	}
	request := policy.Request(string(principal.CallerKind)+":"+principal.CallerID, owner, scope.ID)
	err := r.usageLimiter.Take(redisx.WithSubsystem(req.Context(), redisx.SubsystemUsage), request)
	if err == nil {
		return true
	}
	var exceeded *usagebudget.Exceeded
	if errors.As(err, &exceeded) {
		retry := max(int64(1), exceeded.RetryAfter.Milliseconds())
		w.Header().Set("X-CSAR-Status", "usage_exceeded")
		w.Header().Set("Retry-After", strconv.FormatInt((retry+999)/1000, 10))
		apierror.New("usage_exceeded", http.StatusTooManyRequests, "usage budget exceeded").WithDetail(exceeded.Dimension).WithRetryAfterMS(retry).WithRequestID(r.requestID(req)).Write(w)
	} else {
		w.Header().Set("X-CSAR-Status", "usage_unavailable")
		apierror.New("usage_unavailable", http.StatusServiceUnavailable, "usage admission unavailable").WithRequestID(r.requestID(req)).Write(w)
	}
	return false
}
