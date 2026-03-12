// Package protoconv converts between gRPC proto messages and config types.
//
// ProtoToConfig reconstructs a config.Config from a FullConfigSnapshot
// received over the coordinator gRPC stream, enabling routers to rebuild
// their routing tables from coordinator-pushed configuration.
package protoconv

import (
	"strings"

	"github.com/ledatu/csar-core/configutil"
	"github.com/ledatu/csar/internal/config"
	csarv1 "github.com/ledatu/csar/proto/csar/v1"
)

// FullSnapshotToConfig converts a FullConfigSnapshot proto message into
// a config.Config suitable for building a router.Router.
func FullSnapshotToConfig(snap *csarv1.FullConfigSnapshot) *config.Config {
	cfg := &config.Config{
		Paths: make(map[string]config.PathConfig),
	}

	for _, r := range snap.GetRoutes() {
		rc := protoToRouteConfig(r)
		method := strings.ToLower(r.GetMethod())
		path := r.GetPath()

		if _, ok := cfg.Paths[path]; !ok {
			cfg.Paths[path] = make(config.PathConfig)
		}
		cfg.Paths[path][method] = rc
	}

	cfg.CircuitBreakers = protoToCircuitBreakers(snap.GetCircuitBreakers())
	cfg.SecurityProfiles = protoToSecurityProfiles(snap.GetSecurityProfiles())
	cfg.ThrottlingPolicies = protoToThrottlingPolicies(snap.GetThrottlingPolicies())
	cfg.CORSPolicies = protoToCORSPolicies(snap.GetCorsPolicies())
	cfg.RetryPolicies = protoToRetryPolicies(snap.GetRetryPolicies())
	cfg.RedactPolicies = protoToRedactPolicies(snap.GetRedactPolicies())
	cfg.AuthValidatePolicies = protoToAuthValidatePolicies(snap.GetAuthValidatePolicies())
	cfg.AuthzPolicies = protoToAuthzPolicies(snap.GetAuthzPolicies())

	if gt := snap.GetGlobalThrottle(); gt != nil {
		cfg.GlobalThrottle = &config.GlobalThrottleConfig{
			RPS:     gt.GetRps(),
			Burst:   int(gt.GetBurst()),
			MaxWait: configutil.Duration{Duration: gt.GetMaxWait().AsDuration()},
		}
	}

	if dh := snap.GetDebugHeaders(); dh != nil {
		cfg.DebugHeaders = protoToDebugHeaders(dh)
	}

	if ac := snap.GetGlobalAccessControl(); ac != nil {
		cfg.AccessControl = protoToAccessControl(ac)
	}

	return cfg
}

func protoToRouteConfig(r *csarv1.RouteConfig) config.RouteConfig {
	rc := config.RouteConfig{}

	// Use full backend if available, else fall back to legacy target_url.
	if b := r.GetBackend(); b != nil {
		rc.Backend = protoToBackend(b)
	} else if r.GetTargetUrl() != "" {
		rc.Backend = config.BackendConfig{TargetURL: r.GetTargetUrl()}
	}

	// Securities (full list) takes precedence over legacy single security.
	if secs := r.GetSecurities(); len(secs) > 0 {
		rc.Security = make(config.SecurityConfigs, 0, len(secs))
		for _, s := range secs {
			rc.Security = append(rc.Security, protoToSecurity(s))
		}
	} else if s := r.GetSecurity(); s != nil {
		rc.Security = config.SecurityConfigs{protoToSecurity(s)}
	}

	// Traffic (full) takes precedence over legacy.
	if t := r.GetTrafficConfig(); t != nil {
		tc := protoToTraffic(t)
		rc.Traffic = &tc
	} else if t := r.GetTraffic(); t != nil {
		tc := protoToTraffic(t)
		rc.Traffic = &tc
	}

	if r.GetRetry() != nil {
		rc.Retry = protoToRetryConfig(r.GetRetry())
	}
	if r.GetRedact() != nil {
		rc.Redact = protoToRedactConfig(r.GetRedact())
	}
	if r.GetCors() != nil {
		rc.CORS = protoToCORSConfig(r.GetCors())
	}
	if r.GetTenant() != nil {
		rc.Tenant = protoToTenantConfig(r.GetTenant())
	}
	if r.GetCache() != nil {
		rc.Cache = protoToCacheConfig(r.GetCache())
	}
	if r.GetAuthValidate() != nil {
		rc.AuthValidate = protoToAuthValidateConfig(r.GetAuthValidate())
	}
	if r.GetAccess() != nil {
		rc.Access = protoToAccessControl(r.GetAccess())
	}

	// Resilience: prefer full message, fall back to legacy field.
	if res := r.GetResilience(); res != nil && res.GetCircuitBreaker() != "" {
		rc.Resilience = &config.ResilienceConfig{CircuitBreaker: res.GetCircuitBreaker()}
	} else if r.GetResilienceProfile() != "" {
		rc.Resilience = &config.ResilienceConfig{CircuitBreaker: r.GetResilienceProfile()}
	}

	if len(r.GetHeaders()) > 0 {
		rc.Headers = r.GetHeaders()
	}
	rc.MaxResponseSize = r.GetMaxResponseSize()
	if r.GetProtocol() != nil {
		rc.Protocol = protoToProtocol(r.GetProtocol())
	}
	if r.GetAuthz() != nil {
		rc.Authz = protoToAuthzRouteConfig(r.GetAuthz())
	}

	return rc
}

func protoToBackend(b *csarv1.BackendConfigProto) config.BackendConfig {
	bc := config.BackendConfig{
		TargetURL:    b.GetTargetUrl(),
		Targets:      b.GetTargets(),
		LoadBalancer: b.GetLoadBalancer(),
		PathRewrite:  b.GetPathRewrite(),
		PathMode:     b.GetPathMode(),
	}
	if hc := b.GetHealthCheck(); hc != nil {
		bc.HealthCheck = &config.HealthCheckConfig{
			Enabled:            hc.GetEnabled(),
			Mode:               hc.GetMode(),
			Path:               hc.GetPath(),
			Interval:           configutil.Duration{Duration: hc.GetInterval().AsDuration()},
			Timeout:            configutil.Duration{Duration: hc.GetTimeout().AsDuration()},
			UnhealthyThreshold: int(hc.GetUnhealthyThreshold()),
			HealthyThreshold:   int(hc.GetHealthyThreshold()),
		}
	}
	if t := b.GetTls(); t != nil {
		bc.TLS = &config.BackendTLSConfig{
			InsecureSkipVerify: t.GetInsecureSkipVerify(),
			CAFile:             t.GetCaFile(),
			CertFile:           t.GetCertFile(),
			KeyFile:            t.GetKeyFile(),
		}
	}
	return bc
}

func protoToSecurity(s *csarv1.SecurityConfigProto) config.SecurityConfig {
	sc := config.SecurityConfig{
		Profile:      s.GetProfile(),
		KMSKeyID:     s.GetKmsKeyId(),
		TokenRef:     s.GetTokenRef(),
		TokenVersion: s.GetTokenVersion(),
		InjectHeader: s.GetInjectHeader(),
		InjectFormat: s.GetInjectFormat(),
		OnKMSError:   s.GetOnKmsError(),
	}
	if s.GetStripTokenParamsSet() {
		v := s.GetStripTokenParams()
		sc.StripTokenParams = &v
	}
	return sc
}

func protoToTraffic(t *csarv1.TrafficConfigProto) config.TrafficConfig {
	tc := config.TrafficConfig{
		Use:             t.GetUse(),
		RPS:             t.GetRps(),
		Burst:           int(t.GetBurst()),
		MaxWait:         configutil.Duration{Duration: t.GetMaxWait().AsDuration()},
		Backend:         t.GetBackend(),
		Key:             t.GetKey(),
		ExcludeIPs:      t.GetExcludeIps(),
		ClientLimitMode: t.GetClientLimitMode(),
	}
	if vips := t.GetVipOverrides(); len(vips) > 0 {
		tc.VIPOverrides = make([]config.VIPOverride, 0, len(vips))
		for _, v := range vips {
			tc.VIPOverrides = append(tc.VIPOverrides, config.VIPOverride{
				Header: v.GetHeader(),
				Values: v.GetValues(),
			})
		}
	}
	if abp := t.GetAdaptiveBackpressure(); abp != nil {
		tc.AdaptiveBackpressure = &config.AdaptiveBackpressureConfig{
			Enabled:        abp.GetEnabled(),
			RespectHeaders: abp.GetRespectHeaders(),
			SuspendBucket:  abp.GetSuspendBucket(),
			MaxBodyBuffer:  abp.GetMaxBodyBuffer(),
		}
	}
	return tc
}

func protoToRetryConfig(r *csarv1.RetryConfigProto) *config.RetryConfig {
	rc := &config.RetryConfig{
		Use:              r.GetUse(),
		MaxAttempts:      int(r.GetMaxAttempts()),
		Backoff:          configutil.Duration{Duration: r.GetBackoff().AsDuration()},
		MaxBackoff:       configutil.Duration{Duration: r.GetMaxBackoff().AsDuration()},
		AutoRetry429:     r.GetAutoRetry_429(),
		MaxInternalWait:  configutil.Duration{Duration: r.GetMaxInternalWait().AsDuration()},
		RetryableMethods: r.GetRetryableMethods(),
	}
	if codes := r.GetRetryableStatusCodes(); len(codes) > 0 {
		rc.RetryableStatusCodes = make([]int, len(codes))
		for i, code := range codes {
			rc.RetryableStatusCodes[i] = int(code)
		}
	}
	return rc
}

func protoToRedactConfig(r *csarv1.RedactConfigProto) *config.RedactConfig {
	rc := &config.RedactConfig{
		Use:    r.GetUse(),
		Fields: r.GetFields(),
		Mask:   r.GetMask(),
	}
	if r.GetEnabledSet() {
		v := r.GetEnabled()
		rc.Enabled = &v
	}
	return rc
}

func protoToCORSConfig(c *csarv1.CORSConfigProto) *config.CORSConfig {
	return &config.CORSConfig{
		Use:              c.GetUse(),
		AllowedOrigins:   c.GetAllowedOrigins(),
		AllowedMethods:   c.GetAllowedMethods(),
		AllowedHeaders:   c.GetAllowedHeaders(),
		ExposedHeaders:   c.GetExposedHeaders(),
		AllowCredentials: c.GetAllowCredentials(),
		MaxAge:           int(c.GetMaxAge()),
	}
}

func protoToTenantConfig(t *csarv1.TenantConfigProto) *config.TenantConfig {
	return &config.TenantConfig{
		Header:   t.GetHeader(),
		Backends: t.GetBackends(),
		Default:  t.GetDefaultBackend(),
	}
}

func protoToCacheConfig(c *csarv1.CacheConfigProto) *config.CacheConfig {
	cc := &config.CacheConfig{
		TTL:         configutil.Duration{Duration: c.GetTtl().AsDuration()},
		MaxEntries:  int(c.GetMaxEntries()),
		MaxBodySize: c.GetMaxBodySize(),
		Methods:     c.GetMethods(),
	}
	if c.GetEnabledSet() {
		v := c.GetEnabled()
		cc.Enabled = &v
	}
	return cc
}

func protoToAuthValidateConfig(a *csarv1.AuthValidateConfigProto) *config.AuthValidateConfig {
	return &config.AuthValidateConfig{
		Use:            a.GetUse(),
		JWKSURL:        a.GetJwksUrl(),
		Issuer:         a.GetIssuer(),
		Audiences:      a.GetAudiences(),
		HeaderName:     a.GetHeaderName(),
		TokenPrefix:    a.GetTokenPrefix(),
		CacheTTL:       configutil.Duration{Duration: a.GetCacheTtl().AsDuration()},
		RequiredClaims: a.GetRequiredClaims(),
		ForwardClaims:  a.GetForwardClaims(),
		CookieName:     a.GetCookieName(),
	}
}

func protoToAccessControl(a *csarv1.AccessControlProto) *config.AccessControlConfig {
	return &config.AccessControlConfig{
		AllowCIDRs: a.GetAllowCidrs(),
		TrustProxy: a.GetTrustProxy(),
	}
}

func protoToProtocol(p *csarv1.ProtocolPolicyProto) *config.ProtocolPolicy {
	pp := &config.ProtocolPolicy{}
	if p.GetEmitWaitMsSet() {
		v := p.GetEmitWaitMs()
		pp.EmitWaitMS = &v
	}
	if p.GetTransparentRetrySet() {
		v := p.GetTransparentRetry()
		pp.TransparentRetry = &v
	}
	if p.GetEmitClientHintSet() {
		v := p.GetEmitClientHint()
		pp.EmitClientHint = &v
	}
	return pp
}

func protoToDebugHeaders(d *csarv1.DebugHeadersProto) *config.DebugHeadersConfig {
	dh := &config.DebugHeadersConfig{
		Enabled:         d.GetEnabled(),
		RequestIDHeader: d.GetRequestIdHeader(),
	}
	if d.GetEmitRouteIdSet() {
		v := d.GetEmitRouteId()
		dh.EmitRouteID = &v
	}
	return dh
}

// ---------------------------------------------------------------------------
// Top-level policy map converters
// ---------------------------------------------------------------------------

func protoToCircuitBreakers(cbs map[string]*csarv1.CircuitBreakerProfileProto) map[string]config.CircuitBreakerProfile {
	if len(cbs) == 0 {
		return nil
	}
	out := make(map[string]config.CircuitBreakerProfile, len(cbs))
	for name, cb := range cbs {
		out[name] = config.CircuitBreakerProfile{
			MaxRequests:      cb.GetMaxRequests(),
			Interval:         configutil.Duration{Duration: cb.GetInterval().AsDuration()},
			Timeout:          configutil.Duration{Duration: cb.GetTimeout().AsDuration()},
			FailureThreshold: cb.GetFailureThreshold(),
		}
	}
	return out
}

func protoToSecurityProfiles(profiles map[string]*csarv1.SecurityConfigProto) map[string]config.SecurityConfig {
	if len(profiles) == 0 {
		return nil
	}
	out := make(map[string]config.SecurityConfig, len(profiles))
	for name, s := range profiles {
		out[name] = protoToSecurity(s)
	}
	return out
}

func protoToThrottlingPolicies(policies map[string]*csarv1.ThrottlingPolicyProto) map[string]config.ThrottlingPolicy {
	if len(policies) == 0 {
		return nil
	}
	out := make(map[string]config.ThrottlingPolicy, len(policies))
	for name, p := range policies {
		tp := config.ThrottlingPolicy{
			RPS:             p.GetRps(),
			Burst:           int(p.GetBurst()),
			MaxWait:         configutil.Duration{Duration: p.GetMaxWait().AsDuration()},
			Backend:         p.GetBackend(),
			Key:             p.GetKey(),
			ExcludeIPs:      p.GetExcludeIps(),
			ClientLimitMode: p.GetClientLimitMode(),
		}
		if vips := p.GetVipOverrides(); len(vips) > 0 {
			tp.VIPOverrides = make([]config.VIPOverride, 0, len(vips))
			for _, v := range vips {
				tp.VIPOverrides = append(tp.VIPOverrides, config.VIPOverride{
					Header: v.GetHeader(),
					Values: v.GetValues(),
				})
			}
		}
		out[name] = tp
	}
	return out
}

func protoToCORSPolicies(policies map[string]*csarv1.CORSConfigProto) map[string]config.CORSConfig {
	if len(policies) == 0 {
		return nil
	}
	out := make(map[string]config.CORSConfig, len(policies))
	for name, c := range policies {
		out[name] = *protoToCORSConfig(c)
	}
	return out
}

func protoToRetryPolicies(policies map[string]*csarv1.RetryConfigProto) map[string]config.RetryConfig {
	if len(policies) == 0 {
		return nil
	}
	out := make(map[string]config.RetryConfig, len(policies))
	for name, r := range policies {
		out[name] = *protoToRetryConfig(r)
	}
	return out
}

func protoToRedactPolicies(policies map[string]*csarv1.RedactConfigProto) map[string]config.RedactConfig {
	if len(policies) == 0 {
		return nil
	}
	out := make(map[string]config.RedactConfig, len(policies))
	for name, r := range policies {
		out[name] = *protoToRedactConfig(r)
	}
	return out
}

func protoToAuthValidatePolicies(policies map[string]*csarv1.AuthValidateConfigProto) map[string]config.AuthValidateConfig {
	if len(policies) == 0 {
		return nil
	}
	out := make(map[string]config.AuthValidateConfig, len(policies))
	for name, a := range policies {
		out[name] = *protoToAuthValidateConfig(a)
	}
	return out
}

func protoToAuthzRouteConfig(a *csarv1.AuthzRouteConfigProto) *config.AuthzRouteConfig {
	return &config.AuthzRouteConfig{
		Use:          a.GetUse(),
		Subject:      a.GetSubject(),
		Resource:     a.GetResource(),
		Action:       a.GetAction(),
		ScopeType:    a.GetScopeType(),
		ScopeID:      a.GetScopeId(),
		StripHeaders: a.GetStripHeaders(),
	}
}

func protoToAuthzPolicies(policies map[string]*csarv1.AuthzRouteConfigProto) map[string]config.AuthzRouteConfig {
	if len(policies) == 0 {
		return nil
	}
	out := make(map[string]config.AuthzRouteConfig, len(policies))
	for name, a := range policies {
		out[name] = *protoToAuthzRouteConfig(a)
	}
	return out
}
