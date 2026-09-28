package throttle

import (
	"context"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync/atomic"
	"time"

	"github.com/redis/go-redis/v9"

	"github.com/ledatu/csar/pkg/middleware/authzmw"
)

// Compile-time check: DynamicThrottler satisfies Waiter.
var _ Waiter = (*DynamicThrottler)(nil)
var _ RequestSuspendable = (*DynamicThrottler)(nil)

// requestContextKey is the context key type for storing the HTTP request.
type requestContextKey struct{}

// WithRequest stores the HTTP request in the context so that DynamicThrottler
// can extract placeholder values. Called by the router before throttle.Wait().
func WithRequest(ctx context.Context, r *http.Request) context.Context {
	return context.WithValue(ctx, requestContextKey{}, r)
}

// requestFromContext extracts the HTTP request from the context.
func requestFromContext(ctx context.Context) *http.Request {
	r, _ := ctx.Value(requestContextKey{}).(*http.Request)
	return r
}

// originalQueryKey is the context key for storing a pre-strip query snapshot.
type originalQueryKey struct{}

// WithOriginalQuery stores a snapshot of the URL query values in the context
// BEFORE strip_token_params removes consumed query parameters. This ensures
// DynamicThrottler.resolveKey can resolve {query.*} keys from the original
// URL even after StripQueryKeys has mutated the request's URL in place.
func WithOriginalQuery(ctx context.Context, values url.Values) context.Context {
	return context.WithValue(ctx, originalQueryKey{}, values)
}

// originalQueryFromContext retrieves the pre-strip query snapshot, or nil.
func originalQueryFromContext(ctx context.Context) url.Values {
	v, _ := ctx.Value(originalQueryKey{}).(url.Values)
	return v
}

// placeholderPattern matches {query.param}, {header.Header-Name} and
// {path.var} placeholders.
var placeholderPattern = regexp.MustCompile(`\{(query|header|path)\.([^}]+)\}`)

// DynamicThrottler implements per-entity rate limiting using dynamic key templates.
// Each unique resolved key gets its own Redis GCRA rate limiter.
//
// Key template examples:
//
//	"seller:{query.seller_id}"    → per-seller throttling
//	"api:{header.X-API-Key}"     → per-API-key throttling
//	"user:{query.user_id}:{header.X-Tenant}" → composite key
type DynamicThrottler struct {
	client      *redis.Client
	script      *redis.Script
	keyPrefix   string
	keyTemplate string

	rps     float64
	burst   int
	maxWait time.Duration

	// Observability
	waiting atomic.Int64
}

// NewDynamicThrottler creates a DynamicThrottler for per-entity rate limiting.
// The keyTemplate contains placeholders like {query.param} and {header.Name}
// that are resolved from the HTTP request at runtime.
func NewDynamicThrottler(client *redis.Client, keyPrefix, keyTemplate string, rps float64, burst int, maxWait time.Duration) *DynamicThrottler {
	if keyPrefix == "" {
		keyPrefix = "csar:rl:"
	}
	return &DynamicThrottler{
		client:      client,
		script:      redis.NewScript(gcraScript),
		keyPrefix:   keyPrefix,
		keyTemplate: keyTemplate,
		rps:         rps,
		burst:       burst,
		maxWait:     maxWait,
	}
}

// Wait blocks until the request is allowed or the timeout is exceeded.
// The dynamic key is resolved from the HTTP request stored in the context.
func (dt *DynamicThrottler) Wait(ctx context.Context) error {
	dt.waiting.Add(1)
	defer dt.waiting.Add(-1)

	resolvedKey := dt.resolveKey(requestFromContext(ctx))
	return gcraWait(ctx, dt.client, dt.script, dt.keyPrefix+resolvedKey, resolvedKey,
		newGCRAParams(dt.rps, dt.burst), dt.maxWait)
}

// SuspendRequestFor holds back only the key that r resolves to, so an
// upstream 429 for one entity does not pause the others.
func (dt *DynamicThrottler) SuspendRequestFor(r *http.Request, d time.Duration) error {
	ctx, cancel := context.WithTimeout(context.Background(), suspendTimeout)
	defer cancel()
	return gcraSuspend(ctx, dt.client, dt.keyPrefix+dt.resolveKey(r), newGCRAParams(dt.rps, dt.burst), d)
}

// Waiting returns the number of requests currently waiting.
func (dt *DynamicThrottler) Waiting() int64 {
	return dt.waiting.Load()
}

// UpdateLimit dynamically changes the rate limit.
func (dt *DynamicThrottler) UpdateLimit(rps float64, burst int) {
	dt.rps = rps
	dt.burst = burst
}

// resolveKey replaces placeholders in the key template with values from the request.
// {query.param} → URL query parameter value
// {header.Name} → HTTP header value
// {path.var}    → route path variable, as captured before path rewriting
// Unresolved placeholders are replaced with "_unknown_".
//
// For {query.*} lookups, resolveKey first checks for a pre-strip query snapshot
// stored in the request context by WithOriginalQuery. This handles the case where
// strip_token_params has removed query params (e.g. id) that the throttle
// key template still needs to resolve.
func (dt *DynamicThrottler) resolveKey(req *http.Request) string {
	if req == nil {
		return dt.keyTemplate
	}
	// Pre-fetch the original query snapshot (may be nil if no stripping occurred).
	origQuery := originalQueryFromContext(req.Context())

	return placeholderPattern.ReplaceAllStringFunc(dt.keyTemplate, func(match string) string {
		parts := placeholderPattern.FindStringSubmatch(match)
		if len(parts) != 3 {
			return "_unknown_"
		}
		source, name := parts[1], parts[2]
		switch source {
		case "query":
			// Prefer pre-strip snapshot so {query.seller_id} resolves even
			// after StripQueryKeys has removed seller_id from the live URL.
			var v string
			if origQuery != nil {
				v = origQuery.Get(name)
			}
			if v == "" {
				v = req.URL.Query().Get(name)
			}
			if v == "" {
				return "_unknown_"
			}
			return sanitizeKeyPart(v)
		case "header":
			v := req.Header.Get(name)
			if v == "" {
				return "_unknown_"
			}
			return sanitizeKeyPart(v)
		case "path":
			v := authzmw.PathVarsFromContext(req.Context())[name]
			if v == "" {
				return "_unknown_"
			}
			return sanitizeKeyPart(v)
		default:
			return "_unknown_"
		}
	})
}

// sanitizeKeyPart removes characters that could cause issues in Redis keys.
// Allows alphanumeric, dash, underscore, dot, and colon.
func sanitizeKeyPart(s string) string {
	if len(s) > 128 {
		s = s[:128]
	}
	var b strings.Builder
	b.Grow(len(s))
	for _, c := range s {
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
			c == '-' || c == '_' || c == '.' || c == ':' {
			b.WriteRune(c)
		}
	}
	return b.String()
}

// ExtractKeyPlaceholders returns the placeholder names from a key template.
// Used by the router to determine if a throttle has dynamic keys.
func ExtractKeyPlaceholders(keyTemplate string) []string {
	matches := placeholderPattern.FindAllStringSubmatch(keyTemplate, -1)
	var result []string
	for _, m := range matches {
		if len(m) >= 3 {
			result = append(result, m[1]+"."+m[2])
		}
	}
	return result
}
