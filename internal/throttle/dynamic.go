package throttle

import (
	"context"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"sync/atomic"
	"time"

	"github.com/redis/go-redis/v9"
)

// Compile-time check: DynamicThrottler satisfies Waiter.
var _ Waiter = (*DynamicThrottler)(nil)

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

// placeholderPattern matches {query.param} and {header.Header-Name} placeholders.
var placeholderPattern = regexp.MustCompile(`\{(query|header)\.([^}]+)\}`)

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

	// Resolve the dynamic key from the request
	req := requestFromContext(ctx)
	resolvedKey := dt.resolveKey(req)
	key := dt.keyPrefix + resolvedKey

	// GCRA parameters in milliseconds
	emissionIntervalMS := int64(1000.0 / dt.rps)
	if emissionIntervalMS < 1 {
		emissionIntervalMS = 1
	}
	burstOffsetMS := emissionIntervalMS * int64(dt.burst)
	maxWaitMS := dt.maxWait.Milliseconds()

	deadline := time.Now().Add(dt.maxWait)

	for {
		if ctx.Err() != nil {
			return fmt.Errorf("client cancelled: %w", ctx.Err())
		}

		nowMS := time.Now().UnixMilli()
		result, err := dt.script.Run(ctx, dt.client, []string{key},
			emissionIntervalMS, burstOffsetMS, nowMS, maxWaitMS,
		).Int64()
		if err != nil {
			return fmt.Errorf("redis GCRA error: %w", err)
		}

		switch {
		case result == 0:
			return nil
		case result == -1:
			return fmt.Errorf("queue timeout exceeded (%s): rate limit reached for key %q", dt.maxWait, resolvedKey)
		case result > 0:
			parkDuration := time.Duration(result) * time.Millisecond
			remaining := time.Until(deadline)
			if remaining <= 0 {
				return fmt.Errorf("queue timeout exceeded (%s): rate limit reached for key %q", dt.maxWait, resolvedKey)
			}
			if parkDuration > remaining {
				parkDuration = remaining
			}
			select {
			case <-ctx.Done():
				return fmt.Errorf("client cancelled: %w", ctx.Err())
			case <-time.After(parkDuration):
				continue
			}
		}
	}
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
// Unresolved placeholders are replaced with "_unknown_".
func (dt *DynamicThrottler) resolveKey(req *http.Request) string {
	if req == nil {
		return dt.keyTemplate
	}
	return placeholderPattern.ReplaceAllStringFunc(dt.keyTemplate, func(match string) string {
		parts := placeholderPattern.FindStringSubmatch(match)
		if len(parts) != 3 {
			return "_unknown_"
		}
		source, name := parts[1], parts[2]
		switch source {
		case "query":
			v := req.URL.Query().Get(name)
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
