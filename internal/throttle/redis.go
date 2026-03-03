package throttle

import (
	"context"
	"fmt"
	"sync/atomic"
	"time"

	"github.com/redis/go-redis/v9"
)

// slidingWindowScript is an atomic Lua script that implements a sliding window
// rate limiter in Redis. It increments a counter for the current window,
// sets expiry on first use, and returns 1 if allowed, 0 if denied.
const slidingWindowScript = `
local key = KEYS[1]
local limit = tonumber(ARGV[1])
local window_ms = tonumber(ARGV[2])

local count = redis.call('INCR', key)
if count == 1 then
    redis.call('PEXPIRE', key, window_ms)
end
if count > limit then
    return 0
end
return 1
`

// RedisThrottler implements distributed rate limiting via a Redis sliding window.
// It provides the same Wait-based interface as the local Throttler.
type RedisThrottler struct {
	client    *redis.Client
	script    *redis.Script
	keyPrefix string
	routeKey  string

	rps     float64
	burst   int
	maxWait time.Duration

	// Observability
	waiting atomic.Int64
}

// RedisConfig holds connection settings for the Redis rate limiter.
type RedisConfig struct {
	Address   string
	Password  string
	DB        int
	KeyPrefix string
}

// NewRedisClient creates a shared Redis client from the config.
func NewRedisClient(cfg RedisConfig) *redis.Client {
	return redis.NewClient(&redis.Options{
		Addr:     cfg.Address,
		Password: cfg.Password,
		DB:       cfg.DB,
	})
}

// NewRedisThrottler creates a RedisThrottler for a specific route.
func NewRedisThrottler(client *redis.Client, keyPrefix, routeKey string, rps float64, burst int, maxWait time.Duration) *RedisThrottler {
	if keyPrefix == "" {
		keyPrefix = "csar:rl:"
	}
	return &RedisThrottler{
		client:    client,
		script:    redis.NewScript(slidingWindowScript),
		keyPrefix: keyPrefix,
		routeKey:  routeKey,
		rps:       rps,
		burst:     burst,
		maxWait:   maxWait,
	}
}

// Wait blocks until the request is allowed or the timeout is exceeded.
// It polls Redis at short intervals to check if the sliding window has capacity.
func (rt *RedisThrottler) Wait(ctx context.Context) error {
	rt.waiting.Add(1)
	defer rt.waiting.Add(-1)

	// Calculate the window: 1 second window with limit = rps + burst
	limit := int(rt.rps) + rt.burst
	if limit < 1 {
		limit = 1
	}
	windowMS := 1000 // 1 second window

	key := rt.keyPrefix + rt.routeKey

	waitCtx := ctx
	if rt.maxWait > 0 {
		var cancel context.CancelFunc
		waitCtx, cancel = context.WithTimeout(ctx, rt.maxWait)
		defer cancel()
	}

	// First attempt
	allowed, err := rt.tryAcquire(waitCtx, key, limit, windowMS)
	if err != nil {
		return fmt.Errorf("redis rate limit error: %w", err)
	}
	if allowed {
		return nil
	}

	// Poll with backoff
	ticker := time.NewTicker(50 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-waitCtx.Done():
			if ctx.Err() != nil {
				return fmt.Errorf("client cancelled: %w", ctx.Err())
			}
			return fmt.Errorf("queue timeout exceeded (%s): rate limit reached", rt.maxWait)
		case <-ticker.C:
			allowed, err := rt.tryAcquire(waitCtx, key, limit, windowMS)
			if err != nil {
				return fmt.Errorf("redis rate limit error: %w", err)
			}
			if allowed {
				return nil
			}
		}
	}
}

// tryAcquire attempts to acquire a rate limit token from Redis.
func (rt *RedisThrottler) tryAcquire(ctx context.Context, key string, limit, windowMS int) (bool, error) {
	result, err := rt.script.Run(ctx, rt.client, []string{key}, limit, windowMS).Int()
	if err != nil {
		return false, err
	}
	return result == 1, nil
}

// Waiting returns the number of requests currently waiting.
func (rt *RedisThrottler) Waiting() int64 {
	return rt.waiting.Load()
}

// UpdateLimit dynamically changes the rate limit.
func (rt *RedisThrottler) UpdateLimit(rps float64, burst int) {
	rt.rps = rps
	rt.burst = burst
}
