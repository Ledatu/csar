package throttle

import (
	"context"
	"fmt"
	"sync/atomic"
	"time"

	"github.com/redis/go-redis/v9"
)

// Compile-time check: RedisThrottler satisfies Waiter.
var _ Waiter = (*RedisThrottler)(nil)

// gcraScript implements the Generic Cell Rate Algorithm (GCRA) in Redis.
//
// GCRA stores a single key per entity: the TAT (Theoretical Arrival Time).
// Instead of maintaining a counter that needs periodic replenishment, GCRA
// works with absolute timestamps, making it ideal for distributed systems.
//
// Algorithm:
//   - emission_interval = 1/rate (seconds per request)
//   - burst_offset = emission_interval * burst (the maximum "credit")
//   - TAT_new = max(now, TAT_old) + emission_interval
//   - If TAT_new - now > burst_offset → request is denied
//   - The script returns the wait time in milliseconds (0 = allowed immediately,
//     >0 = how long the caller should park, -1 = denied/exceeds max burst)
//
// Returns:
//
//	0   → allowed immediately
//	>0  → wait this many ms, then retry (optimistic parking)
//	-1  → denied (wait would exceed burst_offset)
const gcraScript = `
local key = KEYS[1]
local emission_interval_ms = tonumber(ARGV[1])
local burst_offset_ms = tonumber(ARGV[2])
local now_ms = tonumber(ARGV[3])
local max_wait_ms = tonumber(ARGV[4])

local tat = tonumber(redis.call('GET', key) or now_ms)

local new_tat = math.max(now_ms, tat) + emission_interval_ms
local diff = new_tat - now_ms

if diff > burst_offset_ms then
    -- Would exceed burst capacity. Return how long the caller must wait,
    -- or -1 if it exceeds max_wait.
    local wait = tat + emission_interval_ms - now_ms - burst_offset_ms
    if wait < 0 then wait = 0 end
    if max_wait_ms > 0 and wait > max_wait_ms then
        return -1
    end
    return wait
end

-- Allowed: update TAT with expiry = burst_offset + emission_interval + safety margin
redis.call('SET', key, tostring(new_tat), 'PX', burst_offset_ms + emission_interval_ms + 1000)
return 0
`

// RedisThrottler implements distributed rate limiting via Redis GCRA.
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
		script:    redis.NewScript(gcraScript),
		keyPrefix: keyPrefix,
		routeKey:  routeKey,
		rps:       rps,
		burst:     burst,
		maxWait:   maxWait,
	}
}

// Wait blocks until the request is allowed or the timeout is exceeded.
// Uses GCRA with optimistic parking: Redis returns the exact wait time,
// and Go sleeps for that duration instead of polling.
func (rt *RedisThrottler) Wait(ctx context.Context) error {
	rt.waiting.Add(1)
	defer rt.waiting.Add(-1)

	key := rt.keyPrefix + rt.routeKey

	// GCRA parameters in milliseconds
	emissionIntervalMS := int64(1000.0 / rt.rps)
	if emissionIntervalMS < 1 {
		emissionIntervalMS = 1
	}
	burstOffsetMS := emissionIntervalMS * int64(rt.burst)
	maxWaitMS := rt.maxWait.Milliseconds()

	deadline := time.Now().Add(rt.maxWait)

	for {
		// Check context before Redis call
		if ctx.Err() != nil {
			return fmt.Errorf("client cancelled: %w", ctx.Err())
		}

		nowMS := time.Now().UnixMilli()
		result, err := rt.script.Run(ctx, rt.client, []string{key},
			emissionIntervalMS, burstOffsetMS, nowMS, maxWaitMS,
		).Int64()
		if err != nil {
			return fmt.Errorf("redis GCRA error: %w", err)
		}

		switch {
		case result == 0:
			// Allowed immediately
			return nil

		case result == -1:
			// Denied: wait would exceed max_wait
			return fmt.Errorf("queue timeout exceeded (%s): rate limit reached", rt.maxWait)

		case result > 0:
			// Optimistic parking: sleep for the suggested duration, then retry
			parkDuration := time.Duration(result) * time.Millisecond

			// Clamp to remaining deadline
			remaining := time.Until(deadline)
			if remaining <= 0 {
				return fmt.Errorf("queue timeout exceeded (%s): rate limit reached", rt.maxWait)
			}
			if parkDuration > remaining {
				parkDuration = remaining
			}

			select {
			case <-ctx.Done():
				return fmt.Errorf("client cancelled: %w", ctx.Err())
			case <-time.After(parkDuration):
				// Retry after parking (optimistic: someone else may have taken the slot)
				continue
			}
		}
	}
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
