package throttle

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"sync/atomic"
	"time"

	"github.com/ledatu/csar/internal/redisx"
	"github.com/redis/go-redis/v9"
)

// Compile-time check: RedisThrottler satisfies Waiter.
var _ Waiter = (*RedisThrottler)(nil)
var _ RequestSuspendable = (*RedisThrottler)(nil)

// ErrBackendUnavailable means the rate-limit decision could not be made
// because the Redis backend failed, as opposed to the caller being over limit.
var ErrBackendUnavailable = errors.New("throttle backend unavailable")

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
//     >0 = how long until the next slot); the caller decides whether to park
//     or reject against its max_wait
//
// Returns:
//
//	0   → allowed immediately
//	>0  → wait this many ms, then retry (optimistic parking)
const gcraScript = `
local key = KEYS[1]
local emission_interval_ms = tonumber(ARGV[1])
local burst_offset_ms = tonumber(ARGV[2])
local now_ms = tonumber(ARGV[3])

local tat = tonumber(redis.call('GET', key) or now_ms)

local new_tat = math.max(now_ms, tat) + emission_interval_ms
local diff = new_tat - now_ms

if diff > burst_offset_ms then
    local wait = tat + emission_interval_ms - now_ms - burst_offset_ms
    if wait < 1 then wait = 1 end
    return wait
end

-- Allowed: update TAT with expiry = burst_offset + emission_interval + safety margin
redis.call('SET', key, tostring(new_tat), 'PX', burst_offset_ms + emission_interval_ms + 1000)
return 0
`

// gcraSuspendScript pushes the key's TAT so that the next request is admitted
// no earlier than ARGV[1] (epoch ms) and paced at the emission interval after
// it. It never moves the TAT backwards.
const gcraSuspendScript = `
local key = KEYS[1]
local until_ms = tonumber(ARGV[1])
local emission_interval_ms = tonumber(ARGV[2])
local burst_offset_ms = tonumber(ARGV[3])
local now_ms = tonumber(ARGV[4])

local target = until_ms + burst_offset_ms - emission_interval_ms
local tat = tonumber(redis.call('GET', key) or 0)
if target <= tat then
    return 0
end
redis.call('SET', key, tostring(target), 'PX', target - now_ms + 1000)
return 1
`

var suspendScript = redis.NewScript(gcraSuspendScript)

// RetryAfterError is returned by the GCRA throttlers when the next slot for
// the key is further away than max_wait. Wait is that distance.
type RetryAfterError struct {
	Key     string
	Wait    time.Duration
	MaxWait time.Duration
}

func (e *RetryAfterError) Error() string {
	return fmt.Sprintf("queue timeout exceeded (%s): rate limit reached, next slot in %s", e.MaxWait, e.Wait)
}

type gcraParams struct {
	emissionIntervalMS int64
	burstOffsetMS      int64
}

func newGCRAParams(rps float64, burst int) gcraParams {
	emission := int64(1000.0 / rps)
	if emission < 1 {
		emission = 1
	}
	return gcraParams{emissionIntervalMS: emission, burstOffsetMS: emission * int64(burst)}
}

// gcraWait admits one request for key, parking while the next slot is within
// the deadline and returning *RetryAfterError once it is not.
func gcraWait(ctx context.Context, client *redis.Client, script *redis.Script, key, label string, p gcraParams, maxWait time.Duration) error {
	deadline := time.Now().Add(maxWait)
	for {
		if ctx.Err() != nil {
			return fmt.Errorf("client cancelled: %w", ctx.Err())
		}
		result, err := runGCRA(ctx, client, script, key, p.emissionIntervalMS, p.burstOffsetMS)
		if err != nil {
			return err
		}
		if result <= 0 {
			return nil
		}
		wait := time.Duration(result) * time.Millisecond
		if wait > time.Until(deadline) {
			return &RetryAfterError{Key: label, Wait: wait, MaxWait: maxWait}
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("client cancelled: %w", ctx.Err())
		case <-time.After(wait):
		}
	}
}

func gcraSuspend(ctx context.Context, client *redis.Client, key string, p gcraParams, d time.Duration) error {
	now := time.Now()
	err := suspendScript.Run(redisx.WithSubsystem(ctx, redisx.SubsystemThrottle), client, []string{key},
		now.Add(d).UnixMilli(), p.emissionIntervalMS, p.burstOffsetMS, now.UnixMilli(),
	).Err()
	if err != nil {
		return fmt.Errorf("%w: redis GCRA suspend: %w", ErrBackendUnavailable, err)
	}
	return nil
}

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

	return gcraWait(ctx, rt.client, rt.script, rt.keyPrefix+rt.routeKey, rt.routeKey,
		newGCRAParams(rt.rps, rt.burst), rt.maxWait)
}

// SuspendRequestFor holds the whole route back for d (upstream backpressure).
func (rt *RedisThrottler) SuspendRequestFor(_ *http.Request, d time.Duration) error {
	ctx, cancel := context.WithTimeout(context.Background(), suspendTimeout)
	defer cancel()
	return gcraSuspend(ctx, rt.client, rt.keyPrefix+rt.routeKey, newGCRAParams(rt.rps, rt.burst), d)
}

func runGCRA(ctx context.Context, client *redis.Client, script *redis.Script, key string, emissionIntervalMS, burstOffsetMS int64) (int64, error) {
	result, err := script.Run(redisx.WithSubsystem(ctx, redisx.SubsystemThrottle), client, []string{key},
		emissionIntervalMS, burstOffsetMS, time.Now().UnixMilli(),
	).Int64()
	if err == nil {
		return result, nil
	}
	if ctx.Err() != nil {
		return 0, fmt.Errorf("client cancelled: %w", ctx.Err())
	}
	return 0, fmt.Errorf("%w: redis GCRA: %w", ErrBackendUnavailable, err)
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
