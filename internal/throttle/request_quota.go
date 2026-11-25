package throttle

import (
	"context"
	"crypto/sha256"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/ledatu/csar/internal/requestquota"
	"github.com/redis/go-redis/v9"
)

// RequestQuota is router-owned request admission, not a worker ownership lease.
type RequestQuota = requestquota.Policy

// All windows are checked before charging any. Redis TIME, rather than router
// clocks, defines rolling windows; policy changes do not rename stored keys.
var requestQuotaScript = redis.NewScript(`
local clock = redis.call('TIME')
local now = tonumber(clock[1])*1000 + math.floor(tonumber(clock[2])/1000)
local retry = 0
for i,key in ipairs(KEYS) do
 local window = tonumber(ARGV[2*i])
 local capacity = tonumber(ARGV[2*i+1])
 local kind = redis.call('TYPE',key).ok
 if kind ~= 'none' and kind ~= 'zset' then return redis.error_reply('invalid request quota state') end
 local first = redis.call('ZRANGE',key,0,0,'WITHSCORES')
 if #first>0 and (first[1]~='window:'..ARGV[2*i] or tonumber(first[2])~=0 or redis.call('PTTL',key)<=0) then return redis.error_reply('request quota window changed or corrupt') end
 local last = redis.call('ZREVRANGE',key,0,0,'WITHSCORES')
 if #last > 0 and tonumber(last[2]) > now then return redis.error_reply('request quota clock moved backwards') end
 redis.call('ZREMRANGEBYSCORE',key,1,now-window)
 local count = math.max(0,redis.call('ZCARD',key)-1)
 if capacity == 0 then
  retry = math.max(retry,window)
 elseif count >= capacity then
  local edge = redis.call('ZRANGE',key,count-capacity+1,count-capacity+1,'WITHSCORES')
  retry = math.max(retry,tonumber(edge[2])+window-now)
 end
end
if retry > 0 then return retry end
for i,key in ipairs(KEYS) do
 redis.call('ZADD',key,0,'window:'..ARGV[2*i])
 redis.call('ZADD',key,now,ARGV[1])
 redis.call('PEXPIRE',key,86400000)
end
return 0
`)

func (dt *DynamicThrottler) SetQuotas(client *redis.Client, quotas []RequestQuota) error {
	if err := requestquota.Validate(quotas); err != nil {
		return err
	}
	if len(quotas) > 0 {
		if client == nil || !client.Options().ContextTimeoutEnabled {
			return fmt.Errorf("request quotas require a context-aware Redis client")
		}
		if dt.maxWait != 0 {
			return fmt.Errorf("request quotas require immediate admission")
		}
	}

	dt.quotaClient = client
	dt.quotas = append([]RequestQuota(nil), quotas...)
	return nil
}
func (dt *DynamicThrottler) admitQuotas(ctx context.Context) error {
	if len(dt.quotas) == 0 {
		return nil
	}
	req := requestFromContext(ctx)
	scope := (&DynamicThrottler{keyTemplate: dt.quotas[0].Key}).resolveKey(req)
	if req == nil || strings.Contains(scope, "_unknown_") || strings.ContainsAny(scope, "{}") {
		return fmt.Errorf("request quota scope unavailable")
	}
	digest := fmt.Sprintf("%x", sha256.Sum256([]byte(scope)))
	keys := make([]string, 0, len(dt.quotas))
	args := []any{uuid.NewString()}
	for _, q := range dt.quotas {
		keys = append(keys, dt.keyPrefix+"{request-quota:"+digest+"}:"+q.Name)
		args = append(args, q.Window.Milliseconds(), q.Requests)
	}
	bounded, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()
	wait, err := requestQuotaScript.Run(bounded, dt.quotaClient, keys, args...).Int64()
	if err != nil {
		return fmt.Errorf("%w: request quota: %w", ErrBackendUnavailable, err)
	}
	if wait < 0 || wait > (24*time.Hour).Milliseconds() {
		return fmt.Errorf("%w: invalid request quota response", ErrBackendUnavailable)
	}
	if wait > 0 {
		return &RetryAfterError{Wait: time.Duration(wait) * time.Millisecond, Key: "request-quota"}
	}
	return nil
}
