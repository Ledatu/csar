package coordinator

import (
	"bytes"
	"context"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/ledatu/csar/internal/config"
	"github.com/ledatu/csar/internal/logging"
	"github.com/ledatu/csar/internal/protoconv"
	csarv1 "github.com/ledatu/csar/proto/csar/v1"
)

func TestSubscribeRedisPrefixRoundTrip(t *testing.T) {
	for _, tc := range []struct {
		name  string
		redis *config.RedisConfig
		want  string
	}{
		{name: "omitted Redis resets prefix"},
		{name: "explicit empty prefix", redis: &config.RedisConfig{Address: "redis:6379"}},
		{name: "custom prefix", redis: &config.RedisConfig{
			Address: "redis:6379", Password: logging.NewSecret("not-on-wire"), DB: 3, KeyPrefix: "custom:",
		}, want: "custom:"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			client, coord, cleanup := testEnv(t)
			defer cleanup()
			coord.SetTopLevelConfig(&config.Config{Redis: tc.redis})
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			stream, err := client.Subscribe(ctx, &csarv1.SubscribeRequest{RouterId: "prefix-test"})
			if err != nil {
				t.Fatal(err)
			}
			snap := nextSSRFSnapshot(t, stream)
			if snap.RedisKeyPrefix == nil || snap.GetRedisKeyPrefix() != tc.want {
				t.Fatal("Redis prefix presence/value was lost over gRPC")
			}
			r := protoconv.FullSnapshotToConfig(snap).Redis
			if r == nil || r.KeyPrefix != tc.want || r.Address != "" || !r.Password.IsEmpty() || r.DB != 0 {
				t.Fatal("snapshot must reconstruct only the Redis namespace")
			}
			coord.SetTopLevelConfig(&config.Config{Redis: &config.RedisConfig{KeyPrefix: "changed:"}})
			if got := nextSSRFSnapshot(t, stream).GetRedisKeyPrefix(); got != "changed:" {
				t.Fatalf("prefix-only update = %q", got)
			}
		})
	}
}

func TestCoordinatorRestartWarningsDoNotExposeValues(t *testing.T) {
	var logs bytes.Buffer
	coord := New(nil, slog.New(slog.NewTextHandler(&logs, nil)))
	old := &config.Config{Redis: &config.RedisConfig{Address: "old-host:6379", Password: logging.NewSecret("old-secret")}}
	coord.SetTopLevelConfig(old)
	if logs.Len() != 0 {
		t.Fatal("initial config load must not require a restart")
	}
	updated := &config.Config{Redis: &config.RedisConfig{Address: "new-host:6379", Password: logging.NewSecret("new-secret")}}
	coord.SetTopLevelConfig(updated)
	for _, field := range []string{"redis.address", "redis.password"} {
		if !strings.Contains(logs.String(), "field="+field) {
			t.Fatalf("missing coordinator warning for %s", field)
		}
	}
	for _, value := range []string{"old-host", "new-host", "old-secret", "new-secret"} {
		if strings.Contains(logs.String(), value) {
			t.Fatal("coordinator warning exposed a configuration value")
		}
	}
	logs.Reset()
	updated.Redis.KeyPrefix = "hot:"
	updated.Audit = &config.AuditClientConfig{Capture: &config.AuditCaptureConfig{Response: "off"}}
	coord.SetTopLevelConfig(updated)
	if logs.Len() != 0 {
		t.Fatal("hot-only change produced coordinator restart warnings")
	}
}
