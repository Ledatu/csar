package router

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/ledatu/csar-core/usagebudget"
	"github.com/ledatu/csar/internal/config"
	"github.com/redis/go-redis/v9"
	"gopkg.in/yaml.v3"
)

func TestUsageVocabularyReloadPreservesSpend(t *testing.T) {
	fixture := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: fixture.Addr(), ContextTimeoutEnabled: true, MaxRetries: -1})
	defer client.Close()
	var old, next config.UsageBudgetConfig
	for key, dst := range map[string]*config.UsageBudgetConfig{"owner_seller": &old, "owner_tenant": &next} {
		if err := yaml.Unmarshal([]byte("name: reports\nwindow: 1m\ncaller: 10\nowner: 10\n"+key+": 2\nfleet: 20\n"), dst); err != nil {
			t.Fatal(err)
		}
	}
	limiter, err := usagebudget.New(client, "test:usage:", time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if err := limiter.Take(context.Background(), old.Request("agent-one", "owner", "wildberries:cabinet")); err != nil {
		t.Fatal(err)
	}
	before := fixture.Keys()
	// Rebuild admission as on source reload, preserving Redis and all identities.
	limiter, err = usagebudget.New(client, "test:usage:", time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if err := limiter.Take(context.Background(), next.Request("agent-one", "owner", "wildberries:cabinet")); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(before, fixture.Keys()) {
		t.Fatal("vocabulary created fresh counter keys")
	}
	var exceeded *usagebudget.Exceeded
	if err := limiter.Take(context.Background(), next.Request("agent-two", "owner", "wildberries:cabinet")); !errors.As(err, &exceeded) || exceeded.Dimension != "owner_seller" {
		t.Fatal("reload reset owner/tenant spend", err)
	}
	if err := limiter.Take(context.Background(), next.Request("agent-two", "owner", "wildberries:other")); err != nil {
		t.Fatal("different authorized tenant incorrectly aggregated", err)
	}
}
