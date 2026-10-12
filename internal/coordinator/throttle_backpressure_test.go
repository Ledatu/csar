package coordinator

import (
	"reflect"
	"testing"

	"github.com/ledatu/csar/internal/config"
	"github.com/ledatu/csar/internal/configsource"
	"github.com/ledatu/csar/internal/protoconv"
	csarv1 "github.com/ledatu/csar/proto/csar/v1"
	"google.golang.org/protobuf/proto"
)

func TestResolvedPolicyBackpressureSurvivesSnapshot(t *testing.T) {
	cfg, err := config.ParseBytes([]byte(`
listen_addr: ":8080"
throttling_policies:
  wb:
    requests: 3
    period: 1m
    burst: 1
    adaptive_backpressure:
      enabled: true
      respect_headers: [X-Ratelimit-Retry, Retry-After, X-Ratelimit-Reset]
      suspend_bucket: true
      max_body_buffer: 12345
paths:
  /report:
    get:
      x-csar-backend: {target_url: "https://example.com"}
      x-csar-traffic: wb
      x-csar-retry: {max_attempts: 1, auto_retry_429: false}
      x-csar-protocol: {transparent_retry: false}
`))
	if err != nil {
		t.Fatal(err)
	}
	entries := configsource.ConfigToRouteEntries(cfg)
	entry := entries["GET:/report"]
	snapshot := &csarv1.FullConfigSnapshot{
		Routes:             []*csarv1.RouteConfig{routeEntryToProto(&entry)},
		ThrottlingPolicies: throttlingPoliciesToProto(cfg.ThrottlingPolicies),
	}
	data, err := proto.Marshal(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	var decoded csarv1.FullConfigSnapshot
	if err := proto.Unmarshal(data, &decoded); err != nil {
		t.Fatal(err)
	}
	reconstructed := protoconv.FullSnapshotToConfig(&decoded)
	if err := reconstructed.ResolvePolicies(); err != nil {
		t.Fatal(err)
	}
	want := cfg.Paths["/report"]["get"]
	got := reconstructed.Paths["/report"]["get"]
	if !reflect.DeepEqual(got.Traffic, want.Traffic) || !reflect.DeepEqual(got.Retry, want.Retry) || !reflect.DeepEqual(got.Protocol, want.Protocol) {
		t.Fatalf("snapshot lost resolved policy settings or disabled retries: %+v", got)
	}
}
