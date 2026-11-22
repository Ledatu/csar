package coordinator

import (
	"context"
	"testing"

	"github.com/ledatu/csar/internal/config"
	"github.com/ledatu/csar/internal/configsource"
	"github.com/ledatu/csar/internal/statestore"
	csarv1 "github.com/ledatu/csar/proto/csar/v1"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/proto"
)

type snapshotRecorder struct {
	grpc.ServerStream
	last *csarv1.ConfigUpdate
}

func (*snapshotRecorder) Context() context.Context                 { return context.Background() }
func (s *snapshotRecorder) Send(update *csarv1.ConfigUpdate) error { s.last = update; return nil }

func TestSnapshotsAndQuotasUseCommittedSourceConfig(t *testing.T) {
	store := statestore.NewMemoryStore()
	defer store.Close()
	coord := New(store, newTestLogger())
	makeConfig := func(host string) *config.Config {
		return &config.Config{
			SSRF:  &config.SSRFConfig{AllowedInternalHosts: []string{host}},
			Redis: &config.RedisConfig{KeyPrefix: host + ":"},
			Paths: map[string]config.PathConfig{
				"/z": {"get": {Backend: config.BackendConfig{TargetURL: "https://" + host + "/z"}}},
				"/a": {"get": {Backend: config.BackendConfig{TargetURL: "https://" + host + "/a"}, Traffic: &config.TrafficConfig{RPS: 100, Burst: 10}}},
			},
		}
	}
	old, next := makeConfig("old.example"), makeConfig("next.example")
	coord.SetTopLevelConfig(old)
	stream := &snapshotRecorder{}
	if err := coord.sendFullConfigSnapshot(stream, nil); err != nil {
		t.Fatal(err)
	}
	first := stream.last.GetFullConfigSnapshot()
	if len(first.Routes) != 2 || first.Routes[0].Path != "/a" || first.Routes[1].Path != "/z" {
		t.Fatal("snapshot routes are not in stable order")
	}
	// A source update has written only one route before failing or pausing.
	if err := store.PutRoute(context.Background(), configsource.ConfigToRouteEntries(next)["GET:/a"]); err != nil {
		t.Fatal(err)
	}
	for range 20 {
		if err := coord.sendFullConfigSnapshot(stream, nil); err != nil {
			t.Fatal(err)
		}
		if !proto.Equal(first, stream.last.GetFullConfigSnapshot()) {
			t.Fatal("uncommitted store writes or route ordering changed the snapshot")
		}
	}
	if err := coord.sendQuotaAssignment("router", stream); err != nil {
		t.Fatal(err)
	}
	if q := stream.last.GetQuotaAssignment().GetQuotas()["GET:/a"]; q == nil || q.Rps != 100 {
		t.Fatal("quota assignment did not use committed routes")
	}
	coord.SetTopLevelConfig(next)
	if err := coord.sendFullConfigSnapshot(stream, nil); err != nil {
		t.Fatal(err)
	}
	got := stream.last.GetFullConfigSnapshot()
	if len(got.Routes) != 2 || got.Routes[0].TargetUrl != "https://next.example/a" ||
		got.SsrfProtection.AllowedInternalHosts[0] != "next.example" || got.GetRedisKeyPrefix() != "next.example:" {
		t.Fatal("committed routes and policies were not published together")
	}
}
