package coordinator

import (
	"context"
	"encoding/json"
	"reflect"
	"testing"
	"time"

	"github.com/ledatu/csar/internal/config"
	"github.com/ledatu/csar/internal/configsource"
	"github.com/ledatu/csar/internal/protoconv"
	"github.com/ledatu/csar/internal/statestore"
	csarv1 "github.com/ledatu/csar/proto/csar/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
)

func TestRequestQuotaSurvivesStoreWireAndCapability(t *testing.T) {
	budget := []config.RequestQuota{{Name: "daily", Key: "ozon:{path.cabinet}", Requests: 20, Window: config.Duration{Duration: 24 * time.Hour}}}
	cfg := &config.Config{Paths: map[string]config.PathConfig{"/report": {"get": {Backend: config.BackendConfig{TargetURL: "https://reports"}, Traffic: &config.TrafficConfig{Quotas: budget}}}}}
	entry := configsource.ConfigToRouteEntries(cfg)["GET:/report"]
	data, err := json.Marshal(entry)
	if err != nil {
		t.Fatal(err)
	}
	var stored statestore.RouteEntry
	if err := json.Unmarshal(data, &stored); err != nil {
		t.Fatal(err)
	}
	store := statestore.NewMemoryStore()
	defer store.Close()
	if err := store.PutRoute(context.Background(), stored); err != nil {
		t.Fatal(err)
	}
	coord := New(store, newTestLogger())
	cfg.ThrottlingPolicies = map[string]config.ThrottlingPolicy{"reads": {Quotas: budget}}
	coord.SetTopLevelConfig(cfg)
	stream := &snapshotRecorder{}
	if err := coord.sendFullConfigSnapshot(stream, nil); status.Code(err) != codes.FailedPrecondition {
		t.Fatal("old router accepted request quota policy", err)
	}
	if err := coord.sendFullConfigSnapshot(stream, map[string]string{config.RequestQuotaCapability: "1"}); err != nil {
		t.Fatal(err)
	}
	bytes, err := proto.Marshal(stream.last.GetFullConfigSnapshot())
	if err != nil {
		t.Fatal(err)
	}
	var snapshot csarv1.FullConfigSnapshot
	if err := proto.Unmarshal(bytes, &snapshot); err != nil {
		t.Fatal(err)
	}
	restored := protoconv.FullSnapshotToConfig(&snapshot)
	if !reflect.DeepEqual(restored.ThrottlingPolicies["reads"].Quotas, budget) {
		t.Fatal("named policy quotas lost")
	}
	if !reflect.DeepEqual(restored.Paths["/report"]["get"].Traffic.Quotas, budget) || restored.CheckPolicySnapshot(cfg.RequiredCapabilities()) != nil {
		t.Fatal("request quota limits changed in store/wire")
	}
	stored.Route.Traffic.Quotas = nil
	cfg.Paths["/report"]["get"].Traffic.Quotas = nil
	cfg.ThrottlingPolicies = nil
	coord.SetTopLevelConfig(cfg)
	if err := store.PutRoute(context.Background(), stored); err != nil {
		t.Fatal(err)
	}
	if err := coord.sendFullConfigSnapshot(stream, nil); err != nil {
		t.Fatal(err)
	}
	restored = protoconv.FullSnapshotToConfig(stream.last.GetFullConfigSnapshot())
	if restored.Paths["/report"]["get"].Traffic.Quotas != nil || restored.CheckPolicySnapshot(cfg.RequiredCapabilities()) != nil {
		t.Fatal("explicit request quota removal not preserved")
	}
}
