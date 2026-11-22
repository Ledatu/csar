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

func TestUsagePolicySurvivesStoreWireAndCapability(t *testing.T) {
	budget := &config.UsageBudgetConfig{Name: "reports", Window: config.Duration{Duration: time.Minute}, Caller: 2, Owner: 3, OwnerSeller: 3, Fleet: 10}
	cfg := &config.Config{Paths: map[string]config.PathConfig{"/report": {"get": {Backend: config.BackendConfig{TargetURL: "https://reports"}, UsageBudget: budget}}}}
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
	stream := &snapshotRecorder{}
	if err := coord.sendFullConfigSnapshot(stream, nil); status.Code(err) != codes.FailedPrecondition {
		t.Fatal("old router accepted usage policy", err)
	}
	if err := coord.sendFullConfigSnapshot(stream, map[string]string{config.UsageBudgetCapability: "1"}); err != nil {
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
	if !reflect.DeepEqual(restored.Paths["/report"]["get"].UsageBudget, budget) || restored.CheckPolicySnapshot(cfg.RequiredCapabilities()) != nil {
		t.Fatal("usage limits changed in store/wire")
	}
	stored.Route.UsageBudget = nil
	if err := store.PutRoute(context.Background(), stored); err != nil {
		t.Fatal(err)
	}
	if err := coord.sendFullConfigSnapshot(stream, nil); err != nil {
		t.Fatal(err)
	}
	restored = protoconv.FullSnapshotToConfig(stream.last.GetFullConfigSnapshot())
	if restored.Paths["/report"]["get"].UsageBudget != nil || restored.CheckPolicySnapshot(cfg.RequiredCapabilities()) != nil {
		t.Fatal("explicit usage removal not preserved")
	}
}
