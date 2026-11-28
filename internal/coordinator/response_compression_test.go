package coordinator

import (
	"context"
	"encoding/json"
	"reflect"
	"testing"

	"github.com/ledatu/csar/internal/config"
	"github.com/ledatu/csar/internal/configsource"
	"github.com/ledatu/csar/internal/protoconv"
	"github.com/ledatu/csar/internal/statestore"
	csarv1 "github.com/ledatu/csar/proto/csar/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
)

func TestResponseCompressionStoreSnapshotAndRemoval(t *testing.T) {
	for _, policy := range []*config.ResponseCompressionConfig{nil, {Mode: "gzip"}, {Mode: "gzip", MinBytes: 4096}, {Mode: "passthrough"}} {
		cfg := &config.Config{Paths: map[string]config.PathConfig{"/custom": {"get": {Backend: config.BackendConfig{TargetURL: "https://upstream.example"}, ResponseCompression: policy}}}}
		active := cfg.RequiredCapabilities()
		entry := configsource.ConfigToRouteEntries(cfg)["GET:/custom"]
		data, err := json.Marshal(entry)
		if err != nil {
			t.Fatal(err)
		}
		var stored statestore.RouteEntry
		if err := json.Unmarshal(data, &stored); err != nil {
			t.Fatal(err)
		}
		store := statestore.NewMemoryStore()
		if err := store.PutRoute(context.Background(), stored); err != nil {
			t.Fatal(err)
		}
		coord := New(store, newTestLogger())
		coord.SetTopLevelConfig(cfg)
		stream := &snapshotRecorder{}
		err = coord.sendFullConfigSnapshot(stream, nil)
		if policy != nil && status.Code(err) != codes.FailedPrecondition {
			t.Fatal("old router received an explicit encoding policy", err)
		}
		if err := coord.sendFullConfigSnapshot(stream, map[string]string{config.ResponseCompressionCapability: "1"}); err != nil {
			t.Fatal(err)
		}
		data, err = proto.Marshal(stream.last.GetFullConfigSnapshot())
		if err != nil {
			t.Fatal(err)
		}
		var wire csarv1.FullConfigSnapshot
		if err := proto.Unmarshal(data, &wire); err != nil {
			t.Fatal(err)
		}
		restored := protoconv.FullSnapshotToConfig(&wire)
		if !reflect.DeepEqual(restored.Paths["/custom"]["get"].ResponseCompression, policy) || restored.CheckPolicySnapshot(active) != nil {
			t.Fatal("policy changed in storage or protobuf")
		}
		stored.Route.ResponseCompression = nil
		cfg.Paths["/custom"]["get"] = stored.Route
		if err := store.PutRoute(context.Background(), stored); err != nil {
			t.Fatal(err)
		}
		coord.SetTopLevelConfig(cfg)
		if err := coord.sendFullConfigSnapshot(stream, nil); err != nil {
			t.Fatal(err)
		}
		restored = protoconv.FullSnapshotToConfig(stream.last.GetFullConfigSnapshot())
		if restored.Paths["/custom"]["get"].ResponseCompression != nil || restored.CheckPolicySnapshot(active) != nil {
			t.Fatal("explicit policy removal lost")
		}
		if policy != nil {
			restored.PolicyVersions = nil
			if restored.CheckPolicySnapshot(active) == nil {
				t.Fatal("legacy snapshot discarded an active encoding policy")
			}
		}
		if err := store.Close(); err != nil {
			t.Fatal(err)
		}
	}
}
