package coordinator

import (
	"context"
	"encoding/json"
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

func TestOriginReceiverSurvivesStoreAndSnapshot(t *testing.T) {
	cfg, err := config.ParseBytes([]byte(`
listen_addr: ":8080"
paths:
  /reports:
    get:
      x-csar-backend: {target_url: "https://reports"}
      x-csar-origin-receiver: "svc:reports"
`))
	if err != nil {
		t.Fatal(err)
	}
	entry := configsource.ConfigToRouteEntries(cfg)["GET:/reports"]
	data, err := json.Marshal(entry) // etcd RouteEntry representation
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
	coord := New(store, newTestLogger()) // exercise store-only mode too
	stream := &snapshotRecorder{}
	for _, metadata := range []map[string]string{nil, {config.OriginPolicyCapability: "2"}} {
		if err := coord.sendFullConfigSnapshot(stream, metadata); status.Code(err) != codes.FailedPrecondition || stream.last != nil {
			t.Fatal("unsupported router received an origin policy", err)
		}
	}
	metadata := map[string]string{config.OriginPolicyCapability: "1"}
	if err := coord.sendFullConfigSnapshot(stream, metadata); err != nil {
		t.Fatal(err)
	}
	wire, err := proto.Marshal(stream.last.GetFullConfigSnapshot())
	if err != nil {
		t.Fatal(err)
	}
	var decoded csarv1.FullConfigSnapshot
	if err := proto.Unmarshal(wire, &decoded); err != nil {
		t.Fatal(err)
	}
	restored := protoconv.FullSnapshotToConfig(&decoded)
	if restored.OriginPolicyVersion != 1 || restored.Paths["/reports"]["get"].OriginReceiver != "svc:reports" {
		t.Fatal("receiver policy was lost in store/snapshot roundtrip")
	}
	stored.Route.OriginReceiver = ""
	if err := store.PutRoute(context.Background(), stored); err != nil {
		t.Fatal(err)
	}
	if err := coord.sendFullConfigSnapshot(stream, nil); err != nil {
		t.Fatal(err)
	}
	restored = protoconv.FullSnapshotToConfig(stream.last.GetFullConfigSnapshot())
	if restored.OriginPolicyVersion != 1 || restored.HasOriginReceivers() {
		t.Fatal("explicit receiver policy removal was not preserved")
	}
}
