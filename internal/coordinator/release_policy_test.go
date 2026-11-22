package coordinator

import (
	"testing"

	"github.com/ledatu/csar/internal/config"
	"github.com/ledatu/csar/internal/protoconv"
	"github.com/ledatu/csar/internal/statestore"
	csarv1 "github.com/ledatu/csar/proto/csar/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
)

func TestReleasePolicyCompatibilityAndRemoval(t *testing.T) {
	store := statestore.NewMemoryStore()
	defer store.Close()
	coord := New(store, newTestLogger())
	cfg := &config.Config{Paths: map[string]config.PathConfig{"/report": {"get": {Backend: config.BackendConfig{TargetURL: "https://reports"}, AuditRelease: true}}}}
	coord.SetTopLevelConfig(cfg)
	stream := &snapshotRecorder{}
	if err := coord.sendFullConfigSnapshot(stream, nil); status.Code(err) != codes.FailedPrecondition || stream.last != nil {
		t.Fatal("unsupported router received release policy", err)
	}
	if err := coord.sendFullConfigSnapshot(stream, map[string]string{config.AuditReleaseCapability: "1"}); err != nil {
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
	if !restored.Paths["/report"]["get"].AuditRelease || restored.CheckPolicySnapshot(cfg.RequiredCapabilities()) != nil {
		t.Fatal("release policy lost on wire")
	}
	route := cfg.Paths["/report"]["get"]
	route.AuditRelease = false
	cfg.Paths["/report"]["get"] = route
	coord.SetTopLevelConfig(cfg)
	if err := coord.sendFullConfigSnapshot(stream, nil); err != nil {
		t.Fatal(err)
	}
	restored = protoconv.FullSnapshotToConfig(stream.last.GetFullConfigSnapshot())
	if restored.Paths["/report"]["get"].AuditRelease || restored.PolicyVersions[config.AuditReleaseCapability] != 1 {
		t.Fatal("explicit release removal lost")
	}
}
