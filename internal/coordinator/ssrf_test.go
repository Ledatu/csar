package coordinator

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	coresrc "github.com/ledatu/csar-core/configsource"
	"github.com/ledatu/csar/internal/config"
	"github.com/ledatu/csar/internal/configsource"
	"github.com/ledatu/csar/internal/protoconv"
	csarv1 "github.com/ledatu/csar/proto/csar/v1"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/proto"
)

func nextSSRFSnapshot(t *testing.T, stream grpc.ServerStreamingClient[csarv1.ConfigUpdate]) *csarv1.FullConfigSnapshot {
	t.Helper()
	for {
		msg, err := stream.Recv()
		if err != nil {
			t.Fatal(err)
		}
		if snap := msg.GetFullConfigSnapshot(); snap != nil {
			return snap
		}
	}
}

func TestSubscribeSSRFPolicyRoundTrip(t *testing.T) {
	for _, tc := range []struct {
		name       string
		cfg        *config.SSRFConfig
		wantBlocks []bool
	}{
		{name: "omitted YAML", wantBlocks: []bool{true, true, true, true}},
		{name: "empty YAML", cfg: &config.SSRFConfig{}, wantBlocks: []bool{true, true, true, true}},
		{
			name: "explicit false and exact hosts",
			cfg: &config.SSRFConfig{
				BlockPrivate: proto.Bool(false), BlockLoopback: proto.Bool(false),
				BlockLinkLocal: proto.Bool(false), BlockMetadata: proto.Bool(false),
				AllowedInternalHosts: []string{"user-preferences", "internal.example"},
			},
			wantBlocks: []bool{false, false, false, false},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			client, coord, cleanup := testEnv(t)
			defer cleanup()
			coord.SetTopLevelConfig(&config.Config{SSRF: tc.cfg})
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			stream, err := client.Subscribe(ctx, &csarv1.SubscribeRequest{RouterId: "ssrf-test"})
			if err != nil {
				t.Fatal(err)
			}
			snap := nextSSRFSnapshot(t, stream)
			got := protoconv.FullSnapshotToConfig(snap).SSRF
			if got == nil {
				t.Fatal("new coordinator omitted SSRF policy")
			}
			blocks := []bool{got.IsBlockPrivate(), got.IsBlockLoopback(), got.IsBlockLinkLocal(), got.IsBlockMetadata()}
			if !reflect.DeepEqual(blocks, tc.wantBlocks) {
				t.Fatalf("block switches = %v, want %v", blocks, tc.wantBlocks)
			}
			if tc.cfg != nil && !reflect.DeepEqual(got.AllowedInternalHosts, tc.cfg.AllowedInternalHosts) {
				t.Fatalf("allowlist = %v, want %v", got.AllowedInternalHosts, tc.cfg.AllowedInternalHosts)
			}
		})
	}
}

func TestSubscribeReceivesPolicyOnlyConfigChanges(t *testing.T) {
	client, coord, cleanup := testEnv(t)
	defer cleanup()
	coord.SetSnapshotDebounce(20 * time.Millisecond)
	path := filepath.Join(t.TempDir(), "config.yaml")
	const routes = `listen_addr: ":8080"
paths:
  /preferences:
    get:
      x-csar-backend:
        target_url: https://user-preferences:8080
`
	writeConfig := func(policy string) {
		t.Helper()
		if err := os.WriteFile(path, []byte(routes+policy), 0600); err != nil {
			t.Fatal(err)
		}
	}
	writeConfig("")
	watcher := configsource.NewConfigWatcherWithOptions(
		coresrc.NewFileSource(path), coord.store, newTestLogger(),
		[]configsource.WatcherOption{
			configsource.WithOnConfigApplied(coord.SetTopLevelConfig),
		},
	)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := watcher.Apply(ctx); err != nil {
		t.Fatal(err)
	}
	stream, err := client.Subscribe(ctx, &csarv1.SubscribeRequest{RouterId: "policy-only-test"})
	if err != nil {
		t.Fatal(err)
	}
	initial := nextSSRFSnapshot(t, stream)
	for _, policy := range []string{
		"ssrf_protection:\n  allowed_internal_hosts: [user-preferences]\n",
		"ssrf_protection: {}\n",
		"ssrf_protection:\n  allowed_internal_hosts: [user-preferences]\n",
		"",
	} {
		writeConfig(policy)
		if _, err := watcher.Apply(ctx); err != nil {
			t.Fatal(err)
		}
		snap := nextSSRFSnapshot(t, stream)
		if len(snap.Routes) != 1 || !proto.Equal(initial.Routes[0], snap.Routes[0]) {
			t.Fatal("policy-only update changed routes")
		}
		wantHosts := 0
		if policy == "ssrf_protection:\n  allowed_internal_hosts: [user-preferences]\n" {
			wantHosts = 1
		}
		ssrf := protoconv.FullSnapshotToConfig(snap).SSRF
		if ssrf == nil || len(ssrf.AllowedInternalHosts) != wantHosts {
			t.Fatalf("SSRF policy = %+v, want %d hosts", ssrf, wantHosts)
		}
		if !ssrf.IsBlockPrivate() || !ssrf.IsBlockLoopback() || !ssrf.IsBlockLinkLocal() || !ssrf.IsBlockMetadata() {
			t.Fatal("policy-only update disabled default blocking")
		}
	}
}
