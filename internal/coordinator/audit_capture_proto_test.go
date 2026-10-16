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

func TestAuditResponsePolicySurvivesSnapshotAndReload(t *testing.T) {
	for _, mode := range []string{"errors", "off"} {
		cfg, err := config.ParseBytes([]byte(`
listen_addr: ":8080"
audit_capture_policies:
  diagnostics:
    request: false
    response: ` + mode + `
    response_max_bytes: 1024
    include_query: false
paths:
  /report:
    get:
      x-csar-backend: {target_url: "https://example.com"}
      x-csar-audit: errors
      x-csar-audit-capture: {use: diagnostics}
`))
		if err != nil {
			t.Fatal(err)
		}
		entries := configsource.ConfigToRouteEntries(cfg)
		entry := entries["GET:/report"]
		snapshot := &csarv1.FullConfigSnapshot{
			Routes:               []*csarv1.RouteConfig{routeEntryToProto(&entry)},
			AuditCapturePolicies: auditCapturePoliciesMapToProto(cfg.AuditCapturePolicies),
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
		want := cfg.Paths["/report"]["get"].AuditCapture
		got := reconstructed.Paths["/report"]["get"].AuditCapture
		if !reflect.DeepEqual(got, want) || got.CaptureResponseEnabled() != (mode == "errors") || got.CaptureRequestEnabled() {
			t.Fatalf("response settings lost during %s snapshot: got=%+v want=%+v", mode, got, want)
		}
		// Reapplying resolution during a reload must retain explicit off and
		// must not turn a response-only policy into request capture.
		if err := reconstructed.ResolvePolicies(); err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(reconstructed.Paths["/report"]["get"].AuditCapture, want) {
			t.Fatal("reload changed response policy")
		}
	}
}
