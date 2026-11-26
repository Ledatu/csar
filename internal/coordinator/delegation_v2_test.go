package coordinator

import (
	"testing"

	"github.com/ledatu/csar-core/authntokens"
	"github.com/ledatu/csar/internal/config"
	"github.com/ledatu/csar/internal/protoconv"
	"github.com/ledatu/csar/internal/statestore"
	csarv1 "github.com/ledatu/csar/proto/csar/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
)

func TestV2CapabilityWireBindingsAndRemoval(t *testing.T) {
	store := statestore.NewMemoryStore()
	defer store.Close()
	coord := New(store, newTestLogger())
	a := &config.AuthValidateConfig{Mode: authntokens.GrantResourceV2, CredentialProfile: "facts", ResourceNamespace: "workspace", ResourcePathParam: "workspace", RequiredScope: "facts:read", Audiences: []string{"https://facts.test"}}
	cfg := &config.Config{Paths: map[string]config.PathConfig{"/workspaces/{workspace}": {"get": {AuthValidate: a, Backend: config.BackendConfig{TargetURL: "https://facts"}}}}}
	coord.SetTopLevelConfig(cfg)
	stream := &snapshotRecorder{}
	if err := coord.sendFullConfigSnapshot(stream, nil); status.Code(err) != codes.FailedPrecondition || stream.last != nil {
		t.Fatal("unsupported subscriber received v2", err)
	}
	if err := coord.sendFullConfigSnapshot(stream, map[string]string{config.DelegationV2Capability: "2"}); err != nil {
		t.Fatal(err)
	}
	raw, err := proto.Marshal(stream.last.GetFullConfigSnapshot())
	if err != nil {
		t.Fatal(err)
	}
	var wire csarv1.FullConfigSnapshot
	if err := proto.Unmarshal(raw, &wire); err != nil {
		t.Fatal(err)
	}
	restored := protoconv.FullSnapshotToConfig(&wire)
	got := restored.Paths["/workspaces/{workspace}"]["get"].AuthValidate
	if got.CredentialProfile != a.CredentialProfile || got.ResourceNamespace != a.ResourceNamespace || got.Mode != a.Mode || got.ValidateDelegationV2("/workspaces/{workspace}") != nil {
		t.Fatal("v2 required binding lost")
	}
	// Simulate an old converter retaining the established mode but dropping new fields.
	got.CredentialProfile = ""
	if got.ValidateDelegationV2("/workspaces/{workspace}") == nil {
		t.Fatal("dropped field became v1 authority")
	}
	active := cfg.RequiredCapabilities()
	route := cfg.Paths["/workspaces/{workspace}"]["get"]
	route.AuthValidate = nil
	cfg.Paths["/workspaces/{workspace}"]["get"] = route
	coord.SetTopLevelConfig(cfg)
	if err := coord.sendFullConfigSnapshot(stream, nil); err != nil {
		t.Fatal(err)
	}
	removed := protoconv.FullSnapshotToConfig(stream.last.GetFullConfigSnapshot())
	if removed.CheckPolicySnapshot(active) != nil {
		t.Fatal("versioned explicit removal rejected")
	}
	removed.PolicyVersions = nil
	if removed.CheckPolicySnapshot(active) == nil {
		t.Fatal("legacy snapshot silently removed v2")
	}
	descriptor := (&csarv1.AuthValidateConfigProto{}).ProtoReflect().Descriptor().Fields()
	for name, tag := range map[string]int{"mode": 11, "resource_path_param": 22, "credential_profile": 23, "resource_namespace": 24} {
		f := descriptor.ByName(protoreflect.Name(name))
		if f == nil || int(f.Number()) != tag {
			t.Fatal("protobuf tag changed", name)
		}
	}
}

func TestAccountAndDirectCapabilitiesAndPresenceSurviveSnapshot(t *testing.T) {
	store := statestore.NewMemoryStore()
	defer store.Close()
	coord := New(store, newTestLogger())
	cfg := &config.Config{Paths: map[string]config.PathConfig{"/security": {"post": {OriginReceiver: "svc:authn", OriginBinding: "account", Backend: config.BackendConfig{TargetURL: "https://authn"}}}, "/facts/{id}": {"get": {Backend: config.BackendConfig{TargetURL: "https://facts"}, AuthValidate: &config.AuthValidateConfig{Mode: "access-resource-v2"}}}}}
	coord.SetTopLevelConfig(cfg)
	stream := &snapshotRecorder{}
	metadata := map[string]string{config.OriginPolicyCapability: "1", config.DelegationV2Capability: "2"}
	if err := coord.sendFullConfigSnapshot(stream, metadata); status.Code(err) != codes.FailedPrecondition {
		t.Fatal("old subscriber received new semantics", err)
	}
	metadata[config.AccountOriginCapability] = "1"
	metadata[config.AccessResourceCapability] = "1"
	if err := coord.sendFullConfigSnapshot(stream, metadata); err != nil {
		t.Fatal(err)
	}
	raw, err := proto.Marshal(stream.last.GetFullConfigSnapshot())
	if err != nil {
		t.Fatal(err)
	}
	var wire csarv1.FullConfigSnapshot
	if err := proto.Unmarshal(raw, &wire); err != nil {
		t.Fatal(err)
	}
	restored := protoconv.FullSnapshotToConfig(&wire)
	if restored.Paths["/security"]["post"].OriginBinding != "account" || restored.CheckPolicySnapshot(cfg.RequiredCapabilities()) != nil {
		t.Fatal("account binding lost")
	}
	for _, r := range wire.Routes {
		if r.OriginBinding == nil {
			t.Fatal("explicit binding presence lost")
		}
		r.OriginBinding = nil
	}
	if protoconv.FullSnapshotToConfig(&wire).CheckPolicySnapshot(cfg.RequiredCapabilities()) == nil {
		t.Fatal("dropped binding became tenant default")
	}
	field := (&csarv1.RouteConfig{}).ProtoReflect().Descriptor().Fields().ByName("origin_binding")
	if field == nil || field.Number() != 38 || !field.HasPresence() {
		t.Fatal("append-only account field missing")
	}
}
