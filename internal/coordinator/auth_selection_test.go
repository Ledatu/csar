package coordinator

import (
	"reflect"
	"testing"

	"github.com/ledatu/csar/internal/config"
	"github.com/ledatu/csar/internal/protoconv"
	csarv1 "github.com/ledatu/csar/proto/csar/v1"
	"google.golang.org/protobuf/proto"
)

func TestAuthSelectionSurvivesCoordinatorSnapshot(t *testing.T) {
	original := &config.AuthValidateConfig{Mode: "select", Methods: []config.AuthValidateConfig{
		{Mode: "jwt", JWKSURL: "https://authn/jwks", JWKSTLS: "authn", Audiences: []string{"reader"}, ForwardClaims: map[string]string{"sub": "X-Gateway-Subject"}},
		{Mode: "session", SessionEndpoint: "https://authn/auth/validate", CookieName: "csar_session", SessionTLS: "authn", ForwardHeaders: []string{"X-Gateway-Subject"}},
		{Mode: "grant-resource", Audiences: []string{"projects"}, IntrospectionEndpoint: "https://authn/introspect", IntrospectionTLS: "authn", RequiredScope: "documents:read", ResourcePathParam: "project_id"},
	}}
	snapshot := &csarv1.FullConfigSnapshot{Routes: []*csarv1.RouteConfig{{Path: "/catalog", Method: "GET", AuthValidate: authValidateToProto(original)}}}
	wire, err := proto.Marshal(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	var decoded csarv1.FullConfigSnapshot
	if err := proto.Unmarshal(wire, &decoded); err != nil {
		t.Fatal(err)
	}
	restored := protoconv.FullSnapshotToConfig(&decoded)
	got := restored.Paths["/catalog"]["get"].AuthValidate
	if !reflect.DeepEqual(original, got) {
		t.Fatalf("authentication methods lost: %+v", got)
	}
}
