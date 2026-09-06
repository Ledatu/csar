package coordinator

import (
	"testing"

	"github.com/ledatu/csar/internal/config"
)

func TestAuthzToProto_PreservesAnyOfAndPolicyName(t *testing.T) {
	in := &config.AuthzRouteConfig{
		PolicyName: "campaign-read",
		AnyOf: []config.AuthzRouteConfig{
			{
				PolicyName: "campaign-tenant-read",
				Subject:    "{header.X-Gateway-Subject}",
				Resource:   "campaign",
				Action:     "read",
				ScopeType:  "tenant",
				ScopeID:    "{path.marketplace}:{path.external_id}",
			},
			{
				PolicyName: "campaign-platform-read",
				Subject:    "{header.X-Gateway-Subject}",
				Resource:   "campaign",
				Action:     "read",
				ScopeType:  "platform",
			},
		},
	}

	out := authzToProto(in)

	if out.GetPolicyName() != "campaign-read" {
		t.Errorf("PolicyName = %q, want campaign-read", out.GetPolicyName())
	}
	if len(out.GetAnyOf()) != 2 {
		t.Fatalf("len(AnyOf) = %d, want 2", len(out.GetAnyOf()))
	}
	if b := out.GetAnyOf()[0]; b.GetPolicyName() != "campaign-tenant-read" || b.GetScopeType() != "tenant" || b.GetScopeId() == "" {
		t.Errorf("branch 0 = %+v", b)
	}
	if b := out.GetAnyOf()[1]; b.GetPolicyName() != "campaign-platform-read" || b.GetScopeType() != "platform" {
		t.Errorf("branch 1 = %+v", b)
	}
}

func TestAuthzToProto_TerminalHasNoBranches(t *testing.T) {
	out := authzToProto(&config.AuthzRouteConfig{
		PolicyName: "support-platform-read",
		Subject:    "{header.X-Gateway-Subject}",
		Resource:   "support",
		Action:     "read",
		ScopeType:  "platform",
	})
	if len(out.GetAnyOf()) != 0 || out.GetPolicyName() != "support-platform-read" || out.GetResource() != "support" {
		t.Errorf("terminal conversion = %+v", out)
	}
}
