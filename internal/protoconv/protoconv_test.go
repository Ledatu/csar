package protoconv

import (
	"testing"

	csarv1 "github.com/ledatu/csar/proto/csar/v1"
)

func TestProtoToAuthValidateConfig_PreservesJWKSTLS(t *testing.T) {
	cfg := protoToAuthValidateConfig(&csarv1.AuthValidateConfigProto{
		Mode:    "jwt",
		JwksUrl: "https://auth.example.com/.well-known/jwks.json",
		JwksTls: "authn-mtls",
	})

	if cfg.JWKSTLS != "authn-mtls" {
		t.Fatalf("JWKSTLS = %q, want authn-mtls", cfg.JWKSTLS)
	}
}

func TestFullSnapshotToConfig_BackendTLSPolicies(t *testing.T) {
	snap := &csarv1.FullConfigSnapshot{
		BackendTlsPolicies: map[string]*csarv1.BackendTLSConfigProto{
			"authn-mtls": {
				CaFile:   "/etc/csar/tls/ca.pem",
				CertFile: "/etc/csar/tls/csar-client.pem",
				KeyFile:  "/etc/csar/tls/csar-client-key.pem",
			},
			"insecure-dev": {
				InsecureSkipVerify: true,
			},
		},
	}

	cfg := FullSnapshotToConfig(snap)

	if len(cfg.BackendTLSPolicies) != 2 {
		t.Fatalf("BackendTLSPolicies len = %d, want 2", len(cfg.BackendTLSPolicies))
	}

	mtls, ok := cfg.BackendTLSPolicies["authn-mtls"]
	if !ok {
		t.Fatal("BackendTLSPolicies missing authn-mtls")
	}
	if mtls.CAFile != "/etc/csar/tls/ca.pem" {
		t.Errorf("CAFile = %q, want /etc/csar/tls/ca.pem", mtls.CAFile)
	}
	if mtls.CertFile != "/etc/csar/tls/csar-client.pem" {
		t.Errorf("CertFile = %q, want /etc/csar/tls/csar-client.pem", mtls.CertFile)
	}
	if mtls.KeyFile != "/etc/csar/tls/csar-client-key.pem" {
		t.Errorf("KeyFile = %q, want /etc/csar/tls/csar-client-key.pem", mtls.KeyFile)
	}
	if mtls.InsecureSkipVerify {
		t.Error("authn-mtls InsecureSkipVerify = true, want false")
	}

	dev, ok := cfg.BackendTLSPolicies["insecure-dev"]
	if !ok {
		t.Fatal("BackendTLSPolicies missing insecure-dev")
	}
	if !dev.InsecureSkipVerify {
		t.Error("insecure-dev InsecureSkipVerify = false, want true")
	}
}

func TestFullSnapshotToConfig_BackendTLSPoliciesNil(t *testing.T) {
	snap := &csarv1.FullConfigSnapshot{}
	cfg := FullSnapshotToConfig(snap)

	if cfg.BackendTLSPolicies != nil {
		t.Fatalf("BackendTLSPolicies = %v, want nil for empty snapshot", cfg.BackendTLSPolicies)
	}
}

func TestFullSnapshotToConfig_SessionTLSWithBackendTLSPolicy(t *testing.T) {
	snap := &csarv1.FullConfigSnapshot{
		Routes: []*csarv1.RouteConfig{
			{
				Path:   "/support/tickets/{ticketID}",
				Method: "PATCH",
				Backend: &csarv1.BackendConfigProto{
					TargetUrl: "https://support:8086",
					PathMode:  "append",
					Tls: &csarv1.BackendTLSConfigProto{
						CaFile:   "/etc/csar/tls/ca.pem",
						CertFile: "/etc/csar/tls/csar-client.pem",
						KeyFile:  "/etc/csar/tls/csar-client-key.pem",
					},
				},
				AuthValidate: &csarv1.AuthValidateConfigProto{
					Mode:            "session",
					SessionEndpoint: "https://authn:8081/auth/validate",
					SessionTls:      "authn-mtls",
					CookieName:      "csar_session",
					ForwardHeaders:  []string{"X-Gateway-Subject"},
				},
			},
		},
		BackendTlsPolicies: map[string]*csarv1.BackendTLSConfigProto{
			"authn-mtls": {
				CaFile:   "/etc/csar/tls/ca.pem",
				CertFile: "/etc/csar/tls/csar-client.pem",
				KeyFile:  "/etc/csar/tls/csar-client-key.pem",
			},
		},
	}

	cfg := FullSnapshotToConfig(snap)

	route, ok := cfg.Paths["/support/tickets/{ticketID}"]["patch"]
	if !ok {
		t.Fatal("route PATCH /support/tickets/{ticketID} not found")
	}
	if route.AuthValidate == nil {
		t.Fatal("route AuthValidate is nil")
	}
	if route.AuthValidate.SessionTLS != "authn-mtls" {
		t.Errorf("SessionTLS = %q, want authn-mtls", route.AuthValidate.SessionTLS)
	}

	policy, ok := cfg.BackendTLSPolicies["authn-mtls"]
	if !ok {
		t.Fatal("BackendTLSPolicies missing authn-mtls")
	}
	if policy.CertFile != "/etc/csar/tls/csar-client.pem" {
		t.Errorf("policy CertFile = %q, want /etc/csar/tls/csar-client.pem", policy.CertFile)
	}
}
