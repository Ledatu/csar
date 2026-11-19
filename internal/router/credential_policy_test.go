package router

import (
	"context"
	"testing"

	"github.com/ledatu/csar/internal/config"
	"github.com/ledatu/csar/pkg/middleware"
)

func policyRoute() config.FlatRoute {
	return config.FlatRoute{Method: "POST", Path: "/external/{tenant_id:[a-z]+}", Route: config.RouteConfig{Backend: config.BackendConfig{TargetURL: "http://localhost:1"}, Security: config.SecurityConfigs{{TokenRef: "apps/example/{path.tenant_id}/api_key", InjectHeader: "X-Api-Key"}}}}
}

func TestCredentialRejectionSelectionMustBeExactAndUnambiguous(t *testing.T) {
	route := policyRoute()
	key := "POST:" + route.Path
	absent := route
	absent.Route.Security = nil
	badMethod := route
	badMethod.Method = "PO ST"
	extendedMethod := route
	extendedMethod.Method = "VERSION-CONTROL"
	multiple := route
	multiple.Route.Security = append(append(config.SecurityConfigs(nil), route.Route.Security...), config.SecurityConfig{TokenRef: "apps/example/client_id", InjectHeader: "X-Client-ID"})
	cases := []struct {
		name    string
		keys    []string
		routes  []config.FlatRoute
		invalid bool
	}{
		{"disabled", nil, []config.FlatRoute{multiple}, false},
		{"exact regex path", []string{key}, []config.FlatRoute{route}, false},
		{"invalid method even in configuration", []string{"PO ST:" + route.Path}, []config.FlatRoute{badMethod}, true},
		{"extension method", []string{"VERSION-CONTROL:" + route.Path}, []config.FlatRoute{extendedMethod}, false},
		{"missing delimiter", []string{"POST /external"}, []config.FlatRoute{route}, true},
		{"lowercase method", []string{"post:" + route.Path}, []config.FlatRoute{route}, true},
		{"empty method", []string{":" + route.Path}, []config.FlatRoute{route}, true},
		{"nonabsolute path", []string{"POST:external"}, []config.FlatRoute{route}, true},
		{"surrounding whitespace", []string{key + " "}, []config.FlatRoute{route}, true},
		{"unknown route", []string{"POST:/missing"}, []config.FlatRoute{route}, true},
		{"duplicate selection", []string{key, key}, []config.FlatRoute{route}, true},
		{"ambiguous configuration", []string{key}, []config.FlatRoute{route, route}, true},
		{"no injection", []string{key}, []config.FlatRoute{absent}, true},
		{"multiple refs", []string{key}, []config.FlatRoute{multiple}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			selected, err := credentialRejectionSelections(tc.keys, tc.routes)
			if (err != nil) != tc.invalid {
				t.Fatalf("selection result=%v error=%v", selected, err)
			}
			if !tc.invalid && len(selected) != len(tc.keys) {
				t.Fatal("selection did not preserve exact keys")
			}
		})
	}
}

type policyFetcher struct{}

func (policyFetcher) GetEncryptedToken(context.Context, string) ([]byte, string, string, error) {
	return []byte("fixture"), "", "v1", nil
}
func (policyFetcher) ReportCredentialRejection(context.Context, string, string, string) error {
	return nil
}

func TestCredentialRejectionPolicyValidatedAgainOnReload(t *testing.T) {
	flat := policyRoute()
	path := flat.Path
	cfg := newTestConfig(map[string]config.PathConfig{path: {"POST": flat.Route}})
	injector := middleware.NewAuthInjector(policyFetcher{}, nil, newTestLogger())
	options := []Option{WithAuthInjector(injector), WithCredentialRejectionRoutes("POST:" + path)}
	current, err := New(cfg, newTestLogger(), options...)
	if err != nil {
		t.Fatal(err)
	}
	defer current.Close()
	// The same options used by file and coordinator reloads must reject a
	// disappearing route or newly ambiguous credential attribution.
	missing := newTestConfig(map[string]config.PathConfig{})
	if replacement, reloadErr := New(missing, newTestLogger(), options...); reloadErr == nil {
		replacement.Close()
		t.Fatal("removed opt-in target accepted on reload")
	}
	multi := flat.Route
	multi.Security = append(append(config.SecurityConfigs(nil), multi.Security...), config.SecurityConfig{TokenRef: "apps/example/client_id", InjectHeader: "X-Client-ID"})
	if replacement, reloadErr := New(newTestConfig(map[string]config.PathConfig{path: {"POST": multi}}), newTestLogger(), options...); reloadErr == nil {
		replacement.Close()
		t.Fatal("multi-ref target accepted on reload")
	}
	active, _ := current.matchRoute("POST", "/external/customer")
	if active == nil || !active.rejectCredentialUnauthorized {
		t.Fatal("failed reload changed current policy")
	}
}

func TestCredentialRejectionSelectionNeedsReportingCapability(t *testing.T) {
	flat := policyRoute()
	cfg := newTestConfig(map[string]config.PathConfig{flat.Path: {"POST": flat.Route}})
	injector := middleware.NewAuthInjector(middleware.NewStaticTokenFetcher(), nil, newTestLogger())
	if r, err := New(cfg, newTestLogger(), WithAuthInjector(injector), WithCredentialRejectionRoutes("POST:"+flat.Path)); err == nil {
		r.Close()
		t.Fatal("opt-in silently ignored missing reporting capability")
	}
}
