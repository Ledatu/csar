package routepattern

import (
	"math/rand"
	"reflect"
	"sort"
	"strings"
	"testing"
)

func TestCompile(t *testing.T) {
	tests := []struct {
		path    string
		want    string
		vars    []string
		isRegex bool
	}{
		{path: "/api/v1/products"},
		{path: "/api/v1/users/{id:[0-9]+}", want: `^/api/v1/users/([0-9]+)$`, vars: []string{"id"}, isRegex: true},
		{path: "/api/{version:v[0-9]+}/items/{id}", want: `^/api/(v[0-9]+)/items/([^/]+)$`, vars: []string{"version", "id"}, isRegex: true},
		{path: "/files/{name}.json", want: `^/files/([^/]+)\.json$`, vars: []string{"name"}, isRegex: true},
		{path: "/x/{empty:}", want: `^/x/()$`, vars: []string{"empty"}, isRegex: true},
		{path: "/x/{rest:.*}", want: `^/x/(.*)$`, vars: []string{"rest"}, isRegex: true},
		{path: "/x/{unclosed", want: `^/x/\{unclosed$`, isRegex: true},
		{path: "/x/{bad:(a+)+}"},
		{path: "/x/{long:" + strings.Repeat("a", maxRegexLength) + "}"},
	}
	for _, tt := range tests {
		re, vars, ok := Compile(tt.path)
		if ok != tt.isRegex {
			t.Errorf("Compile(%q) ok = %v, want %v", tt.path, ok, tt.isRegex)
			continue
		}
		if !ok {
			continue
		}
		if re.String() != tt.want {
			t.Errorf("Compile(%q) = %q, want %q", tt.path, re.String(), tt.want)
		}
		if !reflect.DeepEqual(vars, tt.vars) {
			t.Errorf("Compile(%q) vars = %v, want %v", tt.path, vars, tt.vars)
		}
	}
}

func TestMorePreciseThan(t *testing.T) {
	tests := []struct {
		precise, wide string
	}{
		{
			"/svc/wb/{marketplace}/{external_id}/finance/api/finance/v1/sales-reports/list",
			"/svc/wb/{marketplace}/{external_id}/finance/{rest:.*}",
		},
		{
			"/svc/wb/{marketplace}/{external_id}/content/content/v2/get/cards/list",
			"/svc/wb/{marketplace}/{external_id}/content/{rest:.*}",
		},
		{
			"/svc/ozon/{marketplace}/{external_id}/api/client/statistics/report",
			"/svc/ozon/{marketplace}/{external_id}/api/client/statistics/{report_uuid}",
		},
		{"/items/{id:[0-9]+}", "/items/{slug}"},
		{"/items/v{version}", "/items/{version}"},
		{"/items/{id}.json", "/items/{id:[0-9]+}"},
		{"/prices/{report:list/goods/filter|quarantine/goods}", "/prices/{rest:.*}"},
		{"/x/{rest:.*}", "/{a}/{b}/{c}/{d}"},
		{"/a/{x}/b", "/a/{rest:.+}"},
		{"/a/{x}/{y}", "/a/{x}"},
		{"/a/{x}/long-literal", "/a/{x}/short"},
		{"/a/{x}/aa", "/a/{x}/bb"},
	}
	for _, tt := range tests {
		p, w := SpecificityOf(tt.precise), SpecificityOf(tt.wide)
		if !p.MorePreciseThan(w) {
			t.Errorf("%q should be more precise than %q", tt.precise, tt.wide)
		}
		if w.MorePreciseThan(p) {
			t.Errorf("%q must not be more precise than %q", tt.wide, tt.precise)
		}
	}
}

func TestMorePreciseThan_IsIrreflexive(t *testing.T) {
	s := SpecificityOf("/svc/wb/{marketplace}/{external_id}/finance/{rest:.*}")
	if s.MorePreciseThan(s) {
		t.Fatal("a template must not be more precise than itself")
	}
}

func TestSortOrderDoesNotDependOnInputOrder(t *testing.T) {
	paths := []string{
		"/svc/wb/{marketplace}/{external_id}/finance/{rest:.*}",
		"/svc/wb/{marketplace}/{external_id}/finance/api/finance/v1/sales-reports/list",
		"/svc/wb/{marketplace}/{external_id}/finance/api/finance/v1/sales-reports/detailed/{report_id}",
		"/svc/wb/{marketplace}/{external_id}/content/{rest:.*}",
		"/svc/wb/{marketplace}/{external_id}/content/content/v2/get/cards/list",
		"/svc/ozon/{marketplace}/{external_id}/api/client/statistics/{report_uuid}",
		"/svc/ozon/{marketplace}/{external_id}/api/client/statistics/report",
		"/svc/{rest:.*}",
	}
	sorted := func(in []string) []string {
		out := append([]string(nil), in...)
		sort.Slice(out, func(i, j int) bool {
			return SpecificityOf(out[i]).MorePreciseThan(SpecificityOf(out[j]))
		})
		return out
	}
	want := sorted(paths)
	rng := rand.New(rand.NewSource(1))
	for i := 0; i < 50; i++ {
		shuffled := append([]string(nil), paths...)
		rng.Shuffle(len(shuffled), func(a, b int) { shuffled[a], shuffled[b] = shuffled[b], shuffled[a] })
		if got := sorted(shuffled); !reflect.DeepEqual(got, want) {
			t.Fatalf("order depends on input order:\n got %v\nwant %v", got, want)
		}
	}
	if want[len(want)-1] != "/svc/{rest:.*}" {
		t.Errorf("widest template should sort last, got order %v", want)
	}
}
