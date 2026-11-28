package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ledatu/csar/internal/config"
	"github.com/ledatu/csar/internal/router"
)

func TestResponseCompressionPolicyAndGlobalDefaultSurviveReload(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":"` + strings.Repeat("x", 4096) + `"}`))
	}))
	defer upstream.Close()
	for _, global := range []bool{false, true} {
		cfg := reloadTestConfig(upstream.URL, &config.SSRFConfig{AllowedInternalHosts: []string{"127.0.0.1"}})
		rl := newTestReloader(t, cfg, router.WithResponseGzipDefault(global))
		for _, mode := range []string{"", "gzip", "passthrough", ""} {
			for _, snapshot := range []bool{false, true} {
				next := reloadTestConfig(upstream.URL, cfg.SSRF)
				if mode != "" {
					route := next.Paths["/preferences"]["get"]
					route.ResponseCompression = &config.ResponseCompressionConfig{Mode: mode}
					next.Paths["/preferences"]["get"] = route
				}
				next.PolicyVersions = config.PolicyCapabilities()
				var err error
				if snapshot {
					err = rl.Apply(next)
				} else {
					err = rl.Reload(next)
				}
				if err != nil {
					t.Fatal(err)
				}
				req := httptest.NewRequest(http.MethodGet, "/preferences", nil)
				req.Header.Set("Accept-Encoding", "gzip")
				rec := httptest.NewRecorder()
				rl.reloadHandler.ServeHTTP(rec, req)
				want := mode == "gzip" || mode == "" && global
				if rec.Code != 200 || (rec.Header().Get("Content-Encoding") == "gzip") != want {
					t.Fatalf("global=%v mode=%q snapshot=%v headers=%v body=%s", global, mode, snapshot, rec.Header(), rec.Body.String())
				}
			}
		}
	}
}
