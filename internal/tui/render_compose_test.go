package tui

import (
	"strings"
	"testing"
)

func TestRenderDockerCompose_UsesHealthSidecarProbe(t *testing.T) {
	t.Parallel()

	got := renderDockerCompose(&GenerateResult{
		ProjectName: "test",
		EnableTLS:   true,
		MetricsPort: "9100",
		RouterPort:  "8080",
		OutputDir:   ".",
	})

	if strings.Contains(got, "https://localhost:8080/health") {
		t.Fatal("renderDockerCompose() still probes the main HTTPS listener")
	}
	if strings.Contains(got, "--no-check-certificate") {
		t.Fatal("renderDockerCompose() should not disable TLS verification for healthchecks")
	}
	if !strings.Contains(got, "-health-addr :9100") {
		t.Fatal("renderDockerCompose() should pass -health-addr to the router")
	}
	if !strings.Contains(got, "http://127.0.0.1:9100/health") {
		t.Fatal("renderDockerCompose() should probe the plain HTTP health sidecar")
	}
}
