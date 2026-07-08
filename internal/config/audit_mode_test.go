package config

import (
	"testing"

	"gopkg.in/yaml.v3"
)

func TestAuditModeUnmarshalYAML(t *testing.T) {
	tests := []struct {
		in   string
		want AuditMode
	}{
		{"true", AuditModeAll},
		{"false", AuditModeOff},
		{"all", AuditModeAll},
		{"off", AuditModeOff},
		{"errors", AuditModeErrors},
		{"ERRORS", AuditModeErrors},
	}

	for _, tc := range tests {
		var mode AuditMode
		if err := yaml.Unmarshal([]byte(tc.in), &mode); err != nil {
			t.Fatalf("%q: %v", tc.in, err)
		}
		if mode != tc.want {
			t.Fatalf("%q = %q, want %q", tc.in, mode, tc.want)
		}
	}
}

func TestResolveAuditCapturePolicies(t *testing.T) {
	reqTrue := true
	cfg := &Config{
		Audit: &AuditClientConfig{
			Address: "audit:9084",
			Capture: &AuditCaptureConfig{
				MaxBytes: 8192,
				Mask:     "MASK",
			},
		},
		RedactPolicies: map[string]RedactConfig{
			"seller-secrets": {Fields: []string{"wbToken"}},
		},
		AuditCapturePolicies: map[string]AuditCaptureConfig{
			"seller-mutation-audit": {
				Request: &reqTrue,
				Redact:  "seller-secrets",
			},
		},
		Paths: map[string]PathConfig{
			"/seller/test": {
				"post": {
					AuditCapture: &AuditCaptureConfig{Use: "seller-mutation-audit"},
				},
			},
		},
	}

	if err := cfg.ResolveAuditCapturePolicies(); err != nil {
		t.Fatal(err)
	}

	route := cfg.Paths["/seller/test"]["post"]
	if route.AuditCapture == nil || !route.AuditCapture.CaptureRequestEnabled() {
		t.Fatal("expected resolved capture with request true")
	}
	if route.AuditCapture.MaxBytes != 8192 {
		t.Fatalf("max_bytes = %d", route.AuditCapture.MaxBytes)
	}
	if len(route.AuditCapture.Fields) != 1 || route.AuditCapture.Fields[0] != "wbToken" {
		t.Fatalf("fields = %v", route.AuditCapture.Fields)
	}
}
