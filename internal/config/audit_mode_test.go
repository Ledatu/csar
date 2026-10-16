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
	if !route.AuditCapture.RedactionEnabled() {
		t.Fatal("expected redaction enabled when redact policy resolved")
	}
}

func TestResolveAuditCapturePoliciesNoRedaction(t *testing.T) {
	reqTrue := true
	cfg := &Config{
		AuditCapturePolicies: map[string]AuditCaptureConfig{
			"seller-audit-capture": {
				Request: &reqTrue,
			},
		},
		Paths: map[string]PathConfig{
			"/seller/test": {
				"post": {
					AuditCapture: &AuditCaptureConfig{Use: "seller-audit-capture"},
				},
			},
		},
	}

	if err := cfg.ResolveAuditCapturePolicies(); err != nil {
		t.Fatal(err)
	}

	route := cfg.Paths["/seller/test"]["post"]
	if route.AuditCapture.RedactionEnabled() {
		t.Fatal("expected redaction disabled without redact policy")
	}
}

func TestResponseCapturePolicy(t *testing.T) {
	for _, mode := range []string{"errors", "off", "invalid"} {
		cfg := &Config{AuditCapturePolicies: map[string]AuditCaptureConfig{"errors": {Response: mode, ResponseMaxBytes: 2048}}, Paths: map[string]PathConfig{"/test": {"get": {AuditCapture: &AuditCaptureConfig{Use: "errors"}}}}}
		err := cfg.ResolveAuditCapturePolicies()
		if mode == "invalid" {
			if err == nil {
				t.Fatal("invalid mode accepted")
			}
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
		capture := cfg.Paths["/test"]["get"].AuditCapture
		if capture.Response != mode || capture.ResponseMaxBytes != 2048 || capture.CaptureRequestEnabled() {
			t.Fatalf("%+v", capture)
		}
	}
}

func TestResponseCaptureRejectsInvalidUnusedConfiguration(t *testing.T) {
	for _, capture := range []AuditCaptureConfig{{Response: "all"}, {ResponseMaxBytes: -1}, {ResponseMaxBytes: 4097}} {
		for _, global := range []bool{false, true} {
			cfg := &Config{}
			if global {
				cfg.Audit = &AuditClientConfig{Capture: &capture}
			} else {
				cfg.AuditCapturePolicies = map[string]AuditCaptureConfig{"unused": capture}
			}
			if err := cfg.ResolveAuditCapturePolicies(); err == nil {
				t.Fatalf("invalid config accepted: global=%v capture=%+v", global, capture)
			}
		}
	}
}

func TestResponseCaptureInheritanceAndExplicitOff(t *testing.T) {
	cfg := &Config{
		Audit: &AuditClientConfig{Capture: &AuditCaptureConfig{Response: "errors", ResponseMaxBytes: 1024}},
		Paths: map[string]PathConfig{"/test": {
			"get":    {AuditCapture: &AuditCaptureConfig{}},
			"post":   {AuditCapture: &AuditCaptureConfig{Response: "off"}},
			"delete": {},
		}},
	}
	if err := cfg.ResolveAuditCapturePolicies(); err != nil {
		t.Fatal(err)
	}
	get := cfg.Paths["/test"]["get"].AuditCapture
	post := cfg.Paths["/test"]["post"].AuditCapture
	if !get.CaptureResponseEnabled() || get.ResponseMaxBytes != 1024 || get.CaptureRequestEnabled() {
		t.Fatalf("inherited=%+v", get)
	}
	if post.CaptureResponseEnabled() || post.ResponseMaxBytes != 1024 {
		t.Fatalf("off=%+v", post)
	}
	if cfg.Paths["/test"]["delete"].AuditCapture != nil {
		t.Fatal("enabled capture implicitly")
	}
}
