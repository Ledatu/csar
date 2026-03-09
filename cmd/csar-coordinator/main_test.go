package main

import (
	"context"
	"testing"
)

func TestParseAllowlist(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  []string
	}{
		{"empty", "", nil},
		{"single", "router-1", []string{"router-1"}},
		{"multiple", "router-1,router-2,router-3", []string{"router-1", "router-2", "router-3"}},
		{"with spaces", " router-1 , router-2 ", []string{"router-1", "router-2"}},
		{"trailing comma", "router-1,", []string{"router-1"}},
		{"only commas", ",,", nil},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parseAllowlist(tt.input)
			if len(got) != len(tt.want) {
				t.Fatalf("parseAllowlist(%q) = %v, want %v", tt.input, got, tt.want)
			}
			for i, g := range got {
				if g != tt.want[i] {
					t.Errorf("parseAllowlist(%q)[%d] = %q, want %q", tt.input, i, g, tt.want[i])
				}
			}
		})
	}
}

func TestCheckIdentity_NoAllowlist_DevMode_AllowsAnyone(t *testing.T) {
	// Insecure dev mode (requirePeerCert=false) — should allow without identity.
	ctx := context.Background()
	err := checkIdentity(ctx, nil, false)
	if err != nil {
		t.Errorf("checkIdentity in dev mode with nil allowlist should allow, got: %v", err)
	}

	err = checkIdentity(ctx, []string{}, false)
	if err != nil {
		t.Errorf("checkIdentity in dev mode with empty allowlist should allow, got: %v", err)
	}
}

func TestCheckIdentity_NoAllowlist_TLSMode_RequiresCert(t *testing.T) {
	// TLS mode (requirePeerCert=true) — must reject callers without a cert
	// even when no allowlist is configured.
	ctx := context.Background()
	err := checkIdentity(ctx, nil, true)
	if err == nil {
		t.Fatal("checkIdentity in TLS mode with no peer cert should deny, got nil error")
	}
	errMsg := err.Error()
	if !contains(errMsg, "no verified client certificate") {
		t.Errorf("error should mention missing certificate, got: %v", err)
	}

	err = checkIdentity(ctx, []string{}, true)
	if err == nil {
		t.Fatal("checkIdentity in TLS mode with empty allowlist and no peer cert should deny, got nil error")
	}
}

func TestCheckIdentity_AllowlistSet_DeniesWithoutIdentity(t *testing.T) {
	// Allowlist is configured but no TLS peer info in context — must deny.
	ctx := context.Background()
	allowlist := []string{"router-1", "router-2"}

	err := checkIdentity(ctx, allowlist, true)
	if err == nil {
		t.Fatal("checkIdentity with allowlist but no peer identity should deny, got nil error")
	}

	// Should be Unauthenticated, not PermissionDenied
	errMsg := err.Error()
	if !contains(errMsg, "no verified client certificate") {
		t.Errorf("error should mention missing certificate, got: %v", err)
	}
}

func TestCheckIdentity_AllowlistSet_DeniesUnknownIdentity(t *testing.T) {
	// Even with an empty context (no peer), the allowlist should reject.
	ctx := context.Background()
	allowlist := []string{"router-1"}

	err := checkIdentity(ctx, allowlist, true)
	if err == nil {
		t.Fatal("checkIdentity should deny unknown identity")
	}
}

// contains is a helper for substring matching in tests.
func contains(s, substr string) bool {
	return len(s) >= len(substr) && len(s) > 0 && containsImpl(s, substr)
}

func containsImpl(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
