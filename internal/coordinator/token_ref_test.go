package coordinator

import "testing"

func TestValidateTokenRef(t *testing.T) {
	tests := []struct {
		name    string
		ref     string
		wantErr bool
	}{
		{"valid simple", "my_token", false},
		{"valid with slash", "balance/upstream_api", false},
		{"valid with dash", "my-token-ref", false},
		{"valid deep path", "tenant/service/token_name", false},
		{"valid with numbers", "v2/token123", false},

		{"empty", "", true},
		{"path traversal", "balance/../secret", true},
		{"leading slash", "/balance/token", true},
		{"leading double slash", "//balance/token", true},
		{"spaces", "balance token", true},
		{"special chars", "balance@token", true},
		{"dots in name", "balance..token", true},
		{"too long", string(make([]byte, 257)), true},
		{"colon", "balance:token", true},
		{"equals", "balance=token", true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateTokenRef(tc.ref)
			if (err != nil) != tc.wantErr {
				t.Errorf("ValidateTokenRef(%q) error = %v, wantErr %v", tc.ref, err, tc.wantErr)
			}
		})
	}
}
