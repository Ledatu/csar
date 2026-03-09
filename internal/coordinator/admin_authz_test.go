package coordinator

import "testing"

func TestCheckAdminAuthorization(t *testing.T) {
	tests := []struct {
		name     string
		claims   *AdminClaims
		authz    AdminAuthzConfig
		op       AdminOperation
		tokenRef string
		kmsKeyID string
		wantErr  bool
	}{
		{
			name:     "nil claims",
			claims:   nil,
			op:       OpWrite,
			tokenRef: "balance/token",
			wantErr:  true,
		},
		{
			name: "valid write scope",
			claims: &AdminClaims{
				Sub:   "svc-deployer",
				Scope: "csar.token.write csar.token.read",
			},
			op:       OpWrite,
			tokenRef: "balance/token",
			wantErr:  false,
		},
		{
			name: "missing write scope",
			claims: &AdminClaims{
				Sub:   "svc-reader",
				Scope: "csar.token.read",
			},
			op:       OpWrite,
			tokenRef: "balance/token",
			wantErr:  true,
		},
		{
			name: "token prefix enforced - missing claim",
			claims: &AdminClaims{
				Sub:   "svc-deployer",
				Scope: "csar.token.write",
			},
			authz:    AdminAuthzConfig{EnforceTokenPrefixClaim: true},
			op:       OpWrite,
			tokenRef: "balance/upstream_api",
			wantErr:  true,
		},
		{
			name: "token prefix enforced - match",
			claims: &AdminClaims{
				Sub:         "svc-balance",
				Scope:       "csar.token.write",
				TokenPrefix: "balance/",
			},
			authz:    AdminAuthzConfig{EnforceTokenPrefixClaim: true},
			op:       OpWrite,
			tokenRef: "balance/upstream_api",
			wantErr:  false,
		},
		{
			name: "token prefix enforced - mismatch",
			claims: &AdminClaims{
				Sub:         "svc-balance",
				Scope:       "csar.token.write",
				TokenPrefix: "balance/",
			},
			authz:    AdminAuthzConfig{EnforceTokenPrefixClaim: true},
			op:       OpWrite,
			tokenRef: "bidding/upstream_api",
			wantErr:  true,
		},
		{
			name: "allowed kms keys claim - match",
			claims: &AdminClaims{
				Sub:            "svc-deployer",
				Scope:          "csar.token.write",
				AllowedKMSKeys: []string{"key-balance-main"},
			},
			authz:    AdminAuthzConfig{EnforceAllowedKMSKeys: true},
			op:       OpWrite,
			tokenRef: "balance/token",
			kmsKeyID: "key-balance-main",
			wantErr:  false,
		},
		{
			name: "allowed kms keys claim - mismatch",
			claims: &AdminClaims{
				Sub:            "svc-deployer",
				Scope:          "csar.token.write",
				AllowedKMSKeys: []string{"key-balance-main"},
			},
			authz:    AdminAuthzConfig{EnforceAllowedKMSKeys: true},
			op:       OpWrite,
			tokenRef: "balance/token",
			kmsKeyID: "key-bidding-main",
			wantErr:  true,
		},
		{
			name: "server-side allowed kms keys - mismatch",
			claims: &AdminClaims{
				Sub:   "svc-deployer",
				Scope: "csar.token.write",
			},
			authz: AdminAuthzConfig{
				AllowedKMSKeys: []string{"key-balance-main", "key-bidding-main"},
			},
			op:       OpWrite,
			tokenRef: "balance/token",
			kmsKeyID: "key-unknown",
			wantErr:  true,
		},
		{
			name: "server-side allowed kms keys - match",
			claims: &AdminClaims{
				Sub:   "svc-deployer",
				Scope: "csar.token.write",
			},
			authz: AdminAuthzConfig{
				AllowedKMSKeys: []string{"key-balance-main"},
			},
			op:       OpWrite,
			tokenRef: "balance/token",
			kmsKeyID: "key-balance-main",
			wantErr:  false,
		},
		{
			name: "delete scope",
			claims: &AdminClaims{
				Sub:   "svc-deployer",
				Scope: "csar.token.delete",
			},
			op:       OpDelete,
			tokenRef: "balance/token",
			wantErr:  false,
		},
		{
			name: "rotate scope",
			claims: &AdminClaims{
				Sub:   "svc-deployer",
				Scope: "csar.token.rotate",
			},
			op:       OpRotate,
			tokenRef: "balance/token",
			wantErr:  false,
		},
		{
			name: "no kms key - no enforcement",
			claims: &AdminClaims{
				Sub:   "svc-deployer",
				Scope: "csar.token.write",
			},
			authz:    AdminAuthzConfig{EnforceAllowedKMSKeys: true},
			op:       OpWrite,
			tokenRef: "balance/token",
			kmsKeyID: "",
			wantErr:  false,
		},
		{
			name: "allowed kms keys enforced - missing claim with kms_key_id present",
			claims: &AdminClaims{
				Sub:   "svc-deployer",
				Scope: "csar.token.write",
			},
			authz:    AdminAuthzConfig{EnforceAllowedKMSKeys: true},
			op:       OpWrite,
			tokenRef: "balance/token",
			kmsKeyID: "key-1",
			wantErr:  true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := CheckAdminAuthorization(tc.claims, tc.authz, tc.op, tc.tokenRef, tc.kmsKeyID)
			if (err != nil) != tc.wantErr {
				t.Errorf("CheckAdminAuthorization() error = %v, wantErr %v", err, tc.wantErr)
			}
		})
	}
}

func TestHasScope(t *testing.T) {
	tests := []struct {
		scopeStr string
		required string
		want     bool
	}{
		{"csar.token.write csar.token.read", "csar.token.write", true},
		{"csar.token.read", "csar.token.write", false},
		{"", "csar.token.write", false},
		{"csar.token.write", "csar.token.write", true},
	}

	for _, tc := range tests {
		got := hasScope(tc.scopeStr, tc.required)
		if got != tc.want {
			t.Errorf("hasScope(%q, %q) = %v, want %v", tc.scopeStr, tc.required, got, tc.want)
		}
	}
}
