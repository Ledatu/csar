package coordinator

import (
	"testing"
	"time"
)

func TestAdminAPIConfig_Validate(t *testing.T) {
	boolPtr := func(v bool) *bool { return &v }

	tests := []struct {
		name    string
		cfg     AdminAPIConfig
		wantErr bool
	}{
		{
			name:    "disabled - no validation",
			cfg:     AdminAPIConfig{Enabled: false},
			wantErr: false,
		},
		{
			name: "missing listen_addr",
			cfg: AdminAPIConfig{
				Enabled: true,
			},
			wantErr: true,
		},
		{
			name: "missing s3_manages_encryption",
			cfg: AdminAPIConfig{
				Enabled:       true,
				ListenAddr:    ":9443",
				AllowInsecure: true,
				Auth: AdminAuthConfig{
					JWKSUrl:   "https://auth/.well-known/jwks.json",
					Issuer:    "https://auth",
					Audiences: []string{"csar-coordinator-admin"},
				},
			},
			wantErr: true,
		},
		{
			name: "missing TLS when not insecure",
			cfg: AdminAPIConfig{
				Enabled:             true,
				ListenAddr:          ":9443",
				S3ManagesEncryption: boolPtr(false),
				Auth: AdminAuthConfig{
					JWKSUrl:   "https://auth/.well-known/jwks.json",
					Issuer:    "https://auth",
					Audiences: []string{"csar-coordinator-admin"},
				},
			},
			wantErr: true,
		},
		{
			name: "missing TLS allowed in insecure mode",
			cfg: AdminAPIConfig{
				Enabled:             true,
				ListenAddr:          ":9443",
				S3ManagesEncryption: boolPtr(false),
				AllowInsecure:       true,
				Auth: AdminAuthConfig{
					JWKSUrl:   "https://auth/.well-known/jwks.json",
					Issuer:    "https://auth",
					Audiences: []string{"csar-coordinator-admin"},
				},
			},
			wantErr: false,
		},
		{
			name: "missing jwks_url",
			cfg: AdminAPIConfig{
				Enabled:             true,
				ListenAddr:          ":9443",
				S3ManagesEncryption: boolPtr(false),
				AllowInsecure:       true,
			},
			wantErr: true,
		},
		{
			name: "missing issuer",
			cfg: AdminAPIConfig{
				Enabled:             true,
				ListenAddr:          ":9443",
				S3ManagesEncryption: boolPtr(false),
				AllowInsecure:       true,
				Auth: AdminAuthConfig{
					JWKSUrl: "https://auth/.well-known/jwks.json",
				},
			},
			wantErr: true,
		},
		{
			name: "missing audiences",
			cfg: AdminAPIConfig{
				Enabled:             true,
				ListenAddr:          ":9443",
				S3ManagesEncryption: boolPtr(false),
				AllowInsecure:       true,
				Auth: AdminAuthConfig{
					JWKSUrl: "https://auth/.well-known/jwks.json",
					Issuer:  "https://auth",
				},
			},
			wantErr: true,
		},
		{
			name: "valid config - s3 managed",
			cfg: AdminAPIConfig{
				Enabled:             true,
				ListenAddr:          ":9443",
				S3ManagesEncryption: boolPtr(true),
				AllowInsecure:       true,
				Auth: AdminAuthConfig{
					JWKSUrl:   "https://auth/.well-known/jwks.json",
					Issuer:    "https://auth",
					Audiences: []string{"csar-coordinator-admin"},
				},
			},
			wantErr: false,
		},
		{
			name: "valid config - kms managed",
			cfg: AdminAPIConfig{
				Enabled:             true,
				ListenAddr:          ":9443",
				S3ManagesEncryption: boolPtr(false),
				AllowInsecure:       true,
				Auth: AdminAuthConfig{
					JWKSUrl:   "https://auth/.well-known/jwks.json",
					Issuer:    "https://auth",
					Audiences: []string{"csar-coordinator-admin"},
				},
			},
			wantErr: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.cfg.Validate()
			if (err != nil) != tc.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tc.wantErr)
			}
		})
	}
}

func TestAdminAPIConfig_Validate_DefaultLimits(t *testing.T) {
	boolPtr := func(v bool) *bool { return &v }

	cfg := AdminAPIConfig{
		Enabled:             true,
		ListenAddr:          ":9443",
		S3ManagesEncryption: boolPtr(true),
		AllowInsecure:       true,
		Auth: AdminAuthConfig{
			JWKSUrl:   "https://auth/.well-known/jwks.json",
			Issuer:    "https://auth",
			Audiences: []string{"csar-coordinator-admin"},
		},
	}

	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate() error = %v", err)
	}

	if cfg.Limits.MaxTokenSize != 16384 {
		t.Errorf("MaxTokenSize = %d, want 16384", cfg.Limits.MaxTokenSize)
	}
	if cfg.Limits.RequestTimeout != 5*time.Second {
		t.Errorf("RequestTimeout = %v, want 5s", cfg.Limits.RequestTimeout)
	}
}

func TestAdminAPIConfig_Validate_BadSvcConfig(t *testing.T) {
	boolPtr := func(v bool) *bool { return &v }

	cfg := AdminAPIConfig{
		Enabled:             true,
		ListenAddr:          ":9443",
		S3ManagesEncryption: boolPtr(true),
		AllowInsecure:       true,
		Auth: AdminAuthConfig{
			JWKSUrl:   "https://auth/.well-known/jwks.json",
			Issuer:    "https://auth",
			Audiences: []string{"csar-coordinator-admin"},
		},
		Svc: SvcAPIConfig{
			PrefixMap: map[string]string{"": "campaigns/"},
		},
	}

	if err := cfg.Validate(); err == nil {
		t.Error("expected Validate() to fail for empty subject in SvcAPIConfig.PrefixMap")
	}
}
