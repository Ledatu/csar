package config

import (
	"testing"
)

// ==========================================================================
// Profile enforcement tests (audit follow-up §1, §2)
// ==========================================================================

func TestValidate_Profile_UnknownProfile(t *testing.T) {
	cfg := &Config{
		ListenAddr: ":8080",
		Profile:    "production-mega", // invalid
		Paths: map[string]PathConfig{
			"/test": {"get": RouteConfig{Backend: BackendConfig{TargetURL: "http://localhost"}}},
		},
	}
	err := cfg.Validate()
	if err == nil {
		t.Fatal("Validate() should fail for unknown profile")
	}
	if !containsStr(err.Error(), "unknown profile") {
		t.Errorf("error should mention unknown profile, got: %v", err)
	}
}

func TestValidate_Profile_DevLocal_AllowsEverything(t *testing.T) {
	cfg := &Config{
		ListenAddr: ":8080",
		Profile:    "dev-local",
		Coordinator: CoordinatorConfig{
			AllowInsecure: true, // should be allowed
		},
		SecurityPolicy: &SecurityPolicyConfig{
			Environment: "dev",
		},
		KMS: &KMSConfig{
			Provider: "local",
		},
		Paths: map[string]PathConfig{
			"/test": {"get": RouteConfig{
				Backend: BackendConfig{TargetURL: "http://localhost"},
				Security: SecurityConfigs{
					{TokenRef: "tok", KMSKeyID: "key-1", InjectHeader: "Authorization"},
				},
			}},
		},
	}
	err := cfg.Validate()
	if err != nil {
		t.Fatalf("Validate() should pass for dev-local with relaxed settings: %v", err)
	}
}

func TestValidate_Profile_ProdSingle_RejectsInsecureCoordinator(t *testing.T) {
	cfg := &Config{
		ListenAddr: ":8080",
		Profile:    "prod-single",
		Coordinator: CoordinatorConfig{
			AllowInsecure: true,
		},
		Paths: map[string]PathConfig{
			"/test": {"get": RouteConfig{Backend: BackendConfig{TargetURL: "http://localhost"}}},
		},
	}
	err := cfg.Validate()
	if err == nil {
		t.Fatal("Validate() should fail for prod-single with allow_insecure")
	}
	if !containsStr(err.Error(), "allow_insecure") {
		t.Errorf("error should mention allow_insecure, got: %v", err)
	}
}

func TestValidate_Profile_ProdSingle_RejectsDevEnvironment(t *testing.T) {
	cfg := &Config{
		ListenAddr: ":8080",
		Profile:    "prod-single",
		SecurityPolicy: &SecurityPolicyConfig{
			Environment: "dev",
		},
		Paths: map[string]PathConfig{
			"/test": {"get": RouteConfig{Backend: BackendConfig{TargetURL: "http://localhost"}}},
		},
	}
	err := cfg.Validate()
	if err == nil {
		t.Fatal("Validate() should fail for prod-single with dev environment")
	}
	if !containsStr(err.Error(), "dev") {
		t.Errorf("error should mention dev, got: %v", err)
	}
}

func TestValidate_Profile_ProdSingle_RequiresTLSForSecureRoutes(t *testing.T) {
	cfg := &Config{
		ListenAddr: ":8080",
		Profile:    "prod-single",
		// No TLS configured
		Paths: map[string]PathConfig{
			"/test": {"get": RouteConfig{
				Backend: BackendConfig{TargetURL: "https://api.example.com"},
				Security: SecurityConfigs{
					{TokenRef: "tok", KMSKeyID: "key-1", InjectHeader: "Authorization"},
				},
			}},
		},
	}
	err := cfg.Validate()
	if err == nil {
		t.Fatal("Validate() should fail for prod-single with secure routes but no TLS")
	}
	if !containsStr(err.Error(), "TLS") {
		t.Errorf("error should mention TLS, got: %v", err)
	}
}

func TestValidate_Profile_ProdSingle_RejectsLocalKMS(t *testing.T) {
	cfg := &Config{
		ListenAddr: ":8080",
		Profile:    "prod-single",
		TLS:        &TLSConfig{CertFile: "cert.pem", KeyFile: "key.pem"},
		KMS: &KMSConfig{
			Provider: "local",
		},
		Paths: map[string]PathConfig{
			"/test": {"get": RouteConfig{
				Backend: BackendConfig{TargetURL: "https://api.example.com"},
				Security: SecurityConfigs{
					{TokenRef: "tok", KMSKeyID: "key-1", InjectHeader: "Authorization"},
				},
			}},
		},
	}
	err := cfg.Validate()
	if err == nil {
		t.Fatal("Validate() should fail for prod-single with local KMS and secure routes")
	}
	if !containsStr(err.Error(), "local") {
		t.Errorf("error should mention local, got: %v", err)
	}
}

func TestValidate_Profile_ProdSingle_PassesWithValidConfig(t *testing.T) {
	cfg := &Config{
		ListenAddr: ":8080",
		Profile:    "prod-single",
		TLS:        &TLSConfig{CertFile: "cert.pem", KeyFile: "key.pem"},
		KMS: &KMSConfig{
			Provider: "yandexapi",
			Yandex:   &YandexKMSConfig{AuthMode: "metadata"},
		},
		SecurityPolicy: &SecurityPolicyConfig{
			Environment: "prod",
		},
		Paths: map[string]PathConfig{
			"/test": {"get": RouteConfig{
				Backend: BackendConfig{TargetURL: "https://api.example.com"},
				Security: SecurityConfigs{
					{TokenRef: "tok", KMSKeyID: "key-1", InjectHeader: "Authorization"},
				},
			}},
		},
	}
	err := cfg.Validate()
	if err != nil {
		t.Fatalf("Validate() should pass for valid prod-single config: %v", err)
	}
}

func TestValidate_Profile_ProdDistributed_RequiresCoordinatorEnabled(t *testing.T) {
	cfg := &Config{
		ListenAddr: ":8080",
		Profile:    "prod-distributed",
		TLS:        &TLSConfig{CertFile: "cert.pem", KeyFile: "key.pem"},
		Coordinator: CoordinatorConfig{
			Enabled: false, // must be true
		},
		Paths: map[string]PathConfig{
			"/test": {"get": RouteConfig{Backend: BackendConfig{TargetURL: "http://localhost"}}},
		},
	}
	err := cfg.Validate()
	if err == nil {
		t.Fatal("Validate() should fail for prod-distributed without coordinator enabled")
	}
	if !containsStr(err.Error(), "coordinator") {
		t.Errorf("error should mention coordinator, got: %v", err)
	}
}

func TestValidate_Profile_ProdDistributed_RequiresCoordinatorAddress(t *testing.T) {
	cfg := &Config{
		ListenAddr: ":8080",
		Profile:    "prod-distributed",
		TLS:        &TLSConfig{CertFile: "cert.pem", KeyFile: "key.pem"},
		Coordinator: CoordinatorConfig{
			Enabled: true,
			Address: "", // must be non-empty
			CAFile:  "/path/to/ca.pem",
		},
		Paths: map[string]PathConfig{
			"/test": {"get": RouteConfig{Backend: BackendConfig{TargetURL: "http://localhost"}}},
		},
	}
	err := cfg.Validate()
	if err == nil {
		t.Fatal("Validate() should fail for prod-distributed without coordinator address")
	}
}

func TestValidate_Profile_ProdDistributed_RequiresCoordinatorCA(t *testing.T) {
	cfg := &Config{
		ListenAddr: ":8080",
		Profile:    "prod-distributed",
		TLS:        &TLSConfig{CertFile: "cert.pem", KeyFile: "key.pem"},
		Coordinator: CoordinatorConfig{
			Enabled: true,
			Address: "coord:9090",
			CAFile:  "", // must be non-empty
		},
		Paths: map[string]PathConfig{
			"/test": {"get": RouteConfig{Backend: BackendConfig{TargetURL: "http://localhost"}}},
		},
	}
	err := cfg.Validate()
	if err == nil {
		t.Fatal("Validate() should fail for prod-distributed without coordinator CA")
	}
	if !containsStr(err.Error(), "ca_file") {
		t.Errorf("error should mention ca_file, got: %v", err)
	}
}

func TestValidate_Profile_ProdDistributed_PassesWithValidConfig(t *testing.T) {
	cfg := &Config{
		ListenAddr: ":8080",
		Profile:    "prod-distributed",
		TLS:        &TLSConfig{CertFile: "cert.pem", KeyFile: "key.pem"},
		KMS: &KMSConfig{
			Provider: "yandexapi",
			Yandex:   &YandexKMSConfig{AuthMode: "metadata"},
		},
		Coordinator: CoordinatorConfig{
			Enabled: true,
			Address: "coord:9090",
			CAFile:  "/path/to/ca.pem",
		},
		Paths: map[string]PathConfig{
			"/test": {"get": RouteConfig{
				Backend: BackendConfig{TargetURL: "https://api.example.com"},
				Security: SecurityConfigs{
					{TokenRef: "tok", KMSKeyID: "key-1", InjectHeader: "Authorization"},
				},
			}},
		},
	}
	err := cfg.Validate()
	if err != nil {
		t.Fatalf("Validate() should pass for valid prod-distributed config: %v", err)
	}
}

// ==========================================================================
// ValidateResolvedKMSProvider tests (audit follow-up §1)
// ==========================================================================

func TestValidateResolvedKMSProvider_NoProfile(t *testing.T) {
	cfg := &Config{
		ListenAddr: ":8080",
		Paths: map[string]PathConfig{
			"/test": {"get": RouteConfig{
				Backend: BackendConfig{TargetURL: "https://api.example.com"},
				Security: SecurityConfigs{
					{TokenRef: "tok", KMSKeyID: "key-1", InjectHeader: "Authorization"},
				},
			}},
		},
	}
	// No profile — local should be fine
	if err := cfg.ValidateResolvedKMSProvider("local"); err != nil {
		t.Fatalf("should pass with no profile: %v", err)
	}
}

func TestValidateResolvedKMSProvider_DevLocal_AllowsLocal(t *testing.T) {
	cfg := &Config{
		ListenAddr: ":8080",
		Profile:    "dev-local",
		Paths: map[string]PathConfig{
			"/test": {"get": RouteConfig{
				Backend: BackendConfig{TargetURL: "https://api.example.com"},
				Security: SecurityConfigs{
					{TokenRef: "tok", KMSKeyID: "key-1", InjectHeader: "Authorization"},
				},
			}},
		},
	}
	if err := cfg.ValidateResolvedKMSProvider("local"); err != nil {
		t.Fatalf("should pass for dev-local with local KMS: %v", err)
	}
}

func TestValidateResolvedKMSProvider_ProdSingle_RejectsLocal(t *testing.T) {
	cfg := &Config{
		ListenAddr: ":8080",
		Profile:    "prod-single",
		TLS:        &TLSConfig{CertFile: "cert.pem", KeyFile: "key.pem"},
		Paths: map[string]PathConfig{
			"/test": {"get": RouteConfig{
				Backend: BackendConfig{TargetURL: "https://api.example.com"},
				Security: SecurityConfigs{
					{TokenRef: "tok", KMSKeyID: "key-1", InjectHeader: "Authorization"},
				},
			}},
		},
	}
	err := cfg.ValidateResolvedKMSProvider("local")
	if err == nil {
		t.Fatal("should fail for prod-single with resolved local KMS and secure routes")
	}
	if !containsStr(err.Error(), "local") {
		t.Errorf("error should mention local, got: %v", err)
	}
}

func TestValidateResolvedKMSProvider_ProdSingle_AllowsYandex(t *testing.T) {
	cfg := &Config{
		ListenAddr: ":8080",
		Profile:    "prod-single",
		TLS:        &TLSConfig{CertFile: "cert.pem", KeyFile: "key.pem"},
		Paths: map[string]PathConfig{
			"/test": {"get": RouteConfig{
				Backend: BackendConfig{TargetURL: "https://api.example.com"},
				Security: SecurityConfigs{
					{TokenRef: "tok", KMSKeyID: "key-1", InjectHeader: "Authorization"},
				},
			}},
		},
	}
	if err := cfg.ValidateResolvedKMSProvider("yandexapi"); err != nil {
		t.Fatalf("should pass for prod-single with yandexapi: %v", err)
	}
}

func TestValidateResolvedKMSProvider_ProdSingle_LocalOK_NoSecureRoutes(t *testing.T) {
	cfg := &Config{
		ListenAddr: ":8080",
		Profile:    "prod-single",
		TLS:        &TLSConfig{CertFile: "cert.pem", KeyFile: "key.pem"},
		Paths: map[string]PathConfig{
			"/test": {"get": RouteConfig{Backend: BackendConfig{TargetURL: "http://localhost"}}},
		},
	}
	// local KMS is only rejected when there are secure routes
	if err := cfg.ValidateResolvedKMSProvider("local"); err != nil {
		t.Fatalf("should pass when no secure routes exist: %v", err)
	}
}

func TestValidateResolvedKMSProvider_ProdDistributed_RejectsLocal(t *testing.T) {
	cfg := &Config{
		ListenAddr: ":8080",
		Profile:    "prod-distributed",
		TLS:        &TLSConfig{CertFile: "cert.pem", KeyFile: "key.pem"},
		Coordinator: CoordinatorConfig{
			Enabled: true,
			Address: "coord:9090",
			CAFile:  "/path/to/ca.pem",
		},
		Paths: map[string]PathConfig{
			"/test": {"get": RouteConfig{
				Backend: BackendConfig{TargetURL: "https://api.example.com"},
				Security: SecurityConfigs{
					{TokenRef: "tok", KMSKeyID: "key-1", InjectHeader: "Authorization"},
				},
			}},
		},
	}
	err := cfg.ValidateResolvedKMSProvider("local")
	if err == nil {
		t.Fatal("should fail for prod-distributed with resolved local KMS and secure routes")
	}
}
