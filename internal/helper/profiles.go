package helper

import (
	"embed"
	"fmt"
	"os"
	"path/filepath"
)

//go:embed templates/*
var templateFS embed.FS

// Profile represents a deployment profile.
type Profile string

const (
	ProfileDevLocal        Profile = "dev-local"
	ProfileProdSingle      Profile = "prod-single"
	ProfileProdDistributed Profile = "prod-distributed"
)

// ValidProfiles returns all valid profile names.
func ValidProfiles() []Profile {
	return []Profile{ProfileDevLocal, ProfileProdSingle, ProfileProdDistributed}
}

// IsValidProfile checks if a profile name is valid.
func IsValidProfile(name string) bool {
	for _, p := range ValidProfiles() {
		if string(p) == name {
			return true
		}
	}
	return false
}

// InitProfile generates config scaffolding for the given profile.
// It writes files to the specified output directory.
// If force is false and a destination file already exists, InitProfile returns
// an error instead of silently overwriting.
func InitProfile(profile Profile, outputDir string, force bool) error {
	if !IsValidProfile(string(profile)) {
		return fmt.Errorf("unknown profile %q; valid profiles: dev-local, prod-single, prod-distributed", profile)
	}

	// Map profile -> template files
	templates := profileTemplates(profile)

	for srcPath, dstName := range templates {
		data, err := templateFS.ReadFile(srcPath)
		if err != nil {
			return fmt.Errorf("reading embedded template %q: %w", srcPath, err)
		}

		dstPath := filepath.Join(outputDir, dstName)

		// Guard against silent overwrite unless --force is given.
		if !force {
			if _, statErr := os.Stat(dstPath); statErr == nil {
				return fmt.Errorf("file %q already exists; use --force to overwrite", dstPath)
			}
		}

		if err := os.MkdirAll(filepath.Dir(dstPath), 0o755); err != nil {
			return fmt.Errorf("creating directory for %q: %w", dstPath, err)
		}

		if err := os.WriteFile(dstPath, data, 0o644); err != nil { //nolint:gosec // G306: template file is intentionally world-readable
			return fmt.Errorf("writing %q: %w", dstPath, err)
		}
		fmt.Printf("  created: %s\n", dstPath)
	}

	return nil
}

// profileTemplates returns the mapping of embedded template path -> output filename
// for a given profile.
func profileTemplates(profile Profile) map[string]string {
	switch profile {
	case ProfileDevLocal:
		return map[string]string{
			"templates/dev-local/config.yaml": "config.yaml",
			"templates/dev-local/env.example": ".env.example",
		}
	case ProfileProdSingle:
		return map[string]string{
			"templates/prod-single/config.yaml": "config.yaml",
			"templates/prod-single/env.example": ".env.example",
		}
	case ProfileProdDistributed:
		return map[string]string{
			"templates/prod-distributed/config.yaml":         "config.yaml",
			"templates/prod-distributed/env.example":         ".env.example",
			"templates/prod-distributed/docker-compose.yaml": "docker-compose.yaml",
		}
	default:
		return nil
	}
}

// ProfileValidationRules returns validation rules for a profile.
type ProfileRule struct {
	Name  string
	Check func(cfg ProfileCheckInput) error
}

// ProfileCheckInput contains the config fields needed for profile validation.
type ProfileCheckInput struct {
	Profile             string
	CoordinatorEnabled  bool
	CoordinatorAddress  string
	CoordinatorCAFile   string
	CoordinatorInsecure bool
	HasSecureRoutes     bool
	TLSEnabled          bool
	KMSProvider         string
	SecurityEnvironment string
}

// GetProfileRules returns the validation rules for the given profile.
func GetProfileRules(profile string) []ProfileRule {
	switch Profile(profile) {
	case ProfileProdSingle:
		return prodSingleRules()
	case ProfileProdDistributed:
		return prodDistributedRules()
	default:
		return nil // dev-local has no restrictions
	}
}

func prodSingleRules() []ProfileRule {
	return []ProfileRule{
		{
			Name: "reject-insecure-coordinator",
			Check: func(cfg ProfileCheckInput) error {
				if cfg.CoordinatorInsecure {
					return fmt.Errorf("profile %q rejects coordinator.allow_insecure: true", cfg.Profile)
				}
				return nil
			},
		},
		{
			Name: "reject-dev-environment",
			Check: func(cfg ProfileCheckInput) error {
				if cfg.SecurityEnvironment == "dev" {
					return fmt.Errorf("profile %q rejects security_policy.environment: \"dev\"", cfg.Profile)
				}
				return nil
			},
		},
		{
			Name: "require-tls-for-secure-routes",
			Check: func(cfg ProfileCheckInput) error {
				if cfg.HasSecureRoutes && !cfg.TLSEnabled {
					return fmt.Errorf("profile %q requires TLS when secure routes are configured", cfg.Profile)
				}
				return nil
			},
		},
		{
			Name: "reject-local-kms-in-prod",
			Check: func(cfg ProfileCheckInput) error {
				if cfg.HasSecureRoutes && cfg.KMSProvider == "local" {
					return fmt.Errorf("profile %q rejects kms.provider: \"local\" when secure routes exist; use a cloud KMS", cfg.Profile)
				}
				return nil
			},
		},
	}
}

func prodDistributedRules() []ProfileRule {
	rules := prodSingleRules()
	rules = append(rules,
		ProfileRule{
			Name: "require-coordinator-enabled",
			Check: func(cfg ProfileCheckInput) error {
				if !cfg.CoordinatorEnabled || cfg.CoordinatorAddress == "" {
					return fmt.Errorf("profile %q requires coordinator.enabled: true with a non-empty address", cfg.Profile)
				}
				return nil
			},
		},
		ProfileRule{
			Name: "require-coordinator-tls",
			Check: func(cfg ProfileCheckInput) error {
				if cfg.CoordinatorEnabled && cfg.CoordinatorCAFile == "" {
					return fmt.Errorf("profile %q requires coordinator.ca_file for TLS", cfg.Profile)
				}
				return nil
			},
		},
	)
	return rules
}

// ValidateProfile runs all profile rules against the given config input.
// Returns a list of violations (empty = valid).
func ValidateProfile(input ProfileCheckInput) []error {
	rules := GetProfileRules(input.Profile)
	var violations []error
	for _, rule := range rules {
		if err := rule.Check(input); err != nil {
			violations = append(violations, err)
		}
	}
	return violations
}
