package main

import (
	"fmt"

	"github.com/ledatu/csar/internal/config"
	"github.com/ledatu/csar/internal/helper"
	"github.com/ledatu/csar/internal/tui"
	"github.com/spf13/cobra"
)

// ─── init ──────────────────────────────────────────────────────────────────────

var (
	initProfile   string
	initOutputDir string
	initForce     bool
	initWizard    bool
)

var initCmd = &cobra.Command{
	Use:   "init",
	Short: "Generate config scaffolding (interactive wizard or flags)",
	Long: `Generates a starter configuration for the specified deployment profile.

When called without --profile, launches an interactive setup wizard.

Available profiles:
  dev-local          Local development (no TLS, no coordinator)
  prod-single        Single-node production
  prod-distributed   Multi-node production with coordinator`,
	Example: `  # Interactive wizard (default)
  csar-helper init

  # Non-interactive
  csar-helper init --profile dev-local --output ./config`,
	RunE: func(cmd *cobra.Command, args []string) error {
		// Interactive wizard if no profile specified
		if initProfile == "" || initWizard {
			result, err := tui.RunWizard()
			if err != nil {
				return fmt.Errorf("wizard cancelled: %w", err)
			}
			return tui.ApplyWizardResult(result, initForce)
		}

		fmt.Printf("Generating %q config scaffolding in %s...\n", initProfile, initOutputDir)
		return helper.InitProfile(helper.Profile(initProfile), initOutputDir, initForce)
	},
}

// ─── validate ──────────────────────────────────────────────────────────────────

var validateConfigPath string

var validateCmd = &cobra.Command{
	Use:   "validate",
	Short: "Validate config against its declared profile",
	Long:  `Loads the configuration file and validates it against the declared profile rules.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg, err := config.Load(validateConfigPath)
		if err != nil {
			return fmt.Errorf("loading config: %w", err)
		}

		// Check profile field
		if cfg.Profile == "" {
			tui.RenderValidationReport("", nil, []string{"No profile declared in config — skipping profile validation"})
			return nil
		}

		if !helper.IsValidProfile(cfg.Profile) {
			return fmt.Errorf("unknown profile %q in config", cfg.Profile)
		}

		// Build check input
		input := helper.ProfileCheckInput{
			Profile:             cfg.Profile,
			CoordinatorEnabled:  cfg.Coordinator.Enabled,
			CoordinatorAddress:  cfg.Coordinator.Address,
			CoordinatorCAFile:   cfg.Coordinator.CAFile,
			CoordinatorInsecure: cfg.Coordinator.AllowInsecure,
			HasSecureRoutes:     cfg.HasSecureRoutes(),
			TLSEnabled:          cfg.TLS != nil,
		}
		if cfg.KMS != nil {
			input.KMSProvider = cfg.KMS.Provider
		}
		if cfg.SecurityPolicy != nil {
			input.SecurityEnvironment = cfg.SecurityPolicy.Environment
		}

		violations := helper.ValidateProfile(input)
		tui.RenderValidationReport(cfg.Profile, violations, cfg.Warnings)

		if len(violations) > 0 {
			return fmt.Errorf("config validation failed with %d error(s)", len(violations))
		}
		return nil
	},
}

func init() {
	// init flags
	initCmd.Flags().StringVar(&initProfile, "profile", "", "deployment profile: dev-local, prod-single, prod-distributed")
	initCmd.Flags().StringVar(&initOutputDir, "output", ".", "output directory for generated files")
	initCmd.Flags().BoolVar(&initForce, "force", false, "overwrite existing files")
	initCmd.Flags().BoolVar(&initWizard, "wizard", false, "force interactive wizard mode")

	// validate flags
	validateCmd.Flags().StringVar(&validateConfigPath, "config", "config.yaml", "path to config file")

	rootCmd.AddCommand(initCmd, validateCmd)
}
