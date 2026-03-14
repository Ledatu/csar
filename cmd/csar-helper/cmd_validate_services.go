package main

import (
	"fmt"
	"os"

	"github.com/ledatu/csar-core/authnconfig"
	"github.com/ledatu/csar-core/authzconfig"
	"github.com/spf13/cobra"
)

var validateAuthnPath string

var validateAuthnCmd = &cobra.Command{
	Use:   "validate-authn",
	Short: "Validate a csar-authn config file",
	Long:  `Loads a csar-authn configuration file, expands environment variables, applies defaults, and validates all fields.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		data, err := os.ReadFile(validateAuthnPath)
		if err != nil {
			return fmt.Errorf("reading config: %w", err)
		}
		if _, err := authnconfig.LoadFromBytes(data); err != nil {
			return fmt.Errorf("authn config validation failed: %w", err)
		}
		fmt.Println("OK: authn config is valid")
		return nil
	},
}

var validateAuthzPath string

var validateAuthzCmd = &cobra.Command{
	Use:   "validate-authz",
	Short: "Validate a csar-authz config file",
	Long:  `Loads a csar-authz configuration file, expands environment variables, applies defaults, and validates all fields.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		data, err := os.ReadFile(validateAuthzPath)
		if err != nil {
			return fmt.Errorf("reading config: %w", err)
		}
		if _, err := authzconfig.LoadFromBytes(data); err != nil {
			return fmt.Errorf("authz config validation failed: %w", err)
		}
		fmt.Println("OK: authz config is valid")
		return nil
	},
}

func init() {
	validateAuthnCmd.Flags().StringVar(&validateAuthnPath, "config", "config.yaml", "path to csar-authn config file")
	validateAuthzCmd.Flags().StringVar(&validateAuthzPath, "config", "config.yaml", "path to csar-authz config file")

	rootCmd.AddCommand(validateAuthnCmd, validateAuthzCmd)
}
