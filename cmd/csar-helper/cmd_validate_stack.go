package main

import (
	"fmt"

	"github.com/ledatu/csar/internal/helper"
	"github.com/ledatu/csar/internal/tui"
	"github.com/spf13/cobra"
)

var validateStackDir string

var validateStackCmd = &cobra.Command{
	Use:   "validate-stack",
	Short: "Pre-flight check for a CSAR deployment stack",
	Long: `Runs pre-flight checks on a deployment stack directory. 
Unlike 'validate' which checks config.yaml syntax, 'validate-stack' checks if:

  • Required files exist (config.yaml, .env, docker-compose.yaml)
  • Volume mount host paths exist on disk  
  • Required environment variables are set in .env
  • TLS certificates are present when referenced
  • Database connection strings are syntactically valid`,
	Example: `  # Check the current directory
  csar-helper validate-stack

  # Check a specific directory
  csar-helper validate-stack --dir ./config`,
	RunE: func(cmd *cobra.Command, args []string) error {
		result := helper.ValidateStack(validateStackDir)
		tui.RenderStackValidation(result)

		if result.HasError {
			return fmt.Errorf("stack validation failed with error(s)")
		}
		return nil
	},
}

func init() {
	validateStackCmd.Flags().StringVar(&validateStackDir, "dir", ".", "directory containing the deployment stack")
	rootCmd.AddCommand(validateStackCmd)
}
