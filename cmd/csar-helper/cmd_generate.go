package main

import (
	"fmt"

	"github.com/ledatu/csar/internal/tui"
	"github.com/spf13/cobra"
)

var generateForce bool

var generateCmd = &cobra.Command{
	Use:   "generate",
	Short: "Interactive config + docker-compose generator",
	Long: `Launches an interactive TUI wizard that walks you through configuring
the CSAR API gateway and generates:

  • config.yaml     — Full router configuration with routes, TLS, rate limits, etc.
  • .env.example    — Environment variable template
  • docker-compose.yaml — (optional) Docker Compose for the full stack

The wizard asks questions about your deployment, routes, middleware,
and infrastructure, then produces ready-to-use files.`,
	Aliases: []string{"gen"},
	Example: `  # Interactive generator
  csar-helper generate

  # Overwrite existing files
  csar-helper generate --force`,
	RunE: func(cmd *cobra.Command, args []string) error {
		result, err := tui.RunGenerateWizard()
		if err != nil {
			return fmt.Errorf("generator cancelled: %w", err)
		}

		// Allow --force from CLI flag to override wizard answer
		if generateForce {
			result.Force = true
		}

		return tui.ApplyGenerateResult(result)
	},
}

func init() {
	generateCmd.Flags().BoolVar(&generateForce, "force", false, "overwrite existing files without asking")

	rootCmd.AddCommand(generateCmd)
}
