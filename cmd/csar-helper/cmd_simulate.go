package main

import (
	"fmt"

	"github.com/ledatu/csar/internal/config"
	"github.com/ledatu/csar/internal/simulate"
	"github.com/ledatu/csar/internal/tui"
	"github.com/spf13/cobra"
)

var (
	simConfigPath string
	simPath       string
	simMethod     string
)

var simulateCmd = &cobra.Command{
	Use:   "simulate",
	Short: "Simulate request routing against your config",
	Long: `Runs a local route match against your CSAR configuration and shows
which route matches, what target URL it resolves to, and the complete
middleware pipeline that would be applied.

No real network requests are made.`,
	Aliases: []string{"sim", "check"},
	Example: `  # Simulate a GET request
  csar-helper simulate --config config.yaml --path /api/users --method GET

  # Simulate a POST request
  csar-helper simulate --config config.yaml --path /api/orders --method POST`,
	RunE: func(cmd *cobra.Command, args []string) error {
		if simPath == "" {
			return fmt.Errorf("--path is required")
		}

		cfg, err := config.Load(simConfigPath)
		if err != nil {
			return fmt.Errorf("loading config: %w", err)
		}

		result := simulate.Simulate(cfg, simulate.Request{
			Path:   simPath,
			Method: simMethod,
		})

		tui.RenderSimulationResult(result)
		return nil
	},
}

func init() {
	simulateCmd.Flags().StringVar(&simConfigPath, "config", "config.yaml", "path to CSAR config file")
	simulateCmd.Flags().StringVar(&simPath, "path", "", "request path to simulate (required)")
	simulateCmd.Flags().StringVar(&simMethod, "method", "GET", "HTTP method")

	rootCmd.AddCommand(simulateCmd)
}
