package main

import (
	"fmt"
	"os"

	"github.com/ledatu/csar/internal/clientgen"
	"github.com/ledatu/csar/internal/config"
	"github.com/spf13/cobra"
)

var (
	clientGenConfigPath string
	clientGenOutput     string
	clientGenClassName  string
	clientGenBaseURL    string
	clientGenAxios      bool
)

var clientGenCmd = &cobra.Command{
	Use:   "client-gen",
	Short: "Generate a TypeScript API client from CSAR config",
	Long: `Generates a typed TypeScript API client from your CSAR configuration.

The generated client includes:
  • A typed method for every route in your config
  • Automatic X-CSAR-Wait-MS header injection for throttle awareness
  • Support for both Fetch API and Axios backends
  • Path parameter substitution for dynamic routes
  • Route constants with RPS and max-wait metadata`,
	Example: `  # Generate a Fetch-based client
  csar-helper client-gen --config config.yaml --output ./src/csar-client.ts

  # Generate an Axios-based client
  csar-helper client-gen --config config.yaml --output ./src/api.ts --axios

  # Print to stdout
  csar-helper client-gen --config config.yaml`,
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg, err := config.Load(clientGenConfigPath)
		if err != nil {
			return fmt.Errorf("loading config: %w", err)
		}

		code, err := clientgen.Generate(cfg, clientgen.Options{
			BaseURL:   clientGenBaseURL,
			ClassName: clientGenClassName,
			UseAxios:  clientGenAxios,
		})
		if err != nil {
			return fmt.Errorf("generating client: %w", err)
		}

		if clientGenOutput != "" {
			if err := os.WriteFile(clientGenOutput, []byte(code), 0o644); err != nil { //nolint:gosec // G306: generated client file is intentionally world-readable
				return fmt.Errorf("writing output: %w", err)
			}
			fmt.Printf("TypeScript client written to %s\n", clientGenOutput)
			return nil
		}

		fmt.Print(code)
		return nil
	},
}

func init() {
	clientGenCmd.Flags().StringVar(&clientGenConfigPath, "config", "config.yaml", "path to CSAR config file")
	clientGenCmd.Flags().StringVar(&clientGenOutput, "output", "", "output file path (default: stdout)")
	clientGenCmd.Flags().StringVar(&clientGenClassName, "class-name", "CsarClient", "TypeScript class name")
	clientGenCmd.Flags().StringVar(&clientGenBaseURL, "base-url", "", "base URL for the client (auto-detected from config if empty)")
	clientGenCmd.Flags().BoolVar(&clientGenAxios, "axios", false, "generate Axios-based client instead of Fetch")

	rootCmd.AddCommand(clientGenCmd)
}
