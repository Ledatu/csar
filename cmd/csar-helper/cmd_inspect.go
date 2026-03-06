package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/ledatu/csar/internal/config"
	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"
)

var (
	inspectConfigPath string
	inspectRoute      string
	inspectFormat     string
)

var inspectCmd = &cobra.Command{
	Use:   "inspect",
	Short: "Show the resolved config after all includes and policy merges",
	Long: `Loads the configuration through the full include/merge/resolve pipeline
and outputs the final resolved config that the router would apply at runtime.

Optionally filter to a single route with --route "METHOD /path".`,
	Example: `  # Show full resolved config
  csar-helper inspect --config config.yaml

  # Show a single route
  csar-helper inspect --config config.yaml --route "GET /api/v1/users"

  # JSON output
  csar-helper inspect --config config.yaml --format json`,
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg, err := config.Load(inspectConfigPath)
		if err != nil {
			return fmt.Errorf("loading config: %w", err)
		}

		// If --route is specified, filter to that route.
		if inspectRoute != "" {
			return inspectSingleRoute(cfg, inspectRoute)
		}

		// Output the full resolved config.
		return outputConfig(cfg)
	},
}

func inspectSingleRoute(cfg *config.Config, routeSpec string) error {
	parts := strings.SplitN(routeSpec, " ", 2)
	if len(parts) != 2 {
		return fmt.Errorf("--route must be \"METHOD /path\" (e.g. \"GET /api/v1/users\")")
	}
	method := strings.ToLower(strings.TrimSpace(parts[0]))
	path := strings.TrimSpace(parts[1])

	methods, ok := cfg.Paths[path]
	if !ok {
		return fmt.Errorf("path %q not found in config", path)
	}
	route, ok := methods[method]
	if !ok {
		return fmt.Errorf("method %q not found for path %q", strings.ToUpper(method), path)
	}

	// Build an annotated output map.
	output := routeToAnnotatedMap(route)

	switch inspectFormat {
	case "json":
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(output)
	default:
		data, err := yaml.Marshal(output)
		if err != nil {
			return err
		}
		// Print YAML with source annotations as comments.
		lines := strings.Split(string(data), "\n")
		for _, line := range lines {
			if line == "" {
				continue
			}
			fmt.Println(line)
		}

		// Print source annotations separately if available.
		if len(route.SourceInfo) > 0 {
			fmt.Println("\n# Source tracing:")
			for field, meta := range route.SourceInfo {
				comment := fmt.Sprintf("#   %s: %s:%d", field, meta.File, meta.Line)
				if meta.Policy != "" {
					comment += fmt.Sprintf(" (policy: %s)", meta.Policy)
				}
				fmt.Println(comment)
			}
		}
		return nil
	}
}

func routeToAnnotatedMap(route config.RouteConfig) map[string]interface{} {
	// Marshal to YAML and back to get a clean map representation.
	data, err := yaml.Marshal(route)
	if err != nil {
		return nil
	}
	var m map[string]interface{}
	yaml.Unmarshal(data, &m)
	return m
}

func outputConfig(cfg *config.Config) error {
	switch inspectFormat {
	case "json":
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(cfg)
	default:
		data, err := yaml.Marshal(cfg)
		if err != nil {
			return err
		}
		fmt.Print(string(data))
		return nil
	}
}

func init() {
	inspectCmd.Flags().StringVar(&inspectConfigPath, "config", "config.yaml", "path to config file")
	inspectCmd.Flags().StringVar(&inspectRoute, "route", "", "filter to a single route: \"METHOD /path\"")
	inspectCmd.Flags().StringVar(&inspectFormat, "format", "yaml", "output format: yaml or json")

	rootCmd.AddCommand(inspectCmd)
}
