package main

import (
	"fmt"

	"github.com/ledatu/csar/internal/config"
	"github.com/spf13/cobra"
)

var compileConfigPath string

var compileCmd = &cobra.Command{
	Use:   "compile",
	Short: "Flatten a config and its includes for S3, HTTP or manifest sources",
	Long: `Validates the configuration, merges every include and resolves named policies
into a single YAML document for the router's remote config sources.

${VAR} references are kept as written, so each router expands them from its
own environment at load time. Secret fields keep their source text too, so
reference them as ${VAR} rather than writing values into the config.

Use inspect to see the config as this machine's environment resolves it.`,
	Example: `  csar-helper compile --config config.yaml > compiled/router.yaml`,
	RunE: func(cmd *cobra.Command, args []string) error {
		data, err := config.Compile(compileConfigPath)
		if err != nil {
			return fmt.Errorf("compiling config: %w", err)
		}
		_, err = cmd.OutOrStdout().Write(data)
		return err
	},
}

func init() {
	compileCmd.Flags().StringVar(&compileConfigPath, "config", "config.yaml", "path to config file")
	rootCmd.AddCommand(compileCmd)
}
