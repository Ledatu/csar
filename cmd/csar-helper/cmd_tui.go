package main

import (
	"context"
	"fmt"
	"log/slog"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/ledatu/csar/internal/config"
	"github.com/ledatu/csar/internal/grpcclient"
	"github.com/ledatu/csar/internal/tui"
	"github.com/spf13/cobra"
)

var tuiConfigPath string

var tuiCmd = &cobra.Command{
	Use:   "tui",
	Short: "Interactive route editor (Bubble Tea TUI)",
	Long: `Launches a full-screen terminal UI for browsing and editing CSAR routes.

Features:
  • Fuzzy-filterable route list with method badges
  • Inline route editing (target URL, rate limits, middleware)
  • Ctrl+S to save config changes (+ notify coordinator if connected)
  • Middleware pipeline overview for each route`,
	Example: `  csar-helper tui --config config.yaml`,
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg, err := config.Load(tuiConfigPath)
		if err != nil {
			return fmt.Errorf("loading config: %w", err)
		}

		var opts []tui.AppOption

		// If coordinator is enabled, connect using the config's TLS settings.
		// The coordinator pushes config *to* routers (via Subscribe stream),
		// so the TUI cannot "push config" — it can only save to disk and
		// report health so the coordinator knows a node was updated.
		if cfg.Coordinator.Enabled && cfg.Coordinator.Address != "" {
			client, connErr := grpcclient.Connect(grpcclient.ConnectOptions{
				Address:  cfg.Coordinator.Address,
				CAFile:   cfg.Coordinator.CAFile,
				CertFile: cfg.Coordinator.CertFile,
				KeyFile:  cfg.Coordinator.KeyFile,
				Insecure: cfg.Coordinator.AllowInsecure,
				Logger:   slog.Default(),
			})

			if connErr != nil {
				// Non-fatal: warn and continue in local-only mode
				slog.Warn("could not connect to coordinator — running in local-only mode",
					"address", cfg.Coordinator.Address,
					"error", connErr,
				)
			} else {
				defer client.Close()

				// After saving config to disk, notify the coordinator that
				// this node's config changed so it can re-sync subscribers.
				opts = append(opts, tui.WithPushFn(func(c *config.Config) error {
					return client.ReportHealth(context.Background(), "csar-helper-tui", true)
				}))
			}
		}

		app := tui.NewApp(cfg, tuiConfigPath, opts...)
		p := tea.NewProgram(app, tea.WithAltScreen())
		_, err = p.Run()
		return err
	},
}

func init() {
	tuiCmd.Flags().StringVar(&tuiConfigPath, "config", "config.yaml", "path to CSAR config file")
	rootCmd.AddCommand(tuiCmd)
}
