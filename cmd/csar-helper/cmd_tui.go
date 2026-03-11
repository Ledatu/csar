package main

import (
	"context"
	"fmt"
	"log/slog"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/ledatu/csar/internal/config"
	"github.com/ledatu/csar/internal/ctxprofile"
	"github.com/ledatu/csar/internal/grpcclient"
	"github.com/ledatu/csar/internal/tui"
	"github.com/spf13/cobra"
)

var (
	tuiConfigPath string
	tuiContext    string // optional context name override
)

var tuiCmd = &cobra.Command{
	Use:   "tui",
	Short: "Interactive route editor (Bubble Tea TUI)",
	Long: `Launches a full-screen terminal UI for browsing and editing CSAR routes.

Features:
  • Fuzzy-filterable route list with method badges
  • Inline route editing (target URL, rate limits, middleware)
  • Add new routes with 'a' key
  • Ctrl+S to save config changes (+ notify coordinator if connected)
  • Middleware pipeline overview for each route

The TUI automatically reads the active context from ~/.csar/contexts.yaml
to connect to the coordinator. Override with --context or --config.`,
	Example: `  csar-helper tui --config config.yaml
  csar-helper tui --context prod`,
	RunE: func(cmd *cobra.Command, args []string) error {
		// Resolve config path — try context profile first
		cfgPath := tuiConfigPath
		var ctxConn *ctxprofile.Context

		if tuiContext != "" || cfgPath == "config.yaml" {
			// Try loading context profile
			store, err := ctxprofile.Load(ctxprofile.DefaultStorePath())
			if err == nil {
				name := tuiContext
				if name == "" {
					name = store.CurrentContext
				}
				if ctx := store.GetContext(name); ctx != nil {
					ctxConn = ctx
					if ctx.ConfigPath != "" && cfgPath == "config.yaml" {
						cfgPath = ctx.ConfigPath
					}
				}
			}
		}

		cfg, err := config.Load(cfgPath)
		if err != nil {
			return fmt.Errorf("loading config: %w", err)
		}

		var opts []tui.AppOption

		// Determine coordinator connection — from context profile or config
		coordAddress := cfg.Coordinator.Address
		coordCAFile := cfg.Coordinator.CAFile
		coordCertFile := cfg.Coordinator.CertFile
		coordKeyFile := cfg.Coordinator.KeyFile
		coordInsecure := cfg.Coordinator.AllowInsecure
		coordEnabled := cfg.Coordinator.Enabled

		// Context profile overrides
		if ctxConn != nil {
			if ctxConn.Address != "" {
				coordAddress = ctxConn.Address
				coordEnabled = true
			}
			if ctxConn.CAFile != "" {
				coordCAFile = ctxConn.CAFile
			}
			if ctxConn.CertFile != "" {
				coordCertFile = ctxConn.CertFile
			}
			if ctxConn.KeyFile != "" {
				coordKeyFile = ctxConn.KeyFile
			}
			if ctxConn.Insecure {
				coordInsecure = true
			}
		}

		if coordEnabled && coordAddress != "" {
			client, connErr := grpcclient.Connect(grpcclient.ConnectOptions{
				Address:  coordAddress,
				CAFile:   coordCAFile,
				CertFile: coordCertFile,
				KeyFile:  coordKeyFile,
				Insecure: coordInsecure,
				Logger:   slog.Default(),
			})

			if connErr != nil {
				// Non-fatal: warn and continue in local-only mode
				slog.Warn("could not connect to coordinator — running in local-only mode",
					"address", coordAddress,
					"error", connErr,
				)
			} else {
				defer client.Close()

				opts = append(opts, tui.WithPushFn(func(c *config.Config) error {
					return client.ReportHealth(context.Background(), "csar-helper-tui", true)
				}))
			}
		}

		app := tui.NewApp(cfg, cfgPath, opts...)
		p := tea.NewProgram(app, tea.WithAltScreen())
		_, err = p.Run()
		return err
	},
}

func init() {
	tuiCmd.Flags().StringVar(&tuiConfigPath, "config", "config.yaml", "path to CSAR config file")
	tuiCmd.Flags().StringVar(&tuiContext, "context", "", "context profile name (overrides config coordinator settings)")
	rootCmd.AddCommand(tuiCmd)
}
