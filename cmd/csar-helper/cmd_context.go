package main

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/lipgloss"
	"github.com/ledatu/csar/internal/ctxprofile"
	"github.com/ledatu/csar/internal/tui"
	"github.com/spf13/cobra"
)

// ─── Parent command ─────────────────────────────────────────────────────────────

var contextCmd = &cobra.Command{
	Use:     "context",
	Aliases: []string{"ctx"},
	Short:   "Manage coordinator connection contexts (like kubectl contexts)",
	Long: `Manage named contexts for connecting to CSAR coordinator instances.
Each context stores an address, TLS certificates, and a default config path.

Contexts are stored in ~/.csar/contexts.yaml.`,
}

// ─── set-context ────────────────────────────────────────────────────────────────

var (
	setCtxName     string
	setCtxAddress  string
	setCtxCAFile   string
	setCtxCertFile string
	setCtxKeyFile  string
	setCtxInsecure bool
	setCtxConfig   string
)

var setContextCmd = &cobra.Command{
	Use:   "set-context",
	Short: "Create or update a named context",
	Example: `  # Create a production context
  csar-helper context set-context --name prod \
    --address coordinator.prod.example.com:9090 \
    --ca-file /etc/csar/tls/ca.pem \
    --cert-file /etc/csar/tls/client-cert.pem \
    --key-file /etc/csar/tls/client-key.pem

  # Create a dev context (insecure)
  csar-helper context set-context --name dev \
    --address localhost:9090 --insecure`,
	RunE: func(cmd *cobra.Command, args []string) error {
		if setCtxName == "" {
			return fmt.Errorf("--name is required")
		}
		if setCtxAddress == "" {
			return fmt.Errorf("--address is required")
		}

		storePath := ctxprofile.DefaultStorePath()
		store, err := ctxprofile.Load(storePath)
		if err != nil {
			return err
		}

		ctx := ctxprofile.Context{
			Name:       setCtxName,
			Address:    setCtxAddress,
			CAFile:     setCtxCAFile,
			CertFile:   setCtxCertFile,
			KeyFile:    setCtxKeyFile,
			Insecure:   setCtxInsecure,
			ConfigPath: setCtxConfig,
		}

		store.SetContext(ctx)

		// If this is the first context, auto-set it as current
		if store.CurrentContext == "" {
			store.CurrentContext = setCtxName
		}

		if err := store.Save(storePath); err != nil {
			return err
		}

		fmt.Printf("  %s Context %q saved.\n", tui.IconCheck, setCtxName)
		if store.CurrentContext == setCtxName {
			fmt.Printf("  %s Active context: %s\n", tui.IconArrow, setCtxName)
		}
		return nil
	},
}

// ─── use-context ────────────────────────────────────────────────────────────────

var useCtxName string

var useContextCmd = &cobra.Command{
	Use:     "use-context",
	Short:   "Switch the active context",
	Example: `  csar-helper context use-context --name prod`,
	RunE: func(cmd *cobra.Command, args []string) error {
		if useCtxName == "" {
			return fmt.Errorf("--name is required")
		}

		storePath := ctxprofile.DefaultStorePath()
		store, err := ctxprofile.Load(storePath)
		if err != nil {
			return err
		}

		if err := store.UseContext(useCtxName); err != nil {
			return err
		}

		if err := store.Save(storePath); err != nil {
			return err
		}

		fmt.Printf("  %s Switched to context %q\n", tui.IconCheck, useCtxName)
		return nil
	},
}

// ─── get-contexts ───────────────────────────────────────────────────────────────

var getContextsCmd = &cobra.Command{
	Use:     "get-contexts",
	Short:   "List all saved contexts",
	Example: `  csar-helper context get-contexts`,
	RunE: func(cmd *cobra.Command, args []string) error {
		storePath := ctxprofile.DefaultStorePath()
		store, err := ctxprofile.Load(storePath)
		if err != nil {
			return err
		}

		if len(store.Contexts) == 0 {
			fmt.Println("  No contexts configured. Use: csar-helper context set-context --name <name> --address <addr>")
			return nil
		}

		fmt.Println()
		headerStyle := lipgloss.NewStyle().Bold(true).Foreground(tui.ColorPrimary)
		fmt.Println(headerStyle.Render("  CSAR Contexts"))
		fmt.Println()

		for _, ctx := range store.Contexts {
			marker := "  "
			if ctx.Name == store.CurrentContext {
				marker = lipgloss.NewStyle().Foreground(tui.ColorSuccess).Bold(true).Render("▸ ")
			}

			nameStyle := lipgloss.NewStyle().Bold(true).Foreground(tui.ColorText).Width(20)
			addrStyle := lipgloss.NewStyle().Foreground(tui.ColorDim)

			var flags []string
			if ctx.Insecure {
				flags = append(flags, lipgloss.NewStyle().Foreground(tui.ColorWarning).Render("insecure"))
			}
			if ctx.CAFile != "" {
				flags = append(flags, lipgloss.NewStyle().Foreground(tui.ColorSuccess).Render("TLS"))
			}
			if ctx.CertFile != "" {
				flags = append(flags, lipgloss.NewStyle().Foreground(tui.ColorSuccess).Render("mTLS"))
			}

			flagStr := ""
			if len(flags) > 0 {
				flagStr = "  [" + strings.Join(flags, ", ") + "]"
			}

			fmt.Printf("  %s%s  %s%s\n", marker, nameStyle.Render(ctx.Name), addrStyle.Render(ctx.Address), flagStr)
		}

		fmt.Println()
		return nil
	},
}

// ─── delete-context ─────────────────────────────────────────────────────────────

var deleteCtxName string

var deleteContextCmd = &cobra.Command{
	Use:     "delete-context",
	Short:   "Delete a saved context",
	Example: `  csar-helper context delete-context --name dev`,
	RunE: func(cmd *cobra.Command, args []string) error {
		if deleteCtxName == "" {
			return fmt.Errorf("--name is required")
		}

		storePath := ctxprofile.DefaultStorePath()
		store, err := ctxprofile.Load(storePath)
		if err != nil {
			return err
		}

		if !store.DeleteContext(deleteCtxName) {
			return fmt.Errorf("context %q not found", deleteCtxName)
		}

		if err := store.Save(storePath); err != nil {
			return err
		}

		fmt.Printf("  %s Context %q deleted.\n", tui.IconCheck, deleteCtxName)
		return nil
	},
}

// ─── init ───────────────────────────────────────────────────────────────────────

func init() {
	// set-context flags
	setContextCmd.Flags().StringVar(&setCtxName, "name", "", "context name (required)")
	setContextCmd.Flags().StringVar(&setCtxAddress, "address", "", "coordinator gRPC address (required)")
	setContextCmd.Flags().StringVar(&setCtxCAFile, "ca-file", "", "CA certificate for TLS")
	setContextCmd.Flags().StringVar(&setCtxCertFile, "cert-file", "", "client certificate for mTLS")
	setContextCmd.Flags().StringVar(&setCtxKeyFile, "key-file", "", "client private key for mTLS")
	setContextCmd.Flags().BoolVar(&setCtxInsecure, "insecure", false, "allow plaintext gRPC")
	setContextCmd.Flags().StringVar(&setCtxConfig, "config", "", "default config.yaml path for this context")

	// use-context flags
	useContextCmd.Flags().StringVar(&useCtxName, "name", "", "context name to switch to (required)")

	// delete-context flags
	deleteContextCmd.Flags().StringVar(&deleteCtxName, "name", "", "context name to delete (required)")

	// Wire subcommands
	contextCmd.AddCommand(setContextCmd, useContextCmd, getContextsCmd, deleteContextCmd)
	rootCmd.AddCommand(contextCmd)
}
