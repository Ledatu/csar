package tui

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/charmbracelet/huh"
	"github.com/charmbracelet/lipgloss"
	"github.com/ledatu/csar/internal/helper"
)

// WizardResult contains the answers from the interactive init wizard.
type WizardResult struct {
	ProjectName    string
	Profile        string
	RateLimitStore string
	JWTEnabled     bool
	OutputDir      string
}

// RunWizard runs the interactive init wizard using huh forms.
// Returns the user's selections or an error if cancelled.
func RunWizard() (*WizardResult, error) {
	result := &WizardResult{
		OutputDir: ".",
	}

	// Detect current directory name as default project name
	cwd, _ := os.Getwd()
	defaultName := filepath.Base(cwd)

	form := huh.NewForm(
		huh.NewGroup(
			huh.NewNote().
				Title("  CSAR Setup Wizard").
				Description("Let's configure your API gateway.\nAnswer a few questions to generate a ready-to-use configuration."),

			huh.NewInput().
				Title("Project name").
				Description("Used for logging and identification").
				Value(&result.ProjectName).
				Placeholder(defaultName).
				Validate(func(s string) error {
					if strings.TrimSpace(s) == "" {
						result.ProjectName = defaultName
					}
					return nil
				}),

			huh.NewSelect[string]().
				Title("Deployment profile").
				Description("Determines security and infrastructure constraints").
				Options(
					huh.NewOption("Dev Local — no TLS, no coordinator, relaxed security", "dev-local"),
					huh.NewOption("Prod Single — single node, TLS required", "prod-single"),
					huh.NewOption("Prod Distributed — multi-node with coordinator", "prod-distributed"),
				).
				Value(&result.Profile),
		),

		huh.NewGroup(
			huh.NewSelect[string]().
				Title("Rate limiting backend").
				Description("Where to store rate limit counters").
				Options(
					huh.NewOption("Local — in-memory per pod (simplest)", "local"),
					huh.NewOption("Redis — distributed across all pods", "redis"),
					huh.NewOption("Coordinator — dynamic quota allocation", "coordinator"),
				).
				Value(&result.RateLimitStore),

			huh.NewConfirm().
				Title("Enable JWT authentication?").
				Description("Validate inbound Bearer tokens against a JWKS endpoint").
				Value(&result.JWTEnabled),

			huh.NewInput().
				Title("Output directory").
				Description("Where to generate configuration files").
				Value(&result.OutputDir).
				Placeholder("."),
		),
	).WithTheme(huh.ThemeCatppuccin())

	err := form.Run()
	if err != nil {
		return nil, err
	}

	// Default empty values
	if result.ProjectName == "" {
		result.ProjectName = defaultName
	}
	if result.OutputDir == "" {
		result.OutputDir = "."
	}

	return result, nil
}

// ApplyWizardResult generates configuration files from wizard results.
func ApplyWizardResult(result *WizardResult, force bool) error {
	// Generate the profile template
	if err := helper.InitProfile(helper.Profile(result.Profile), result.OutputDir, force); err != nil {
		return err
	}

	// Print summary
	fmt.Println()
	box := lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(ColorSuccess).
		Padding(1, 2).
		Width(60)

	title := SuccessStyle.Render(fmt.Sprintf("%s Configuration generated!", IconCheck))

	lines := []string{
		title,
		"",
		LabelStyle.Render("Project:") + "  " + ValueStyle.Render(result.ProjectName),
		LabelStyle.Render("Profile:") + "  " + ValueStyle.Render(result.Profile),
		LabelStyle.Render("Rate limits:") + "  " + ValueStyle.Render(result.RateLimitStore),
		LabelStyle.Render("JWT auth:") + "  " + ValueStyle.Render(boolToYesNo(result.JWTEnabled)),
		LabelStyle.Render("Output:") + "  " + ValueStyle.Render(result.OutputDir),
		"",
		DimStyle.Render("Next steps:"),
		DimStyle.Render("  1. Edit config.yaml with your routes"),
		DimStyle.Render("  2. Run: csar-helper validate --config config.yaml"),
		DimStyle.Render("  3. Start: csar --config config.yaml"),
	}

	fmt.Println(box.Render(strings.Join(lines, "\n")))
	return nil
}

func boolToYesNo(b bool) string {
	if b {
		return SuccessStyle.Render("yes")
	}
	return DimStyle.Render("no")
}
