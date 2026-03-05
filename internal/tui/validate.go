package tui

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/lipgloss"
)

// ValidationResult represents a single validation finding.
type ValidationResult struct {
	Level   string // "error", "warning", "info"
	Message string
	Field   string // optional: the config field path
}

// RenderValidationReport renders a pretty validation report to stdout.
func RenderValidationReport(profile string, violations []error, warnings []string) {
	fmt.Println()

	headerStyle := lipgloss.NewStyle().
		Bold(true).
		Foreground(ColorPrimary).
		MarginBottom(1)

	if len(violations) == 0 && len(warnings) == 0 {
		// All good!
		box := lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(ColorSuccess).
			Padding(1, 2).
			Width(60)

		content := SuccessStyle.Render(fmt.Sprintf("%s  Configuration is valid", IconCheck))
		if profile != "" {
			content += "\n" + DimStyle.Render(fmt.Sprintf("   Profile: %s", profile))
		}
		fmt.Println(box.Render(content))
		return
	}

	// Header
	if profile != "" {
		fmt.Println(headerStyle.Render(fmt.Sprintf("  Validation Report — profile: %s", profile)))
	} else {
		fmt.Println(headerStyle.Render("  Validation Report"))
	}

	// Errors
	if len(violations) > 0 {
		errBox := lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(ColorError).
			Padding(0, 2).
			MarginBottom(1).
			Width(70)

		var errLines []string
		errLines = append(errLines, ErrorStyle.Render(fmt.Sprintf("\n  %s  %d error(s)", IconCross, len(violations))))
		errLines = append(errLines, "")
		for _, v := range violations {
			errLines = append(errLines, fmt.Sprintf("  %s %s",
				ErrorStyle.Render(IconDot),
				v.Error(),
			))
		}
		errLines = append(errLines, "")
		fmt.Println(errBox.Render(strings.Join(errLines, "\n")))
	}

	// Warnings
	if len(warnings) > 0 {
		warnBox := lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(ColorWarning).
			Padding(0, 2).
			Width(70)

		var warnLines []string
		warnLines = append(warnLines, WarningStyle.Render(fmt.Sprintf("\n  %s  %d warning(s)", IconWarning, len(warnings))))
		warnLines = append(warnLines, "")
		for _, w := range warnings {
			warnLines = append(warnLines, fmt.Sprintf("  %s %s",
				WarningStyle.Render(IconDot),
				w,
			))
		}
		warnLines = append(warnLines, "")
		fmt.Println(warnBox.Render(strings.Join(warnLines, "\n")))
	}
}
