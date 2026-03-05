package tui

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/lipgloss"
	"github.com/ledatu/csar/internal/helper"
)

// RenderStackValidation renders the results of a validate-stack pre-flight check.
func RenderStackValidation(result *helper.StackCheckResult) {
	fmt.Println()

	headerStyle := lipgloss.NewStyle().
		Bold(true).
		Foreground(ColorPrimary).
		MarginBottom(1)

	fmt.Println(headerStyle.Render(fmt.Sprintf("  %s Stack Pre-flight Check", IconRocket)))

	var errors, warnings, infos []helper.StackCheck
	for _, c := range result.Checks {
		switch c.Level {
		case "error":
			errors = append(errors, c)
		case "warning":
			warnings = append(warnings, c)
		default:
			infos = append(infos, c)
		}
	}

	// Info section
	if len(infos) > 0 {
		infoBox := lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(ColorSuccess).
			Padding(0, 2).
			Width(70)

		var infoLines []string
		infoLines = append(infoLines, SuccessStyle.Render(fmt.Sprintf("\n  %s  %d check(s) passed", IconCheck, len(infos))))
		infoLines = append(infoLines, "")
		for _, c := range infos {
			infoLines = append(infoLines, fmt.Sprintf("  %s %s",
				SuccessStyle.Render(IconCheck),
				DimStyle.Render(c.Message),
			))
		}
		infoLines = append(infoLines, "")
		fmt.Println(infoBox.Render(strings.Join(infoLines, "\n")))
	}

	// Errors section
	if len(errors) > 0 {
		fmt.Println()
		errBox := lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(ColorError).
			Padding(0, 2).
			Width(70)

		var errLines []string
		errLines = append(errLines, ErrorStyle.Render(fmt.Sprintf("\n  %s  %d error(s)", IconCross, len(errors))))
		errLines = append(errLines, "")
		for _, c := range errors {
			errLines = append(errLines, fmt.Sprintf("  %s %s",
				ErrorStyle.Render(IconDot),
				c.Message,
			))
		}
		errLines = append(errLines, "")
		fmt.Println(errBox.Render(strings.Join(errLines, "\n")))
	}

	// Warnings section
	if len(warnings) > 0 {
		fmt.Println()
		warnBox := lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(ColorWarning).
			Padding(0, 2).
			Width(70)

		var warnLines []string
		warnLines = append(warnLines, WarningStyle.Render(fmt.Sprintf("\n  %s  %d warning(s)", IconWarning, len(warnings))))
		warnLines = append(warnLines, "")
		for _, c := range warnings {
			warnLines = append(warnLines, fmt.Sprintf("  %s %s",
				WarningStyle.Render(IconDot),
				c.Message,
			))
		}
		warnLines = append(warnLines, "")
		fmt.Println(warnBox.Render(strings.Join(warnLines, "\n")))
	}

	// Summary
	fmt.Println()
	if !result.HasError && len(warnings) == 0 {
		fmt.Println(SuccessStyle.Render(fmt.Sprintf("  %s All checks passed! Your stack looks ready to deploy.", IconCheck)))
	} else if !result.HasError {
		fmt.Println(WarningStyle.Render(fmt.Sprintf("  %s Stack has %d warning(s) but no blocking errors.", IconWarning, len(warnings))))
	} else {
		fmt.Println(ErrorStyle.Render(fmt.Sprintf("  %s Stack has %d error(s) that must be fixed before deploying.", IconCross, len(errors))))
	}
}
