package tui

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/lipgloss"
	"github.com/ledatu/csar/internal/simulate"
)

// RenderSimulationResult renders a simulation result to stdout using Lip Gloss.
func RenderSimulationResult(result *simulate.MatchResult) {
	fmt.Println()

	if !result.Matched {
		box := lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(ColorError).
			Padding(1, 2).
			Width(60)

		fmt.Println(box.Render(
			ErrorStyle.Render(fmt.Sprintf("%s  No route matched", IconCross)) + "\n\n" +
				DimStyle.Render(result.Decision),
		))
		return
	}

	// Match info
	matchBox := lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(ColorSuccess).
		Padding(1, 2).
		Width(70)

	matchType := "exact"
	if result.IsRegex {
		matchType = "regex"
	}

	matchLines := []string{
		SuccessStyle.Render(fmt.Sprintf("%s  Route matched (%s)", IconCheck, matchType)),
		"",
		fmt.Sprintf("  %s %s %s", LabelStyle.Render("Route:"), MethodBadge(result.RouteMethod), result.RoutePath),
		fmt.Sprintf("  %s %s", LabelStyle.Render("Target:"), ValueStyle.Render(result.TargetURL)),
	}

	fmt.Println(matchBox.Render(strings.Join(matchLines, "\n")))

	// Middleware pipeline
	if len(result.Middlewares) > 0 {
		fmt.Println()

		pipeBox := lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(ColorAccent).
			Padding(1, 2).
			Width(70)

		var pipeLines []string
		pipeLines = append(pipeLines, SubtitleStyle.Render(fmt.Sprintf("  %s Middleware Pipeline (%d)", IconGear, len(result.Middlewares))))
		pipeLines = append(pipeLines, "")

		for i, mw := range result.Middlewares {
			icon := IconDot
			impactStyle := DimStyle
			switch mw.Impact {
			case "blocks":
				icon = "⛔"
				impactStyle = ErrorStyle
			case "modifies":
				icon = "✏️"
				impactStyle = WarningStyle
			case "observes":
				icon = "👁"
				impactStyle = lipgloss.NewStyle().Foreground(ColorSecondary)
			}

			connector := "├"
			if i == len(result.Middlewares)-1 {
				connector = "└"
			}

			pipeLines = append(pipeLines, fmt.Sprintf("  %s─ %s %s %s",
				connector,
				icon,
				lipgloss.NewStyle().Bold(true).Foreground(ColorText).Render(mw.Name),
				impactStyle.Render("["+mw.Impact+"]"),
			))
			pipeLines = append(pipeLines, fmt.Sprintf("  %s  %s",
				func() string {
					if i == len(result.Middlewares)-1 {
						return " "
					}
					return "│"
				}(),
				DimStyle.Render(mw.Details),
			))
		}

		fmt.Println(pipeBox.Render(strings.Join(pipeLines, "\n")))
	}

	// Legend
	fmt.Println()
	fmt.Println(DimStyle.Render("  Legend: ⛔ blocks request  ✏️  modifies request/response  👁 observes only"))
}
