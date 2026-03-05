package tui

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/lipgloss"
)

// printGenerateSummary prints a formatted summary of the generated configuration.
func printGenerateSummary(r *GenerateResult) {
	fmt.Println()
	box := lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(ColorSuccess).
		Padding(1, 2).
		Width(68)

	title := SuccessStyle.Render(fmt.Sprintf("%s Configuration generated!", IconRocket))

	lines := []string{
		title,
		"",
		LabelStyle.Render("Project:") + "  " + ValueStyle.Render(r.ProjectName),
		LabelStyle.Render("Profile:") + "  " + ValueStyle.Render(r.Profile),
		LabelStyle.Render("Listen:") + "  " + ValueStyle.Render(r.ListenAddr),
		LabelStyle.Render("TLS:") + "  " + boolToYesNo(r.EnableTLS),
		LabelStyle.Render("KMS:") + "  " + ValueStyle.Render(r.KMSProvider),
		LabelStyle.Render("Rate limits:") + "  " + ValueStyle.Render(r.RateLimitBackend),
		LabelStyle.Render("JWT auth:") + "  " + boolToYesNo(r.EnableJWT),
		LabelStyle.Render("Circuit breaker:") + "  " + boolToYesNo(r.EnableCircuitBreaker),
		LabelStyle.Render("Retry:") + "  " + boolToYesNo(r.EnableRetry),
		LabelStyle.Render("Coordinator:") + "  " + boolToYesNo(r.EnableCoordinator),
	}

	if len(r.Routes) > 0 {
		lines = append(lines, "")
		lines = append(lines, LabelStyle.Render("Routes:"))
		for _, rt := range r.Routes {
			lines = append(lines,
				fmt.Sprintf("  %s %s %s %s",
					MethodBadge(strings.ToUpper(rt.Method)),
					ValueStyle.Render(rt.Path),
					DimStyle.Render(IconArrow),
					DimStyle.Render(rt.TargetURL),
				),
			)
		}
	}

	if r.GenerateCompose {
		lines = append(lines,
			"",
			LabelStyle.Render("Docker Compose:") + "  " + SuccessStyle.Render("yes"),
		)
		var svc []string
		svc = append(svc, "router")
		if r.IncludeCoordinator {
			svc = append(svc, "coordinator")
		}
		if r.IncludeRedis {
			svc = append(svc, "redis")
		}
		if r.IncludePostgres {
			svc = append(svc, "postgres")
		}
		lines = append(lines,
			LabelStyle.Render("Services:") + "  " + ValueStyle.Render(strings.Join(svc, ", ")),
		)
	}

	lines = append(lines,
		"",
		LabelStyle.Render("Output:") + "  " + ValueStyle.Render(r.OutputDir),
		"",
		DimStyle.Render("Files created:"),
		DimStyle.Render("  "+IconCheck+" config.yaml"),
		DimStyle.Render("  "+IconCheck+" .env.example"),
	)
	if r.GenerateCompose {
		lines = append(lines, DimStyle.Render("  "+IconCheck+" docker-compose.yaml"))
	}

	lines = append(lines,
		"",
		DimStyle.Render("Next steps:"),
		DimStyle.Render("  1. cp .env.example .env  — fill in real values"),
		DimStyle.Render("  2. Edit config.yaml — add routes & backends"),
		DimStyle.Render("  3. csar-helper validate --config config.yaml"),
	)
	if r.GenerateCompose {
		lines = append(lines, DimStyle.Render("  4. docker compose up -d"))
	} else {
		lines = append(lines, DimStyle.Render("  4. csar --config config.yaml"))
	}

	fmt.Println(box.Render(strings.Join(lines, "\n")))
}
