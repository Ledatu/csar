// Package tui provides Bubble Tea TUI screens and Lip Gloss styles
// for the csar-helper CLI.
package tui

import "github.com/charmbracelet/lipgloss"

// ─── Color palette ─────────────────────────────────────────────────────────────

var (
	ColorPrimary    = lipgloss.Color("#7C3AED") // violet
	ColorSecondary  = lipgloss.Color("#06B6D4") // cyan
	ColorSuccess    = lipgloss.Color("#10B981") // green
	ColorWarning    = lipgloss.Color("#F59E0B") // amber
	ColorError      = lipgloss.Color("#EF4444") // red
	ColorMuted      = lipgloss.Color("#6B7280") // gray
	ColorText       = lipgloss.Color("#E5E7EB") // light gray
	ColorDim        = lipgloss.Color("#9CA3AF") // dim gray
	ColorAccent     = lipgloss.Color("#A78BFA") // light violet
	ColorBackground = lipgloss.Color("#1F2937") // dark slate
)

// ─── Reusable styles ───────────────────────────────────────────────────────────

var (
	// Title styles
	TitleStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(ColorPrimary).
			MarginBottom(1)

	SubtitleStyle = lipgloss.NewStyle().
			Foreground(ColorSecondary).
			Italic(true)

	// Status indicators
	SuccessStyle = lipgloss.NewStyle().
			Foreground(ColorSuccess).
			Bold(true)

	WarningStyle = lipgloss.NewStyle().
			Foreground(ColorWarning).
			Bold(true)

	ErrorStyle = lipgloss.NewStyle().
			Foreground(ColorError).
			Bold(true)

	MutedStyle = lipgloss.NewStyle().
			Foreground(ColorMuted)

	DimStyle = lipgloss.NewStyle().
			Foreground(ColorDim)

	// Content styles
	LabelStyle = lipgloss.NewStyle().
			Foreground(ColorAccent).
			Bold(true).
			Width(20)

	ValueStyle = lipgloss.NewStyle().
			Foreground(ColorText)

	// Box styles
	BoxStyle = lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(ColorPrimary).
			Padding(1, 2)

	ActiveBoxStyle = lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(ColorSecondary).
			Padding(1, 2)

	// List item styles
	ItemStyle = lipgloss.NewStyle().
			PaddingLeft(2)

	SelectedItemStyle = lipgloss.NewStyle().
				Foreground(ColorPrimary).
				Bold(true).
				PaddingLeft(1)

	// Help bar
	HelpStyle = lipgloss.NewStyle().
			Foreground(ColorMuted).
			MarginTop(1)

	// Badge styles for methods
	MethodGET    = lipgloss.NewStyle().Background(lipgloss.Color("#10B981")).Foreground(lipgloss.Color("#000")).Bold(true).Padding(0, 1)
	MethodPOST   = lipgloss.NewStyle().Background(lipgloss.Color("#3B82F6")).Foreground(lipgloss.Color("#FFF")).Bold(true).Padding(0, 1)
	MethodPUT    = lipgloss.NewStyle().Background(lipgloss.Color("#F59E0B")).Foreground(lipgloss.Color("#000")).Bold(true).Padding(0, 1)
	MethodDELETE = lipgloss.NewStyle().Background(lipgloss.Color("#EF4444")).Foreground(lipgloss.Color("#FFF")).Bold(true).Padding(0, 1)
	MethodPATCH  = lipgloss.NewStyle().Background(lipgloss.Color("#8B5CF6")).Foreground(lipgloss.Color("#FFF")).Bold(true).Padding(0, 1)
	MethodAny    = lipgloss.NewStyle().Background(lipgloss.Color("#6B7280")).Foreground(lipgloss.Color("#FFF")).Bold(true).Padding(0, 1)
)

// MethodBadge returns a colored badge for the HTTP method.
func MethodBadge(method string) string {
	switch method {
	case "GET", "get":
		return MethodGET.Render("GET")
	case "POST", "post":
		return MethodPOST.Render("POST")
	case "PUT", "put":
		return MethodPUT.Render("PUT")
	case "DELETE", "delete":
		return MethodDELETE.Render("DEL")
	case "PATCH", "patch":
		return MethodPATCH.Render("PATCH")
	default:
		return MethodAny.Render(method)
	}
}

// Icons
const (
	IconCheck   = "✓"
	IconCross   = "✗"
	IconWarning = "⚠"
	IconArrow   = "→"
	IconDot     = "●"
	IconCircle  = "○"
	IconKey     = "🔑"
	IconShield  = "🛡"
	IconRocket  = "🚀"
	IconGear    = "⚙"
	IconPlug    = "🔌"
)
