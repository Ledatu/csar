package tui

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/help"
	"github.com/charmbracelet/bubbles/key"
	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/ledatu/csar/internal/config"
)

// ─── Messages ──────────────────────────────────────────────────────────────────

// RouteUpdatedMsg signals that the user has saved edits to a route.
type RouteUpdatedMsg struct {
	Index int
	Item  RouteItem
}

// RouteEditCancelledMsg signals the user cancelled editing.
type RouteEditCancelledMsg struct{}

// ─── Route edit model ──────────────────────────────────────────────────────────

type editField int

const (
	fieldTargetURL editField = iota
	fieldRPS
	fieldBurst
	fieldMaxWait
	fieldCount
)

// RouteEditModel is a form for editing a single route's properties.
type RouteEditModel struct {
	index   int
	item    RouteItem
	inputs  []textinput.Model
	focused editField
	help    help.Model
	keys    editKeyMap
	width   int
	height  int
	err     error
}

type editKeyMap struct {
	Tab  key.Binding
	STab key.Binding
	Save key.Binding
	Back key.Binding
}

func newEditKeyMap() editKeyMap {
	return editKeyMap{
		Tab: key.NewBinding(
			key.WithKeys("tab"),
			key.WithHelp("tab", "next field"),
		),
		STab: key.NewBinding(
			key.WithKeys("shift+tab"),
			key.WithHelp("shift+tab", "prev field"),
		),
		Save: key.NewBinding(
			key.WithKeys("ctrl+s"),
			key.WithHelp("ctrl+s", "save"),
		),
		Back: key.NewBinding(
			key.WithKeys("esc"),
			key.WithHelp("esc", "back"),
		),
	}
}

func (k editKeyMap) ShortHelp() []key.Binding {
	return []key.Binding{k.Tab, k.Save, k.Back}
}

func (k editKeyMap) FullHelp() [][]key.Binding {
	return [][]key.Binding{
		{k.Tab, k.STab},
		{k.Save, k.Back},
	}
}

// NewRouteEdit creates a route editor for the given route item.
func NewRouteEdit(index int, item RouteItem, width, height int) RouteEditModel {
	inputs := make([]textinput.Model, fieldCount)

	// Target URL
	inputs[fieldTargetURL] = textinput.New()
	inputs[fieldTargetURL].Placeholder = "https://api.example.com"
	inputs[fieldTargetURL].SetValue(item.Route.Backend.TargetURL)
	inputs[fieldTargetURL].CharLimit = 256
	inputs[fieldTargetURL].Width = 50
	inputs[fieldTargetURL].PromptStyle = lipgloss.NewStyle().Foreground(ColorAccent)
	inputs[fieldTargetURL].TextStyle = lipgloss.NewStyle().Foreground(ColorText)

	// RPS
	inputs[fieldRPS] = textinput.New()
	inputs[fieldRPS].Placeholder = "100"
	if item.Route.Traffic != nil {
		inputs[fieldRPS].SetValue(fmt.Sprintf("%.0f", item.Route.Traffic.RPS))
	}
	inputs[fieldRPS].CharLimit = 10
	inputs[fieldRPS].Width = 15
	inputs[fieldRPS].PromptStyle = lipgloss.NewStyle().Foreground(ColorAccent)

	// Burst
	inputs[fieldBurst] = textinput.New()
	inputs[fieldBurst].Placeholder = "10"
	if item.Route.Traffic != nil {
		inputs[fieldBurst].SetValue(fmt.Sprintf("%d", item.Route.Traffic.Burst))
	}
	inputs[fieldBurst].CharLimit = 10
	inputs[fieldBurst].Width = 15
	inputs[fieldBurst].PromptStyle = lipgloss.NewStyle().Foreground(ColorAccent)

	// MaxWait
	inputs[fieldMaxWait] = textinput.New()
	inputs[fieldMaxWait].Placeholder = "5s"
	if item.Route.Traffic != nil && item.Route.Traffic.MaxWait.Duration > 0 {
		inputs[fieldMaxWait].SetValue(item.Route.Traffic.MaxWait.String())
	}
	inputs[fieldMaxWait].CharLimit = 20
	inputs[fieldMaxWait].Width = 15
	inputs[fieldMaxWait].PromptStyle = lipgloss.NewStyle().Foreground(ColorAccent)

	// Focus the first input
	inputs[fieldTargetURL].Focus()

	return RouteEditModel{
		index:  index,
		item:   item,
		inputs: inputs,
		help:   help.New(),
		keys:   newEditKeyMap(),
		width:  width,
		height: height,
	}
}

func (m RouteEditModel) Init() tea.Cmd {
	return textinput.Blink
}

func (m RouteEditModel) Update(msg tea.Msg) (RouteEditModel, tea.Cmd) {
	var cmds []tea.Cmd

	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch {
		case key.Matches(msg, m.keys.Back):
			return m, func() tea.Msg { return RouteEditCancelledMsg{} }

		case key.Matches(msg, m.keys.Save):
			updated, err := m.applyEdits()
			if err != nil {
				m.err = err
				return m, nil
			}
			return m, func() tea.Msg { return RouteUpdatedMsg{Index: m.index, Item: updated} }

		case key.Matches(msg, m.keys.Tab):
			m.nextField()
			return m, nil

		case key.Matches(msg, m.keys.STab):
			m.prevField()
			return m, nil
		}

	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
	}

	// Update focused input
	var cmd tea.Cmd
	m.inputs[m.focused], cmd = m.inputs[m.focused].Update(msg)
	cmds = append(cmds, cmd)

	return m, tea.Batch(cmds...)
}

func (m RouteEditModel) View() string {
	titleBar := lipgloss.NewStyle().
		Bold(true).
		Foreground(ColorPrimary).
		MarginBottom(1).
		Render(fmt.Sprintf("  Edit Route: %s %s", MethodBadge(strings.ToUpper(m.item.Method)), m.item.Path))

	fieldLabels := []string{
		"Target URL",
		"RPS",
		"Burst",
		"Max Wait",
	}

	var fields []string
	for i, label := range fieldLabels {
		labelStyle := lipgloss.NewStyle().Width(14).Foreground(ColorDim)
		if editField(i) == m.focused {
			labelStyle = labelStyle.Foreground(ColorAccent).Bold(true)
		}
		fields = append(fields, fmt.Sprintf("  %s %s", labelStyle.Render(label+":"), m.inputs[i].View()))
	}

	formContent := lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(ColorPrimary).
		Padding(1, 2).
		Width(min(m.width-4, 70)).
		Render(strings.Join(fields, "\n\n"))

	// Info panel on the right
	var infoLines []string
	infoLines = append(infoLines, SubtitleStyle.Render("Route Details"), "")
	if len(m.item.Route.Security) > 0 {
		infoLines = append(infoLines, fmt.Sprintf("  %s Security: %d credential(s)", IconShield, len(m.item.Route.Security)))
		for _, sec := range m.item.Route.Security {
			infoLines = append(infoLines, DimStyle.Render(fmt.Sprintf("    %s %s → %s", IconArrow, sec.TokenRef, sec.InjectHeader)))
		}
	}
	if m.item.Route.AuthValidate != nil {
		infoLines = append(infoLines, fmt.Sprintf("  %s JWT: %s", IconKey, truncate(m.item.Route.AuthValidate.JWKSURL, 35)))
	}
	if m.item.Route.Resilience != nil {
		infoLines = append(infoLines, fmt.Sprintf("  ⛑ Circuit breaker: %s", m.item.Route.Resilience.CircuitBreaker))
	}
	if m.item.Route.CORS != nil {
		infoLines = append(infoLines, fmt.Sprintf("  CORS: %s", strings.Join(m.item.Route.CORS.AllowedOrigins, ", ")))
	}
	if m.item.Route.Cache != nil {
		infoLines = append(infoLines, fmt.Sprintf("  💾 Cache: TTL %s", m.item.Route.Cache.TTL.String()))
	}
	if len(m.item.Route.Headers) > 0 {
		infoLines = append(infoLines, fmt.Sprintf("  Headers: %d static", len(m.item.Route.Headers)))
	}
	if len(infoLines) == 2 {
		infoLines = append(infoLines, DimStyle.Render("  No middleware configured"))
	}

	infoPanel := lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(ColorMuted).
		Padding(1, 2).
		Width(min(m.width-4, 40)).
		Render(strings.Join(infoLines, "\n"))

	// Error display
	errDisplay := ""
	if m.err != nil {
		errDisplay = "\n" + ErrorStyle.Render(fmt.Sprintf("  %s %s", IconCross, m.err.Error()))
	}

	body := lipgloss.JoinHorizontal(lipgloss.Top, formContent, "  ", infoPanel)
	helpView := m.help.View(m.keys)

	return fmt.Sprintf("%s\n\n%s%s\n\n%s", titleBar, body, errDisplay, HelpStyle.Render(helpView))
}

func (m *RouteEditModel) nextField() {
	m.inputs[m.focused].Blur()
	m.focused = (m.focused + 1) % editField(fieldCount)
	m.inputs[m.focused].Focus()
}

func (m *RouteEditModel) prevField() {
	m.inputs[m.focused].Blur()
	m.focused = (m.focused - 1 + editField(fieldCount)) % editField(fieldCount)
	m.inputs[m.focused].Focus()
}

func (m *RouteEditModel) applyEdits() (RouteItem, error) {
	item := m.item
	item.Route.Backend.TargetURL = m.inputs[fieldTargetURL].Value()

	if item.Route.Backend.TargetURL == "" {
		return item, fmt.Errorf("target URL cannot be empty")
	}

	// Parse traffic fields
	rpsStr := m.inputs[fieldRPS].Value()
	burstStr := m.inputs[fieldBurst].Value()
	maxWaitStr := m.inputs[fieldMaxWait].Value()

	if rpsStr != "" || burstStr != "" || maxWaitStr != "" {
		if item.Route.Traffic == nil {
			item.Route.Traffic = &config.TrafficConfig{}
		}

		if rpsStr != "" {
			rps, err := strconv.ParseFloat(rpsStr, 64)
			if err != nil {
				return item, fmt.Errorf("invalid RPS value: %s", rpsStr)
			}
			item.Route.Traffic.RPS = rps
		}

		if burstStr != "" {
			burst, err := strconv.Atoi(burstStr)
			if err != nil {
				return item, fmt.Errorf("invalid burst value: %s", burstStr)
			}
			item.Route.Traffic.Burst = burst
		}

		if maxWaitStr != "" {
			dur, err := time.ParseDuration(maxWaitStr)
			if err != nil {
				return item, fmt.Errorf("invalid max_wait duration: %s", maxWaitStr)
			}
			item.Route.Traffic.MaxWait = config.Duration{Duration: dur}
		}
	} else {
		// All traffic fields cleared → remove traffic config
		item.Route.Traffic = nil
	}

	item.Dirty = true
	return item, nil
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
