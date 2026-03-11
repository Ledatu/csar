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

// RouteAddedMsg signals that the user has added a new route.
type RouteAddedMsg struct {
	Item RouteItem
}

// RouteAddCancelledMsg signals the user cancelled adding.
type RouteAddCancelledMsg struct{}

// ─── Add route model ───────────────────────────────────────────────────────────

type addField int

const (
	addFieldPath addField = iota
	addFieldMethod
	addFieldTargetURL
	addFieldRPS
	addFieldBurst
	addFieldMaxWait
	addFieldCount
)

var methodOptions = []string{"get", "post", "put", "delete", "patch"}

// RouteAddModel is a form for adding a new route.
type RouteAddModel struct {
	inputs    []textinput.Model
	methodIdx int // index into methodOptions
	focused   addField
	help      help.Model
	keys      addKeyMap
	width     int
	height    int
	err       error
}

type addKeyMap struct {
	Tab   key.Binding
	STab  key.Binding
	Save  key.Binding
	Back  key.Binding
	Left  key.Binding
	Right key.Binding
}

func newAddKeyMap() addKeyMap {
	return addKeyMap{
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
			key.WithHelp("ctrl+s", "add route"),
		),
		Back: key.NewBinding(
			key.WithKeys("esc"),
			key.WithHelp("esc", "cancel"),
		),
		Left: key.NewBinding(
			key.WithKeys("left"),
			key.WithHelp("←/→", "change method"),
		),
		Right: key.NewBinding(
			key.WithKeys("right"),
		),
	}
}

func (k addKeyMap) ShortHelp() []key.Binding {
	return []key.Binding{k.Tab, k.Save, k.Back}
}

func (k addKeyMap) FullHelp() [][]key.Binding {
	return [][]key.Binding{
		{k.Tab, k.STab, k.Left},
		{k.Save, k.Back},
	}
}

// NewRouteAdd creates a route add form.
func NewRouteAdd(width, height int) RouteAddModel {
	inputs := make([]textinput.Model, addFieldCount)

	// Path
	inputs[addFieldPath] = textinput.New()
	inputs[addFieldPath].Placeholder = "/api/v1/resource"
	inputs[addFieldPath].CharLimit = 256
	inputs[addFieldPath].Width = 50
	inputs[addFieldPath].PromptStyle = lipgloss.NewStyle().Foreground(ColorAccent)
	inputs[addFieldPath].TextStyle = lipgloss.NewStyle().Foreground(ColorText)

	// Method — displayed as text but cycled with arrow keys
	inputs[addFieldMethod] = textinput.New()
	inputs[addFieldMethod].Placeholder = "get"
	inputs[addFieldMethod].SetValue("get")
	inputs[addFieldMethod].CharLimit = 10
	inputs[addFieldMethod].Width = 10
	inputs[addFieldMethod].PromptStyle = lipgloss.NewStyle().Foreground(ColorAccent)

	// Target URL
	inputs[addFieldTargetURL] = textinput.New()
	inputs[addFieldTargetURL].Placeholder = "http://localhost:3000/api/v1/resource"
	inputs[addFieldTargetURL].CharLimit = 256
	inputs[addFieldTargetURL].Width = 50
	inputs[addFieldTargetURL].PromptStyle = lipgloss.NewStyle().Foreground(ColorAccent)

	// RPS
	inputs[addFieldRPS] = textinput.New()
	inputs[addFieldRPS].Placeholder = "10"
	inputs[addFieldRPS].CharLimit = 10
	inputs[addFieldRPS].Width = 15
	inputs[addFieldRPS].PromptStyle = lipgloss.NewStyle().Foreground(ColorAccent)

	// Burst
	inputs[addFieldBurst] = textinput.New()
	inputs[addFieldBurst].Placeholder = "20"
	inputs[addFieldBurst].CharLimit = 10
	inputs[addFieldBurst].Width = 15
	inputs[addFieldBurst].PromptStyle = lipgloss.NewStyle().Foreground(ColorAccent)

	// Max Wait
	inputs[addFieldMaxWait] = textinput.New()
	inputs[addFieldMaxWait].Placeholder = "5s"
	inputs[addFieldMaxWait].CharLimit = 20
	inputs[addFieldMaxWait].Width = 15
	inputs[addFieldMaxWait].PromptStyle = lipgloss.NewStyle().Foreground(ColorAccent)

	inputs[addFieldPath].Focus()

	return RouteAddModel{
		inputs: inputs,
		help:   help.New(),
		keys:   newAddKeyMap(),
		width:  width,
		height: height,
	}
}

func (m RouteAddModel) Init() tea.Cmd {
	return textinput.Blink
}

func (m RouteAddModel) Update(msg tea.Msg) (RouteAddModel, tea.Cmd) {
	var cmds []tea.Cmd

	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch {
		case key.Matches(msg, m.keys.Back):
			return m, func() tea.Msg { return RouteAddCancelledMsg{} }

		case key.Matches(msg, m.keys.Save):
			item, err := m.buildRouteItem()
			if err != nil {
				m.err = err
				return m, nil
			}
			return m, func() tea.Msg { return RouteAddedMsg{Item: item} }

		case key.Matches(msg, m.keys.Tab):
			m.nextField()
			return m, nil

		case key.Matches(msg, m.keys.STab):
			m.prevField()
			return m, nil

		case key.Matches(msg, m.keys.Left) && m.focused == addFieldMethod:
			m.methodIdx = (m.methodIdx - 1 + len(methodOptions)) % len(methodOptions)
			m.inputs[addFieldMethod].SetValue(methodOptions[m.methodIdx])
			return m, nil

		case key.Matches(msg, m.keys.Right) && m.focused == addFieldMethod:
			m.methodIdx = (m.methodIdx + 1) % len(methodOptions)
			m.inputs[addFieldMethod].SetValue(methodOptions[m.methodIdx])
			return m, nil
		}

	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
	}

	// Update focused input
	if int(m.focused) < len(m.inputs) {
		var cmd tea.Cmd
		m.inputs[m.focused], cmd = m.inputs[m.focused].Update(msg)
		cmds = append(cmds, cmd)
	}

	return m, tea.Batch(cmds...)
}

func (m RouteAddModel) View() string {
	titleBar := lipgloss.NewStyle().
		Bold(true).
		Foreground(ColorPrimary).
		MarginBottom(1).
		Render("  Add New Route")

	fieldLabels := []string{
		"Path",
		"Method",
		"Target URL",
		"RPS",
		"Burst",
		"Max Wait",
	}

	var fields []string
	for i, label := range fieldLabels {
		labelStyle := lipgloss.NewStyle().Width(14).Foreground(ColorDim)
		if addField(i) == m.focused {
			labelStyle = labelStyle.Foreground(ColorAccent).Bold(true)
		}

		// For method field, show badge
		if addField(i) == addFieldMethod {
			method := m.inputs[addFieldMethod].Value()
			if method == "" {
				method = "get"
			}
			badge := MethodBadge(strings.ToUpper(method))
			hint := DimStyle.Render(" (←/→ to change)")
			fields = append(fields, fmt.Sprintf("  %s %s%s", labelStyle.Render(label+":"), badge, hint))
		} else {
			fields = append(fields, fmt.Sprintf("  %s %s", labelStyle.Render(label+":"), m.inputs[i].View()))
		}
	}

	formContent := lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(ColorSuccess).
		Padding(1, 2).
		Width(min(m.width-4, 70)).
		Render(strings.Join(fields, "\n\n"))

	errDisplay := ""
	if m.err != nil {
		errDisplay = "\n" + ErrorStyle.Render(fmt.Sprintf("  %s %s", IconCross, m.err.Error()))
	}

	helpView := m.help.View(m.keys)

	return fmt.Sprintf("%s\n\n%s%s\n\n%s", titleBar, formContent, errDisplay, HelpStyle.Render(helpView))
}

func (m *RouteAddModel) nextField() {
	if int(m.focused) < len(m.inputs) {
		m.inputs[m.focused].Blur()
	}
	m.focused = (m.focused + 1) % addField(addFieldCount)
	if int(m.focused) < len(m.inputs) {
		m.inputs[m.focused].Focus()
	}
}

func (m *RouteAddModel) prevField() {
	if int(m.focused) < len(m.inputs) {
		m.inputs[m.focused].Blur()
	}
	m.focused = (m.focused - 1 + addField(addFieldCount)) % addField(addFieldCount)
	if int(m.focused) < len(m.inputs) {
		m.inputs[m.focused].Focus()
	}
}

func (m *RouteAddModel) buildRouteItem() (RouteItem, error) {
	path := m.inputs[addFieldPath].Value()
	if path == "" {
		return RouteItem{}, fmt.Errorf("path cannot be empty")
	}
	if !strings.HasPrefix(path, "/") {
		return RouteItem{}, fmt.Errorf("path must start with /")
	}

	method := m.inputs[addFieldMethod].Value()
	if method == "" {
		method = "get"
	}

	targetURL := m.inputs[addFieldTargetURL].Value()
	if targetURL == "" {
		return RouteItem{}, fmt.Errorf("target URL cannot be empty")
	}

	route := config.RouteConfig{
		Backend: config.BackendConfig{
			TargetURL: targetURL,
		},
	}

	// Parse traffic fields if provided
	rpsStr := m.inputs[addFieldRPS].Value()
	burstStr := m.inputs[addFieldBurst].Value()
	maxWaitStr := m.inputs[addFieldMaxWait].Value()

	if rpsStr != "" || burstStr != "" || maxWaitStr != "" {
		route.Traffic = &config.TrafficConfig{}

		if rpsStr != "" {
			rps, err := strconv.ParseFloat(rpsStr, 64)
			if err != nil {
				return RouteItem{}, fmt.Errorf("invalid RPS value: %s", rpsStr)
			}
			route.Traffic.RPS = rps
		}

		if burstStr != "" {
			burst, err := strconv.Atoi(burstStr)
			if err != nil {
				return RouteItem{}, fmt.Errorf("invalid burst value: %s", burstStr)
			}
			route.Traffic.Burst = burst
		}

		if maxWaitStr != "" {
			dur, err := time.ParseDuration(maxWaitStr)
			if err != nil {
				return RouteItem{}, fmt.Errorf("invalid max_wait duration: %s", maxWaitStr)
			}
			route.Traffic.MaxWait = config.Duration{Duration: dur}
		}
	}

	return RouteItem{
		Path:   path,
		Method: method,
		Route:  route,
		Dirty:  true,
	}, nil
}
