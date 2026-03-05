package tui

import (
	"fmt"
	"os"
	"strings"

	"github.com/charmbracelet/bubbles/key"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/ledatu/csar/internal/config"
	"gopkg.in/yaml.v3"
)

// ─── Messages ──────────────────────────────────────────────────────────────────

// ConfigPushRequestMsg is sent when the user presses Ctrl+S on the route list.
type ConfigPushRequestMsg struct {
	Config *config.Config
}

// ConfigPushedMsg is the result of a push operation.
type ConfigPushedMsg struct {
	Success bool
	Message string
}

// ─── App state ─────────────────────────────────────────────────────────────────

type appScreen int

const (
	screenList appScreen = iota
	screenEdit
	screenAdd
)

// AppModel is the top-level Bubble Tea model for the TUI route editor.
type AppModel struct {
	cfg        *config.Config
	cfgPath    string
	screen     appScreen
	routeList  RouteListModel
	routeEdit  RouteEditModel
	routeAdd   RouteAddModel
	width      int
	height     int
	statusMsg  string
	statusErr  bool
	pushFn     func(*config.Config) error // optional: push to coordinator
}

// AppOption configures the TUI app.
type AppOption func(*AppModel)

// WithPushFn sets the function used to push config to the coordinator.
func WithPushFn(fn func(*config.Config) error) AppOption {
	return func(m *AppModel) { m.pushFn = fn }
}

// NewApp creates the main TUI application model.
func NewApp(cfg *config.Config, cfgPath string, opts ...AppOption) AppModel {
	m := AppModel{
		cfg:     cfg,
		cfgPath: cfgPath,
		screen:  screenList,
		width:   80,
		height:  24,
	}
	for _, opt := range opts {
		opt(&m)
	}
	m.routeList = NewRouteList(cfg, m.width, m.height-2)
	return m
}

func (m AppModel) Init() tea.Cmd {
	return nil
}

func (m AppModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		m.routeList.SetSize(m.width, m.height-2)
		return m, nil

	case tea.KeyMsg:
		// Global quit
		if key.Matches(msg, key.NewBinding(key.WithKeys("ctrl+c"))) {
			return m, tea.Quit
		}

		switch m.screen {
		case screenList:
			return m.updateList(msg)
		case screenEdit:
			return m.updateEdit(msg)
		case screenAdd:
			return m.updateAdd(msg)
		}

	case RouteUpdatedMsg:
		return m.handleRouteUpdated(msg)

	case RouteEditCancelledMsg:
		m.screen = screenList
		m.statusMsg = ""
		return m, nil

	case RouteAddedMsg:
		return m.handleRouteAdded(msg)

	case RouteAddCancelledMsg:
		m.screen = screenList
		m.statusMsg = ""
		return m, nil

	case ConfigPushedMsg:
		if msg.Success {
			m.statusMsg = SuccessStyle.Render(fmt.Sprintf("%s %s", IconCheck, msg.Message))
			m.statusErr = false
		} else {
			m.statusMsg = ErrorStyle.Render(fmt.Sprintf("%s %s", IconCross, msg.Message))
			m.statusErr = true
		}
		return m, nil

	default:
		switch m.screen {
		case screenList:
			var cmd tea.Cmd
			m.routeList, cmd = m.routeList.Update(msg)
			return m, cmd
		case screenEdit:
			var cmd tea.Cmd
			m.routeEdit, cmd = m.routeEdit.Update(msg)
			return m, cmd
		case screenAdd:
			var cmd tea.Cmd
			m.routeAdd, cmd = m.routeAdd.Update(msg)
			return m, cmd
		}
	}

	return m, nil
}

func (m AppModel) updateList(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "enter":
		sel := m.routeList.SelectedRoute()
		if sel != nil {
			m.routeEdit = NewRouteEdit(m.routeList.SelectedIndex(), *sel, m.width, m.height)
			m.screen = screenEdit
			return m, m.routeEdit.Init()
		}

	case "a":
		m.routeAdd = NewRouteAdd(m.width, m.height)
		m.screen = screenAdd
		return m, m.routeAdd.Init()

	case "ctrl+s":
		return m, m.pushConfig()

	case "q":
		return m, tea.Quit
	}

	var cmd tea.Cmd
	m.routeList, cmd = m.routeList.Update(msg)
	return m, cmd
}

func (m AppModel) updateEdit(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	var cmd tea.Cmd
	m.routeEdit, cmd = m.routeEdit.Update(msg)
	return m, cmd
}

func (m AppModel) updateAdd(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	var cmd tea.Cmd
	m.routeAdd, cmd = m.routeAdd.Update(msg)
	return m, cmd
}

func (m AppModel) handleRouteUpdated(msg RouteUpdatedMsg) (tea.Model, tea.Cmd) {
	// Apply the edit back to the config
	item := msg.Item
	if methods, ok := m.cfg.Paths[item.Path]; ok {
		methods[item.Method] = item.Route
	}

	m.routeList.UpdateItem(msg.Index, item)
	m.screen = screenList
	m.statusMsg = SuccessStyle.Render(fmt.Sprintf("%s Route updated: %s %s", IconCheck, strings.ToUpper(item.Method), item.Path))
	m.statusErr = false
	return m, nil
}

func (m AppModel) handleRouteAdded(msg RouteAddedMsg) (tea.Model, tea.Cmd) {
	item := msg.Item

	// Add to config
	if m.cfg.Paths == nil {
		m.cfg.Paths = make(map[string]config.PathConfig)
	}
	if _, ok := m.cfg.Paths[item.Path]; !ok {
		m.cfg.Paths[item.Path] = make(config.PathConfig)
	}
	m.cfg.Paths[item.Path][item.Method] = item.Route

	// Add to list
	m.routeList.AddItem(item)
	m.screen = screenList
	m.statusMsg = SuccessStyle.Render(fmt.Sprintf("%s Route added: %s %s", IconCheck, strings.ToUpper(item.Method), item.Path))
	m.statusErr = false
	return m, nil
}

func (m AppModel) pushConfig() tea.Cmd {
	return func() tea.Msg {
		// First, save to disk
		data, err := yaml.Marshal(m.cfg)
		if err != nil {
			return ConfigPushedMsg{Success: false, Message: fmt.Sprintf("marshal error: %v", err)}
		}

		if err := writeConfigFile(m.cfgPath, data); err != nil {
			return ConfigPushedMsg{Success: false, Message: fmt.Sprintf("write error: %v", err)}
		}

		// If a coordinator connection is available, notify it that config
		// was updated locally. Note: the coordinator pushes config *to*
		// routers via the Subscribe stream — the TUI cannot push config
		// upstream. This notification lets the coordinator know a node
		// was touched so it can trigger a re-sync if needed.
		if m.pushFn != nil {
			if err := m.pushFn(m.cfg); err != nil {
				// Config was saved, but coordinator notification failed.
				return ConfigPushedMsg{
					Success: true,
					Message: fmt.Sprintf("Config saved to %s (coordinator notification failed: %v)", m.cfgPath, err),
				}
			}
			return ConfigPushedMsg{
				Success: true,
				Message: fmt.Sprintf("Config saved to %s — coordinator notified", m.cfgPath),
			}
		}

		return ConfigPushedMsg{Success: true, Message: fmt.Sprintf("Config saved to %s", m.cfgPath)}
	}
}

func (m AppModel) View() string {
	var view string

	switch m.screen {
	case screenList:
		view = m.routeList.View()
	case screenEdit:
		view = m.routeEdit.View()
	case screenAdd:
		view = m.routeAdd.View()
	}

	// Status bar at the bottom
	if m.statusMsg != "" {
		statusBar := lipgloss.NewStyle().
			Width(m.width).
			Padding(0, 1).
			Render(m.statusMsg)
		view = view + "\n" + statusBar
	}

	return view
}

// writeConfigFile writes data to a config file.
func writeConfigFile(path string, data []byte) error {
	return os.WriteFile(path, data, 0o644)
}
