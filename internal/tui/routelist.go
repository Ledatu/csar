package tui

import (
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/charmbracelet/bubbles/key"
	"github.com/charmbracelet/bubbles/list"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/ledatu/csar/internal/config"
)

// ─── Route item ────────────────────────────────────────────────────────────────

// RouteItem represents a single route in the bubbles list.
type RouteItem struct {
	Path    string
	Method  string
	Route   config.RouteConfig
	Dirty   bool // true if modified since last save
}

func (i RouteItem) FilterValue() string {
	return i.Method + " " + i.Path
}

// ─── Custom delegate ───────────────────────────────────────────────────────────

type routeDelegate struct{}

func (d routeDelegate) Height() int                             { return 3 }
func (d routeDelegate) Spacing() int                            { return 0 }
func (d routeDelegate) Update(_ tea.Msg, _ *list.Model) tea.Cmd { return nil }

func (d routeDelegate) Render(w io.Writer, m list.Model, index int, listItem list.Item) {
	ri, ok := listItem.(RouteItem)
	if !ok {
		return
	}

	isSelected := index == m.Index()

	// Method badge
	badge := MethodBadge(strings.ToUpper(ri.Method))

	// Path
	pathStyle := lipgloss.NewStyle().Foreground(ColorText)
	if isSelected {
		pathStyle = pathStyle.Foreground(ColorPrimary).Bold(true)
	}

	// Detail line: target + middleware indicators
	var indicators []string
	if ri.Route.Backend.TargetURL != "" {
		indicators = append(indicators, DimStyle.Render(IconArrow+" "+truncate(ri.Route.Backend.TargetURL, 40)))
	}
	if ri.Route.Traffic != nil {
		indicators = append(indicators, lipgloss.NewStyle().Foreground(ColorSecondary).Render(fmt.Sprintf("⏱ %.0frps", ri.Route.Traffic.RPS)))
	}
	if len(ri.Route.Security) > 0 {
		indicators = append(indicators, lipgloss.NewStyle().Foreground(ColorWarning).Render(IconShield))
	}
	if ri.Route.AuthValidate != nil {
		indicators = append(indicators, lipgloss.NewStyle().Foreground(ColorSuccess).Render(IconKey))
	}
	if ri.Route.Resilience != nil {
		indicators = append(indicators, lipgloss.NewStyle().Foreground(ColorAccent).Render("⛑"))
	}
	if ri.Route.Cache != nil {
		indicators = append(indicators, lipgloss.NewStyle().Foreground(ColorSecondary).Render("💾"))
	}
	if ri.Route.CORS != nil {
		indicators = append(indicators, DimStyle.Render("CORS"))
	}

	dirtyMark := ""
	if ri.Dirty {
		dirtyMark = WarningStyle.Render(" ●")
	}

	// Cursor
	cursor := "  "
	if isSelected {
		cursor = lipgloss.NewStyle().Foreground(ColorPrimary).Render("▸ ")
	}

	line1 := fmt.Sprintf("%s%s %s%s", cursor, badge, pathStyle.Render(ri.Path), dirtyMark)
	line2 := fmt.Sprintf("    %s", strings.Join(indicators, "  "))

	fmt.Fprintf(w, "%s\n%s\n", line1, line2)
}

// ─── Route list model ──────────────────────────────────────────────────────────

// RouteListModel wraps bubbles/list for displaying routes.
type RouteListModel struct {
	list     list.Model
	keys     routeListKeyMap
	quitting bool
}

type routeListKeyMap struct {
	Enter  key.Binding
	Save   key.Binding
	Reload key.Binding
	Quit   key.Binding
	Add    key.Binding
}

func newRouteListKeyMap() routeListKeyMap {
	return routeListKeyMap{
		Enter: key.NewBinding(
			key.WithKeys("enter"),
			key.WithHelp("enter", "edit route"),
		),
		Save: key.NewBinding(
			key.WithKeys("ctrl+s"),
			key.WithHelp("ctrl+s", "push config"),
		),
		Reload: key.NewBinding(
			key.WithKeys("ctrl+r"),
			key.WithHelp("ctrl+r", "reload"),
		),
		Quit: key.NewBinding(
			key.WithKeys("q", "ctrl+c"),
			key.WithHelp("q", "quit"),
		),
		Add: key.NewBinding(
			key.WithKeys("a"),
			key.WithHelp("a", "add route"),
		),
	}
}

// NewRouteList creates a new route list model from config.
func NewRouteList(cfg *config.Config, width, height int) RouteListModel {
	items := configToItems(cfg)

	delegate := routeDelegate{}
	l := list.New(items, delegate, width, height)
	l.Title = "  CSAR Routes"
	l.SetShowStatusBar(true)
	l.SetFilteringEnabled(true)
	l.Styles.Title = TitleStyle
	l.Styles.FilterPrompt = lipgloss.NewStyle().Foreground(ColorSecondary)
	l.Styles.FilterCursor = lipgloss.NewStyle().Foreground(ColorPrimary)

	keys := newRouteListKeyMap()
	l.AdditionalShortHelpKeys = func() []key.Binding {
		return []key.Binding{keys.Enter, keys.Add, keys.Save}
	}
	l.AdditionalFullHelpKeys = func() []key.Binding {
		return []key.Binding{keys.Enter, keys.Add, keys.Save, keys.Reload}
	}

	return RouteListModel{
		list: l,
		keys: keys,
	}
}

// SelectedRoute returns the currently selected route item, if any.
func (m RouteListModel) SelectedRoute() *RouteItem {
	item := m.list.SelectedItem()
	if item == nil {
		return nil
	}
	ri := item.(RouteItem)
	return &ri
}

// UpdateItem replaces the item at the given index.
func (m *RouteListModel) UpdateItem(index int, item RouteItem) {
	cmd := m.list.SetItem(index, item)
	_ = cmd // discard tea.Cmd since we handle it in Update
}

// AddItem appends a new route item to the list.
func (m *RouteListModel) AddItem(item RouteItem) {
	cmd := m.list.InsertItem(len(m.list.Items()), item)
	_ = cmd
}

// SelectedIndex returns the currently selected index.
func (m RouteListModel) SelectedIndex() int {
	return m.list.Index()
}

// SetSize sets the list dimensions.
func (m *RouteListModel) SetSize(w, h int) {
	m.list.SetSize(w, h)
}

func (m RouteListModel) Init() tea.Cmd {
	return nil
}

func (m RouteListModel) Update(msg tea.Msg) (RouteListModel, tea.Cmd) {
	var cmd tea.Cmd
	m.list, cmd = m.list.Update(msg)
	return m, cmd
}

func (m RouteListModel) View() string {
	return m.list.View()
}

// ─── Helpers ───────────────────────────────────────────────────────────────────

func configToItems(cfg *config.Config) []list.Item {
	var items []list.Item
	// Collect and sort for deterministic order
	type pathMethod struct {
		path   string
		method string
	}
	var keys []pathMethod
	for path, methods := range cfg.Paths {
		for method := range methods {
			keys = append(keys, pathMethod{path, method})
		}
	}
	sort.Slice(keys, func(i, j int) bool {
		if keys[i].path == keys[j].path {
			return keys[i].method < keys[j].method
		}
		return keys[i].path < keys[j].path
	})

	for _, k := range keys {
		route := cfg.Paths[k.path][k.method]
		items = append(items, RouteItem{
			Path:   k.path,
			Method: k.method,
			Route:  route,
		})
	}
	return items
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max-1] + "…"
}
