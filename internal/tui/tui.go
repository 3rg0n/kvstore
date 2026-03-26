package tui

import (
	"fmt"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/ecopelan/kvstore/internal/auth"
	"github.com/ecopelan/kvstore/internal/config"
	"github.com/ecopelan/kvstore/internal/platform"
	"github.com/ecopelan/kvstore/internal/store"
)

// screen is the interface all TUI screens implement.
type screen interface {
	Init() tea.Cmd
	Update(msg tea.Msg) (screen, tea.Cmd)
	View() string
}

// navigation messages
type (
	pushScreenMsg  struct{ s screen }
	popScreenMsg   struct{}
	replaceMsg     struct{ s screen }
	errMsg         string
	successMsg     string
	clearStatusMsg struct{}
)

// Model is the root Bubble Tea model.
type Model struct {
	stack    []screen
	store    *store.Store
	platform platform.Platform
	registry *auth.Registry
	version  string
	width    int
	height   int

	statusMsg   string
	statusStyle lipgloss.Style
}

func (m Model) Init() tea.Cmd {
	if len(m.stack) == 0 {
		return nil
	}
	return m.stack[len(m.stack)-1].Init()
}

func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height

	case tea.KeyMsg:
		if msg.String() == "ctrl+c" {
			return m, tea.Quit
		}
		if msg.String() == "esc" && len(m.stack) > 1 {
			m.stack = m.stack[:len(m.stack)-1]
			return m, m.stack[len(m.stack)-1].Init()
		}

	case pushScreenMsg:
		m.stack = append(m.stack, msg.s)
		return m, msg.s.Init()

	case popScreenMsg:
		if len(m.stack) > 1 {
			m.stack = m.stack[:len(m.stack)-1]
			return m, m.stack[len(m.stack)-1].Init()
		}

	case replaceMsg:
		if len(m.stack) > 0 {
			m.stack[len(m.stack)-1] = msg.s
		} else {
			m.stack = append(m.stack, msg.s)
		}
		return m, msg.s.Init()

	case errMsg:
		m.statusMsg = string(msg)
		m.statusStyle = errorStyle
		return m, tea.Tick(3*time.Second, func(time.Time) tea.Msg { return clearStatusMsg{} })

	case successMsg:
		m.statusMsg = string(msg)
		m.statusStyle = successStyle
		return m, tea.Tick(3*time.Second, func(time.Time) tea.Msg { return clearStatusMsg{} })

	case clearStatusMsg:
		m.statusMsg = ""
	}

	// Route to current screen
	if len(m.stack) > 0 {
		cur := m.stack[len(m.stack)-1]
		newScreen, cmd := cur.Update(msg)
		m.stack[len(m.stack)-1] = newScreen
		return m, cmd
	}
	return m, nil
}

func (m Model) View() string {
	if len(m.stack) == 0 {
		return ""
	}
	view := m.stack[len(m.stack)-1].View()

	if m.statusMsg != "" {
		view += "\n" + m.statusStyle.Render(m.statusMsg)
	}

	return view
}

// Start launches the TUI. Called from rootCmd when no subcommand is given.
func Start(version string) error {
	if err := config.EnsureDataDir(); err != nil {
		return err
	}

	s, err := store.Open(config.StorePath())
	if err != nil {
		return err
	}

	plat := platform.New()

	m := Model{
		store:    s,
		platform: plat,
		registry: auth.NewRegistry(s),
		version:  version,
	}

	// Start with splash screen that checks store state
	splash := newSplashScreen(&m)
	m.stack = []screen{splash}

	p := tea.NewProgram(&m, tea.WithAltScreen())
	if _, err := p.Run(); err != nil {
		_ = s.Close()
		return fmt.Errorf("TUI error: %w", err)
	}

	return s.Close()
}
