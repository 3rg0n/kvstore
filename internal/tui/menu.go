package tui

import (
	"fmt"
	"io"
	"strings"

	"github.com/charmbracelet/bubbles/list"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

// menuItem is a simple list item for the main menu.
type menuItem struct {
	title string
	desc  string
}

func (i menuItem) Title() string       { return i.title }
func (i menuItem) Description() string { return i.desc }
func (i menuItem) FilterValue() string { return i.title }

// menuDelegate renders menu items.
type menuDelegate struct{}

func (d menuDelegate) Height() int                             { return 1 }
func (d menuDelegate) Spacing() int                            { return 0 }
func (d menuDelegate) Update(_ tea.Msg, _ *list.Model) tea.Cmd { return nil }
func (d menuDelegate) Render(w io.Writer, m list.Model, index int, item list.Item) {
	mi, ok := item.(menuItem)
	if !ok {
		return
	}
	cursor := "  "
	style := lipgloss.NewStyle()
	if index == m.Index() {
		cursor = "> "
		style = selectedStyle
	}
	fmt.Fprintf(w, "%s%s", cursor, style.Render(mi.title)) //nolint:errcheck // list delegate writer
}

// --- main menu screen ---

type menuScreen struct {
	root *Model
	list list.Model
}

func newMenuScreen(root *Model) *menuScreen {
	items := []list.Item{
		menuItem{title: "Secrets", desc: "Browse and manage secrets"},
		menuItem{title: "Applications", desc: "Manage registered apps"},
		menuItem{title: "Server", desc: "Control the HTTP API server"},
		menuItem{title: "Settings", desc: "View configuration"},
		menuItem{title: "Exit", desc: "Quit kvstore"},
	}

	l := list.New(items, menuDelegate{}, 40, 10)
	l.Title = "kvstore"
	l.SetShowStatusBar(false)
	l.SetFilteringEnabled(false)
	l.SetShowHelp(false)
	l.Styles.Title = titleStyle

	return &menuScreen{root: root, list: l}
}

func (s *menuScreen) Init() tea.Cmd {
	return nil
}

func (s *menuScreen) Update(msg tea.Msg) (screen, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "enter":
			item, ok := s.list.SelectedItem().(menuItem)
			if !ok {
				return s, nil
			}
			switch item.title {
			case "Secrets":
				return s, func() tea.Msg { return pushScreenMsg{s: newNamespaceScreen(s.root)} }
			case "Applications":
				return s, func() tea.Msg { return pushScreenMsg{s: newAppListScreen(s.root)} }
			case "Server":
				return s, func() tea.Msg { return pushScreenMsg{s: newServerScreen(s.root)} }
			case "Settings":
				return s, func() tea.Msg { return pushScreenMsg{s: newSettingsScreen(s.root)} }
			case "Exit":
				return s, tea.Quit
			}
		case "q":
			return s, tea.Quit
		case "esc":
			return s, tea.Quit
		}
	}

	var cmd tea.Cmd
	s.list, cmd = s.list.Update(msg)
	return s, cmd
}

func (s *menuScreen) View() string {
	var b strings.Builder
	b.WriteString("\n")
	b.WriteString(s.list.View())
	b.WriteString("\n")
	b.WriteString(helpStyle.Render("  ↑/↓ navigate • enter select • q quit"))
	return b.String()
}
