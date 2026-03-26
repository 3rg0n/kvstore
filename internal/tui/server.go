package tui

import (
	"fmt"
	"os/exec"
	"strings"

	"github.com/charmbracelet/bubbles/list"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/huh"
	"github.com/ecopelan/kvstore/internal/config"
)

type serverScreen struct {
	root    *Model
	list    list.Model
	addr    string
	noAuth  bool
	debug   bool
	started bool
	form    *huh.Form
	mode    string // "menu" or "form"
}

func newServerScreen(root *Model) *serverScreen {
	items := []list.Item{
		menuItem{title: "Start Server", desc: "Launch the HTTP API server"},
		menuItem{title: "Back", desc: "Return to main menu"},
	}
	l := list.New(items, menuDelegate{}, 40, 8)
	l.Title = "Server Control"
	l.SetShowStatusBar(false)
	l.SetFilteringEnabled(false)
	l.SetShowHelp(false)
	l.Styles.Title = titleStyle

	return &serverScreen{
		root: root,
		list: l,
		addr: config.DefaultAddr,
		mode: "menu",
	}
}

func (s *serverScreen) Init() tea.Cmd { return nil }

func (s *serverScreen) buildForm() {
	s.form = huh.NewForm(
		huh.NewGroup(
			huh.NewInput().
				Title("Listen Address").
				Value(&s.addr),
			huh.NewConfirm().
				Title("Disable authentication?").
				Description("Only for development").
				Affirmative("Yes").
				Negative("No").
				Value(&s.noAuth),
			huh.NewConfirm().
				Title("Enable debug logging?").
				Affirmative("Yes").
				Negative("No").
				Value(&s.debug),
			huh.NewConfirm().
				Title("Start server?").
				Affirmative("Start").
				Negative("Cancel"),
		),
	)
}

func (s *serverScreen) Update(msg tea.Msg) (screen, tea.Cmd) {
	if s.mode == "form" {
		return s.updateForm(msg)
	}

	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "enter":
			item, ok := s.list.SelectedItem().(menuItem)
			if !ok {
				return s, nil
			}
			switch item.title {
			case "Start Server":
				s.mode = "form"
				s.buildForm()
				return s, s.form.Init()
			case "Back":
				return s, func() tea.Msg { return popScreenMsg{} }
			}
		}
	}

	var cmd tea.Cmd
	s.list, cmd = s.list.Update(msg)
	return s, cmd
}

func (s *serverScreen) updateForm(msg tea.Msg) (screen, tea.Cmd) {
	form, cmd := s.form.Update(msg)
	if f, ok := form.(*huh.Form); ok {
		s.form = f
	}

	if s.form.State == huh.StateCompleted {
		return s, s.startServer()
	}

	if s.form.State == huh.StateAborted {
		s.mode = "menu"
		return s, nil
	}

	return s, cmd
}

func (s *serverScreen) startServer() tea.Cmd {
	addr, noAuth, debug := s.addr, s.noAuth, s.debug
	return func() tea.Msg {
		args := []string{"serve", "--addr", addr}
		if noAuth {
			args = append(args, "--no-auth")
		}
		if debug {
			args = append(args, "--debug")
		}

		cmd := exec.Command("kvstore", args...) //nolint:gosec // user-controlled addr
		if err := cmd.Start(); err != nil {
			return errMsg(fmt.Sprintf("Start server: %v", err))
		}
		return successMsg(fmt.Sprintf("Server started on %s (PID %d)", addr, cmd.Process.Pid))
	}
}

func (s *serverScreen) View() string {
	var b strings.Builder
	b.WriteString("\n")

	if s.mode == "form" {
		b.WriteString(titleStyle.Render("Start Server"))
		b.WriteString("\n")
		b.WriteString(s.form.View())
		return b.String()
	}

	b.WriteString(s.list.View())
	b.WriteString("\n")
	if s.started {
		b.WriteString(successStyle.Render("  Server is running"))
		b.WriteString("\n")
	}
	b.WriteString(helpStyle.Render("  enter select • esc back"))
	return b.String()
}
