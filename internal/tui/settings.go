package tui

import (
	"fmt"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/ecopelan/kvstore/internal/config"
)

type settingsScreen struct {
	root *Model
}

func newSettingsScreen(root *Model) *settingsScreen {
	return &settingsScreen{root: root}
}

func (s *settingsScreen) Init() tea.Cmd { return nil }

func (s *settingsScreen) Update(msg tea.Msg) (screen, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		if msg.String() == "esc" || msg.String() == "q" {
			return s, func() tea.Msg { return popScreenMsg{} }
		}
	}
	return s, nil
}

func (s *settingsScreen) View() string {
	plat := s.root.platform

	var b strings.Builder
	b.WriteString("\n")
	b.WriteString(titleStyle.Render("Settings"))
	b.WriteString("\n")
	b.WriteString(boxStyle.Render(
		labelStyle.Render("Version:") + " " + valueStyle.Render(fmt.Sprintf("kvstore %s", s.root.version)) + "\n" +
			labelStyle.Render("Store:") + " " + valueStyle.Render(config.StorePath()) + "\n" +
			labelStyle.Render("Socket:") + " " + valueStyle.Render(config.SocketPath()) + "\n" +
			labelStyle.Render("TPM:") + " " + valueStyle.Render(boolStr(plat.HasTPM())) + "\n" +
			labelStyle.Render("Biometric:") + " " + valueStyle.Render(boolStr(plat.HasBiometric())),
	))
	b.WriteString("\n\n")
	b.WriteString(helpStyle.Render("  esc back"))
	return b.String()
}

func boolStr(v bool) string {
	if v {
		return "available"
	}
	return "not available"
}
