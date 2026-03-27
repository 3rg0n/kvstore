package tui

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/bubbles/table"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/huh"
	"github.com/charmbracelet/lipgloss"
	"github.com/ecopelan/kvstore/internal/auth"
)

// --- app list screen ---

type appListScreen struct {
	root  *Model
	table table.Model
	apps  []auth.AppRecord
}

type appsLoadedMsg struct {
	apps []auth.AppRecord
	err  error
}

func newAppListScreen(root *Model) *appListScreen {
	cols := []table.Column{
		{Title: "ID", Width: 12},
		{Title: "Name", Width: 20},
		{Title: "Mode", Width: 10},
		{Title: "Namespaces", Width: 25},
	}
	t := table.New(
		table.WithColumns(cols),
		table.WithFocused(true),
		table.WithHeight(10),
	)
	st := table.DefaultStyles()
	st.Header = st.Header.BorderStyle(lipgloss.NormalBorder()).
		BorderForeground(colorBorder).BorderBottom(true).Bold(true)
	st.Selected = st.Selected.Foreground(colorHighlight).Bold(true)
	t.SetStyles(st)

	return &appListScreen{root: root, table: t}
}

func (s *appListScreen) Init() tea.Cmd {
	return s.loadApps()
}

func (s *appListScreen) loadApps() tea.Cmd {
	return func() tea.Msg {
		apps, err := s.root.registry.List()
		return appsLoadedMsg{apps: apps, err: err}
	}
}

func (s *appListScreen) Update(msg tea.Msg) (screen, tea.Cmd) {
	switch msg := msg.(type) {
	case appsLoadedMsg:
		if msg.err != nil {
			return s, func() tea.Msg { return errMsg(fmt.Sprintf("Load apps: %v", msg.err)) }
		}
		s.apps = msg.apps
		rows := make([]table.Row, len(msg.apps))
		for i, a := range msg.apps {
			id := a.ID
			if len(id) > 12 {
				id = id[:12]
			}
			rows[i] = table.Row{id, a.Name, string(a.VerifyMode), strings.Join(a.Namespaces, ",")}
		}
		s.table.SetRows(rows)
		return s, nil

	case tea.KeyMsg:
		switch msg.String() {
		case "enter", "d":
			idx := s.table.Cursor()
			if idx >= 0 && idx < len(s.apps) {
				return s, func() tea.Msg {
					return pushScreenMsg{s: newAppDetailScreen(s.root, s.apps[idx])}
				}
			}
		case "n":
			return s, func() tea.Msg {
				return pushScreenMsg{s: newAppRegisterScreen(s.root)}
			}
		}
	}

	var cmd tea.Cmd
	s.table, cmd = s.table.Update(msg)
	return s, cmd
}

func (s *appListScreen) View() string {
	var b strings.Builder
	b.WriteString("\n")
	b.WriteString(titleStyle.Render("Registered Applications"))
	b.WriteString("\n")
	if len(s.apps) == 0 {
		b.WriteString("  No registered apps. Press [n] to register one.\n")
	} else {
		b.WriteString(s.table.View())
	}
	b.WriteString("\n")
	b.WriteString(helpStyle.Render("  enter details • n register • esc back"))
	return b.String()
}

// --- app detail screen ---

type appDetailScreen struct {
	root *Model
	app  auth.AppRecord
}

func newAppDetailScreen(root *Model, app auth.AppRecord) *appDetailScreen {
	return &appDetailScreen{root: root, app: app}
}

func (s *appDetailScreen) Init() tea.Cmd { return nil }

func (s *appDetailScreen) Update(msg tea.Msg) (screen, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "r":
			return s, s.revoke()
		case "h":
			if s.app.VerifyMode == auth.VerifyHash {
				return s, s.rehash()
			}
			return s, func() tea.Msg { return errMsg("Rehash only available for hash-mode apps") }
		case "e":
			return s, func() tea.Msg {
				return pushScreenMsg{s: newAppUpdateNsScreen(s.root, s.app)}
			}
		}
	}
	return s, nil
}

func (s *appDetailScreen) revoke() tea.Cmd {
	id := s.app.ID
	return func() tea.Msg {
		if err := s.root.registry.Revoke(id); err != nil {
			return errMsg(fmt.Sprintf("Revoke failed: %v", err))
		}
		return popScreenMsg{}
	}
}

func (s *appDetailScreen) rehash() tea.Cmd {
	id := s.app.ID
	return func() tea.Msg {
		if err := s.root.registry.Rehash(id); err != nil {
			return errMsg(fmt.Sprintf("Rehash failed: %v", err))
		}
		return successMsg("Binary hash updated")
	}
}

func (s *appDetailScreen) View() string {
	a := s.app
	var b strings.Builder
	b.WriteString("\n")
	b.WriteString(titleStyle.Render(fmt.Sprintf("App: %s", a.Name)))
	b.WriteString("\n")
	b.WriteString(boxStyle.Render(
		labelStyle.Render("ID:") + " " + valueStyle.Render(a.ID) + "\n" +
			labelStyle.Render("Binary:") + " " + valueStyle.Render(a.BinaryPath) + "\n" +
			labelStyle.Render("Verify:") + " " + valueStyle.Render(string(a.VerifyMode)) + "\n" +
			labelStyle.Render("Hash:") + " " + valueStyle.Render(a.BinaryHash) + "\n" +
			labelStyle.Render("Signer:") + " " + valueStyle.Render(a.SignerID) + "\n" +
			labelStyle.Render("Namespaces:") + " " + valueStyle.Render(strings.Join(a.Namespaces, ", ")) + "\n" +
			labelStyle.Render("Created:") + " " + valueStyle.Render(a.CreatedAt.Format("2006-01-02 15:04:05")),
	))
	b.WriteString("\n\n")
	b.WriteString(helpStyle.Render("  r revoke • h rehash • e edit namespaces • esc back"))
	return b.String()
}

// --- app register screen ---

type appRegisterScreen struct {
	root       *Model
	form       *huh.Form
	binaryPath string
	name       string
	namespaces string
	verifyMode string
}

func newAppRegisterScreen(root *Model) *appRegisterScreen {
	s := &appRegisterScreen{root: root, verifyMode: "auto"}
	s.buildForm()
	return s
}

func (s *appRegisterScreen) buildForm() {
	s.form = huh.NewForm(
		huh.NewGroup(
			huh.NewInput().
				Title("Binary Path").
				Description("Full path to the application binary").
				Value(&s.binaryPath),
			huh.NewInput().
				Title("App Name").
				Description("Friendly name (optional, defaults to filename)").
				Value(&s.name),
			huh.NewInput().
				Title("Namespaces").
				Description("Comma-separated (e.g. secrets,config)").
				Value(&s.namespaces),
			huh.NewSelect[string]().
				Title("Verify Mode").
				Description("Auto prefers code signature on Windows/macOS (recommended)").
				Options(
					huh.NewOption("Auto-detect (recommended)", "auto"),
					huh.NewOption("SHA-256 Hash", "hash"),
					huh.NewOption("Code Signature", "signature"),
				).
				Value(&s.verifyMode),
			huh.NewConfirm().
				Title("Register this application?").
				Affirmative("Register").
				Negative("Cancel"),
		),
	)
}

func (s *appRegisterScreen) Init() tea.Cmd {
	return s.form.Init()
}

func (s *appRegisterScreen) Update(msg tea.Msg) (screen, tea.Cmd) {
	form, cmd := s.form.Update(msg)
	if f, ok := form.(*huh.Form); ok {
		s.form = f
	}

	if s.form.State == huh.StateCompleted {
		if s.binaryPath == "" || s.namespaces == "" {
			return s, func() tea.Msg { return errMsg("Binary path and namespaces are required") }
		}
		return s, s.register()
	}

	if s.form.State == huh.StateAborted {
		return s, func() tea.Msg { return popScreenMsg{} }
	}

	return s, cmd
}

func (s *appRegisterScreen) register() tea.Cmd {
	bpath, name, nsStr, modeStr := s.binaryPath, s.name, s.namespaces, s.verifyMode
	return func() tea.Msg {
		nsList := strings.Split(nsStr, ",")
		for i := range nsList {
			nsList[i] = strings.TrimSpace(nsList[i])
		}

		var mode auth.VerifyMode
		switch modeStr {
		case "hash":
			mode = auth.VerifyHash
		case "signature":
			mode = auth.VerifySignature
		default:
			mode = auth.VerifyAuto
		}

		token, err := s.root.registry.Register(name, bpath, nsList, mode)
		if err != nil {
			return errMsg(fmt.Sprintf("Register failed: %v", err))
		}

		return replaceMsg{s: newTokenDisplayScreen(s.root, token)}
	}
}

func (s *appRegisterScreen) View() string {
	var b strings.Builder
	b.WriteString("\n")
	b.WriteString(titleStyle.Render("Register Application"))
	b.WriteString("\n")
	b.WriteString(s.form.View())
	return b.String()
}

// --- token display screen ---

type tokenDisplayScreen struct {
	root  *Model
	token string
}

func newTokenDisplayScreen(root *Model, token string) *tokenDisplayScreen {
	return &tokenDisplayScreen{root: root, token: token}
}

func (s *tokenDisplayScreen) Init() tea.Cmd { return nil }

func (s *tokenDisplayScreen) Update(msg tea.Msg) (screen, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		if msg.String() == "enter" || msg.String() == "esc" {
			return s, func() tea.Msg { return popScreenMsg{} }
		}
	}
	return s, nil
}

func (s *tokenDisplayScreen) View() string {
	var b strings.Builder
	b.WriteString("\n")
	b.WriteString(successStyle.Render("Application registered successfully!"))
	b.WriteString("\n\n")
	b.WriteString("  Save this token — it is shown only once:\n\n")
	b.WriteString(boxStyle.Render(s.token))
	b.WriteString("\n\n")
	b.WriteString(helpStyle.Render("  Press enter or esc to continue"))
	return b.String()
}

// --- update namespaces screen ---

type appUpdateNsScreen struct {
	root       *Model
	app        auth.AppRecord
	form       *huh.Form
	namespaces string
}

func newAppUpdateNsScreen(root *Model, app auth.AppRecord) *appUpdateNsScreen {
	s := &appUpdateNsScreen{
		root:       root,
		app:        app,
		namespaces: strings.Join(app.Namespaces, ", "),
	}
	s.form = huh.NewForm(
		huh.NewGroup(
			huh.NewInput().
				Title("Namespaces").
				Description("Comma-separated list of allowed namespaces").
				Value(&s.namespaces),
			huh.NewConfirm().
				Title("Update namespaces?").
				Affirmative("Update").
				Negative("Cancel"),
		),
	)
	return s
}

func (s *appUpdateNsScreen) Init() tea.Cmd {
	return s.form.Init()
}

func (s *appUpdateNsScreen) Update(msg tea.Msg) (screen, tea.Cmd) {
	form, cmd := s.form.Update(msg)
	if f, ok := form.(*huh.Form); ok {
		s.form = f
	}

	if s.form.State == huh.StateCompleted {
		return s, s.save()
	}

	if s.form.State == huh.StateAborted {
		return s, func() tea.Msg { return popScreenMsg{} }
	}

	return s, cmd
}

func (s *appUpdateNsScreen) save() tea.Cmd {
	id, nsStr := s.app.ID, s.namespaces
	return func() tea.Msg {
		nsList := strings.Split(nsStr, ",")
		for i := range nsList {
			nsList[i] = strings.TrimSpace(nsList[i])
		}
		if err := s.root.registry.UpdateNamespaces(id, nsList); err != nil {
			return errMsg(fmt.Sprintf("Update failed: %v", err))
		}
		return popScreenMsg{}
	}
}

func (s *appUpdateNsScreen) View() string {
	var b strings.Builder
	b.WriteString("\n")
	b.WriteString(titleStyle.Render(fmt.Sprintf("Update Namespaces: %s", s.app.Name)))
	b.WriteString("\n")
	b.WriteString(s.form.View())
	return b.String()
}
