package tui

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/bubbles/spinner"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/huh"
	"github.com/charmbracelet/lipgloss"
)

// --- splash screen ---

type splashScreen struct {
	root    *Model
	spinner spinner.Model
	status  string
}

type storeCheckedMsg struct {
	initialized bool
	tpmMode     bool
	err         error
}

func newSplashScreen(root *Model) *splashScreen {
	sp := spinner.New()
	sp.Spinner = spinner.Dot
	sp.Style = lipgloss.NewStyle().Foreground(colorPrimary)
	return &splashScreen{root: root, spinner: sp, status: "Checking store..."}
}

func (s *splashScreen) Init() tea.Cmd {
	return tea.Batch(s.spinner.Tick, s.checkStore())
}

func (s *splashScreen) checkStore() tea.Cmd {
	return func() tea.Msg {
		initialized := s.root.store.IsInitialized()
		tpmMode := false
		if initialized {
			tpmMode = s.root.store.IsTPMMode()
		}
		return storeCheckedMsg{initialized: initialized, tpmMode: tpmMode}
	}
}

func (s *splashScreen) Update(msg tea.Msg) (screen, tea.Cmd) {
	switch msg := msg.(type) {
	case storeCheckedMsg:
		if msg.err != nil {
			return s, func() tea.Msg { return errMsg(fmt.Sprintf("Store error: %v", msg.err)) }
		}
		if !msg.initialized {
			return s, func() tea.Msg { return replaceMsg{s: newInitScreen(s.root)} }
		}
		if msg.tpmMode {
			// Auto-unlock with TPM
			return s, s.unlockTPM()
		}
		return s, func() tea.Msg { return replaceMsg{s: newUnlockScreen(s.root)} }

	case spinner.TickMsg:
		var cmd tea.Cmd
		s.spinner, cmd = s.spinner.Update(msg)
		return s, cmd
	}
	return s, nil
}

func (s *splashScreen) unlockTPM() tea.Cmd {
	return func() tea.Msg {
		if err := s.root.store.UnlockTPM(s.root.platform); err != nil {
			return errMsg(fmt.Sprintf("TPM unlock failed: %v", err))
		}
		return replaceMsg{s: newMenuScreen(s.root)}
	}
}

func (s *splashScreen) View() string {
	return fmt.Sprintf("\n  %s %s\n", s.spinner.View(), s.status)
}

// --- init screen ---

type initScreen struct {
	root   *Model
	form   *huh.Form
	method string
}

func newInitScreen(root *Model) *initScreen {
	s := &initScreen{root: root, method: "password"}
	hasTPM := root.platform.HasTPM()

	options := []huh.Option[string]{
		huh.NewOption("Password", "password"),
	}
	if hasTPM {
		options = append(options, huh.NewOption("TPM / Secure Enclave", "tpm"))
	}

	s.form = huh.NewForm(
		huh.NewGroup(
			huh.NewSelect[string]().
				Title("Initialize kvstore").
				Description("Choose how to protect your master key").
				Options(options...).
				Value(&s.method),
		),
	)

	return s
}

func (s *initScreen) Init() tea.Cmd {
	return s.form.Init()
}

func (s *initScreen) Update(msg tea.Msg) (screen, tea.Cmd) {
	form, cmd := s.form.Update(msg)
	if f, ok := form.(*huh.Form); ok {
		s.form = f
	}

	if s.form.State == huh.StateCompleted {
		if s.method == "tpm" {
			return s, s.initTPM()
		}
		return s, func() tea.Msg { return replaceMsg{s: newInitPasswordScreen(s.root)} }
	}

	return s, cmd
}

func (s *initScreen) initTPM() tea.Cmd {
	return func() tea.Msg {
		if err := s.root.store.InitTPM(s.root.platform); err != nil {
			return errMsg(fmt.Sprintf("TPM init failed: %v", err))
		}
		return replaceMsg{s: newMenuScreen(s.root)}
	}
}

func (s *initScreen) View() string {
	return "\n" + s.form.View()
}

// --- init password screen ---

type initPasswordScreen struct {
	root     *Model
	form     *huh.Form
	password string
	confirm  string
	errText  string
}

func newInitPasswordScreen(root *Model) *initPasswordScreen {
	s := &initPasswordScreen{root: root}
	s.buildForm()
	return s
}

func (s *initPasswordScreen) buildForm() {
	s.form = huh.NewForm(
		huh.NewGroup(
			huh.NewInput().
				Title("Master Password").
				Description("At least 8 characters").
				EchoMode(huh.EchoModePassword).
				Value(&s.password),
			huh.NewInput().
				Title("Confirm Password").
				EchoMode(huh.EchoModePassword).
				Value(&s.confirm),
			huh.NewConfirm().
				Title("Initialize store?").
				Affirmative("Initialize").
				Negative("Cancel"),
		),
	)
}

func (s *initPasswordScreen) Init() tea.Cmd {
	return s.form.Init()
}

func (s *initPasswordScreen) Update(msg tea.Msg) (screen, tea.Cmd) {
	form, cmd := s.form.Update(msg)
	if f, ok := form.(*huh.Form); ok {
		s.form = f
	}

	if s.form.State == huh.StateCompleted {
		if len(s.password) < 8 {
			s.errText = "Password must be at least 8 characters"
			s.password = ""
			s.confirm = ""
			s.buildForm()
			return s, s.form.Init()
		}
		if s.password != s.confirm {
			s.errText = "Passwords do not match"
			s.password = ""
			s.confirm = ""
			s.buildForm()
			return s, s.form.Init()
		}
		return s, s.doInit()
	}

	if s.form.State == huh.StateAborted {
		return s, func() tea.Msg { return replaceMsg{s: newInitScreen(s.root)} }
	}

	return s, cmd
}

func (s *initPasswordScreen) doInit() tea.Cmd {
	pw := s.password
	return func() tea.Msg {
		if err := s.root.store.Init([]byte(pw)); err != nil {
			return errMsg(fmt.Sprintf("Init failed: %v", err))
		}
		return replaceMsg{s: newMenuScreen(s.root)}
	}
}

func (s *initPasswordScreen) View() string {
	var b strings.Builder
	b.WriteString("\n")
	b.WriteString(titleStyle.Render("Initialize Store"))
	b.WriteString("\n")
	if s.errText != "" {
		b.WriteString(errorStyle.Render(s.errText))
		b.WriteString("\n\n")
	}
	b.WriteString(s.form.View())
	return b.String()
}

// --- unlock screen ---

type unlockScreen struct {
	root     *Model
	form     *huh.Form
	password string
	errText  string
}

func newUnlockScreen(root *Model) *unlockScreen {
	s := &unlockScreen{root: root}
	s.buildForm()
	return s
}

func (s *unlockScreen) buildForm() {
	s.form = huh.NewForm(
		huh.NewGroup(
			huh.NewInput().
				Title("Master Password").
				Description("Enter your master password to unlock").
				EchoMode(huh.EchoModePassword).
				Value(&s.password),
		),
	)
}

func (s *unlockScreen) Init() tea.Cmd {
	return s.form.Init()
}

func (s *unlockScreen) Update(msg tea.Msg) (screen, tea.Cmd) {
	switch msg := msg.(type) {
	case unlockFailedMsg:
		s.errText = fmt.Sprintf("Unlock failed: %v", msg.err)
		s.password = ""
		s.buildForm()
		return s, s.form.Init()
	default:
		_ = msg
	}

	form, cmd := s.form.Update(msg)
	if f, ok := form.(*huh.Form); ok {
		s.form = f
	}

	if s.form.State == huh.StateCompleted {
		return s, s.doUnlock()
	}

	if s.form.State == huh.StateAborted {
		return s, tea.Quit
	}

	return s, cmd
}

func (s *unlockScreen) doUnlock() tea.Cmd {
	pw := s.password
	return func() tea.Msg {
		if err := s.root.store.Unlock([]byte(pw)); err != nil {
			return unlockFailedMsg{err: err}
		}
		return replaceMsg{s: newMenuScreen(s.root)}
	}
}

type unlockFailedMsg struct{ err error }

func (s *unlockScreen) View() string {
	var b strings.Builder
	b.WriteString("\n")
	b.WriteString(titleStyle.Render("kvstore"))
	b.WriteString("\n")
	if s.errText != "" {
		b.WriteString(errorStyle.Render(s.errText))
		b.WriteString("\n\n")
	}
	b.WriteString(s.form.View())
	b.WriteString("\n")
	b.WriteString(helpStyle.Render("Ctrl+C to quit"))
	return b.String()
}
