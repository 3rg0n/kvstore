package tui

import (
	"fmt"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/list"
	"github.com/charmbracelet/bubbles/viewport"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/huh"
)

// --- namespace browser ---

type namespaceScreen struct {
	root *Model
	list list.Model
}

type namespacesLoadedMsg struct {
	namespaces []string
	err        error
}

func newNamespaceScreen(root *Model) *namespaceScreen {
	l := list.New(nil, menuDelegate{}, 50, 15)
	l.Title = "Namespaces"
	l.SetShowStatusBar(false)
	l.SetFilteringEnabled(false)
	l.SetShowHelp(false)
	l.Styles.Title = titleStyle
	return &namespaceScreen{root: root, list: l}
}

func (s *namespaceScreen) Init() tea.Cmd {
	return s.loadNamespaces()
}

func (s *namespaceScreen) loadNamespaces() tea.Cmd {
	return func() tea.Msg {
		ns, err := s.root.store.ListNamespaces()
		return namespacesLoadedMsg{namespaces: ns, err: err}
	}
}

func (s *namespaceScreen) Update(msg tea.Msg) (screen, tea.Cmd) {
	switch msg := msg.(type) {
	case namespacesLoadedMsg:
		if msg.err != nil {
			return s, func() tea.Msg { return errMsg(fmt.Sprintf("Load namespaces: %v", msg.err)) }
		}
		items := make([]list.Item, len(msg.namespaces))
		for i, ns := range msg.namespaces {
			items[i] = menuItem{title: ns}
		}
		s.list.SetItems(items)
		return s, nil

	case tea.KeyMsg:
		switch msg.String() {
		case "enter":
			item, ok := s.list.SelectedItem().(menuItem)
			if !ok {
				return s, nil
			}
			return s, func() tea.Msg {
				return pushScreenMsg{s: newKeyListScreen(s.root, item.title)}
			}
		case "n":
			return s, func() tea.Msg {
				return pushScreenMsg{s: newNewKeyScreen(s.root, "", true)}
			}
		}
	}

	var cmd tea.Cmd
	s.list, cmd = s.list.Update(msg)
	return s, cmd
}

func (s *namespaceScreen) View() string {
	var b strings.Builder
	b.WriteString("\n")
	b.WriteString(s.list.View())
	if len(s.list.Items()) == 0 {
		b.WriteString("\n  No namespaces yet. Press [n] to create one.\n")
	}
	b.WriteString("\n")
	b.WriteString(helpStyle.Render("  enter open • n new • esc back"))
	return b.String()
}

// --- key list ---

type keyListScreen struct {
	root      *Model
	namespace string
	list      list.Model
}

type keysLoadedMsg struct {
	keys []string
	err  error
}

func newKeyListScreen(root *Model, namespace string) *keyListScreen {
	l := list.New(nil, menuDelegate{}, 50, 15)
	l.Title = fmt.Sprintf("Keys in '%s'", namespace)
	l.SetShowStatusBar(false)
	l.SetFilteringEnabled(false)
	l.SetShowHelp(false)
	l.Styles.Title = titleStyle
	return &keyListScreen{root: root, namespace: namespace, list: l}
}

func (s *keyListScreen) Init() tea.Cmd {
	return s.loadKeys()
}

func (s *keyListScreen) loadKeys() tea.Cmd {
	ns := s.namespace
	return func() tea.Msg {
		keys, err := s.root.store.List(ns)
		return keysLoadedMsg{keys: keys, err: err}
	}
}

func (s *keyListScreen) Update(msg tea.Msg) (screen, tea.Cmd) {
	switch msg := msg.(type) {
	case keysLoadedMsg:
		if msg.err != nil {
			return s, func() tea.Msg { return errMsg(fmt.Sprintf("Load keys: %v", msg.err)) }
		}
		items := make([]list.Item, len(msg.keys))
		for i, k := range msg.keys {
			items[i] = menuItem{title: k}
		}
		s.list.SetItems(items)
		return s, nil

	case keyDeletedMsg:
		return s, s.loadKeys()

	case tea.KeyMsg:
		switch msg.String() {
		case "enter", "v":
			item, ok := s.list.SelectedItem().(menuItem)
			if !ok {
				return s, nil
			}
			return s, func() tea.Msg {
				return pushScreenMsg{s: newValueViewScreen(s.root, s.namespace, item.title)}
			}
		case "e":
			item, ok := s.list.SelectedItem().(menuItem)
			if !ok {
				return s, nil
			}
			return s, func() tea.Msg {
				return pushScreenMsg{s: newValueEditScreen(s.root, s.namespace, item.title)}
			}
		case "d":
			item, ok := s.list.SelectedItem().(menuItem)
			if !ok {
				return s, nil
			}
			return s, s.deleteKey(item.title)
		case "+", "n":
			return s, func() tea.Msg {
				return pushScreenMsg{s: newNewKeyScreen(s.root, s.namespace, false)}
			}
		}
	}

	var cmd tea.Cmd
	s.list, cmd = s.list.Update(msg)
	return s, cmd
}

type keyDeletedMsg struct{}

func (s *keyListScreen) deleteKey(key string) tea.Cmd {
	ns := s.namespace
	return func() tea.Msg {
		if err := s.root.store.Delete(ns, key); err != nil {
			return errMsg(fmt.Sprintf("Delete failed: %v", err))
		}
		return keyDeletedMsg{}
	}
}

func (s *keyListScreen) View() string {
	var b strings.Builder
	b.WriteString("\n")
	b.WriteString(s.list.View())
	if len(s.list.Items()) == 0 {
		b.WriteString("\n  No keys in this namespace. Press [+] to add one.\n")
	}
	b.WriteString("\n")
	b.WriteString(helpStyle.Render("  enter/v view • e edit • d delete • + new • esc back"))
	return b.String()
}

// --- value view ---

type valueViewScreen struct {
	root      *Model
	namespace string
	key       string
	viewport  viewport.Model
	content   string
	ready     bool
}

type valueLoadedMsg struct {
	value     string
	createdAt time.Time
	updatedAt time.Time
	err       error
}

func newValueViewScreen(root *Model, namespace, key string) *valueViewScreen {
	return &valueViewScreen{root: root, namespace: namespace, key: key}
}

func (s *valueViewScreen) Init() tea.Cmd {
	ns, k := s.namespace, s.key
	return func() tea.Msg {
		entry, err := s.root.store.Get(ns, k)
		if err != nil {
			return valueLoadedMsg{err: err}
		}
		return valueLoadedMsg{
			value:     string(entry.Value),
			createdAt: entry.CreatedAt,
			updatedAt: entry.UpdatedAt,
		}
	}
}

func (s *valueViewScreen) Update(msg tea.Msg) (screen, tea.Cmd) {
	switch msg := msg.(type) {
	case valueLoadedMsg:
		if msg.err != nil {
			return s, func() tea.Msg { return errMsg(fmt.Sprintf("Get value: %v", msg.err)) }
		}
		var b strings.Builder
		b.WriteString(labelStyle.Render("Namespace:") + " " + valueStyle.Render(s.namespace) + "\n")
		b.WriteString(labelStyle.Render("Key:") + " " + valueStyle.Render(s.key) + "\n")
		b.WriteString(labelStyle.Render("Created:") + " " + valueStyle.Render(msg.createdAt.Format(time.RFC3339)) + "\n")
		b.WriteString(labelStyle.Render("Updated:") + " " + valueStyle.Render(msg.updatedAt.Format(time.RFC3339)) + "\n")
		b.WriteString("\n")
		b.WriteString(labelStyle.Render("Value:") + "\n")
		b.WriteString(msg.value)
		s.content = b.String()

		s.viewport = viewport.New(60, 15)
		s.viewport.SetContent(s.content)
		s.ready = true
		return s, nil

	case tea.KeyMsg:
		switch msg.String() {
		case "e":
			return s, func() tea.Msg {
				return replaceMsg{s: newValueEditScreen(s.root, s.namespace, s.key)}
			}
		}
	}

	if s.ready {
		var cmd tea.Cmd
		s.viewport, cmd = s.viewport.Update(msg)
		return s, cmd
	}
	return s, nil
}

func (s *valueViewScreen) View() string {
	if !s.ready {
		return "\n  Loading..."
	}
	var b strings.Builder
	b.WriteString("\n")
	b.WriteString(titleStyle.Render(fmt.Sprintf("%s/%s", s.namespace, s.key)))
	b.WriteString("\n")
	b.WriteString(s.viewport.View())
	b.WriteString("\n\n")
	b.WriteString(helpStyle.Render("  e edit • ↑/↓ scroll • esc back"))
	return b.String()
}

// --- value edit ---

type valueEditScreen struct {
	root      *Model
	namespace string
	key       string
	value     string
	form      *huh.Form
	loaded    bool
}

func newValueEditScreen(root *Model, namespace, key string) *valueEditScreen {
	return &valueEditScreen{root: root, namespace: namespace, key: key}
}

func (s *valueEditScreen) Init() tea.Cmd {
	ns, k := s.namespace, s.key
	return func() tea.Msg {
		entry, err := s.root.store.Get(ns, k)
		if err != nil {
			return valueLoadedMsg{err: err}
		}
		return valueLoadedMsg{value: string(entry.Value)}
	}
}

func (s *valueEditScreen) buildForm() {
	s.form = huh.NewForm(
		huh.NewGroup(
			huh.NewText().
				Title(fmt.Sprintf("Edit %s/%s", s.namespace, s.key)).
				Value(&s.value),
			huh.NewConfirm().
				Title("Save?").
				Affirmative("Save").
				Negative("Cancel"),
		),
	)
}

func (s *valueEditScreen) Update(msg tea.Msg) (screen, tea.Cmd) {
	switch msg := msg.(type) {
	case valueLoadedMsg:
		if msg.err != nil {
			return s, func() tea.Msg {
				return errMsg(fmt.Sprintf("Load value: %v", msg.err))
			}
		}
		s.value = msg.value
		s.loaded = true
		s.buildForm()
		return s, s.form.Init()
	default:
		_ = msg
	}

	if !s.loaded || s.form == nil {
		return s, nil
	}

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

func (s *valueEditScreen) save() tea.Cmd {
	ns, k, v := s.namespace, s.key, s.value
	return func() tea.Msg {
		if err := s.root.store.Set(ns, k, []byte(v)); err != nil {
			return errMsg(fmt.Sprintf("Save failed: %v", err))
		}
		return replaceMsg{s: newValueViewScreen(s.root, ns, k)}
	}
}

func (s *valueEditScreen) View() string {
	if !s.loaded {
		return "\n  Loading..."
	}
	return "\n" + s.form.View()
}

// --- new key ---

type newKeyScreen struct {
	root         *Model
	namespace    string
	key          string
	value        string
	newNamespace bool // if true, also prompt for namespace name
	form         *huh.Form
}

func newNewKeyScreen(root *Model, namespace string, newNamespace bool) *newKeyScreen {
	s := &newKeyScreen{root: root, namespace: namespace, newNamespace: newNamespace}
	s.buildForm()
	return s
}

func (s *newKeyScreen) buildForm() {
	var groups []*huh.Group

	if s.newNamespace {
		groups = append(groups, huh.NewGroup(
			huh.NewInput().
				Title("Namespace").
				Description("Name for the new namespace").
				Value(&s.namespace),
		))
	}

	groups = append(groups, huh.NewGroup(
		huh.NewInput().
			Title("Key").
			Value(&s.key),
		huh.NewText().
			Title("Value").
			Value(&s.value),
		huh.NewConfirm().
			Title("Save?").
			Affirmative("Save").
			Negative("Cancel"),
	))

	s.form = huh.NewForm(groups...)
}

func (s *newKeyScreen) Init() tea.Cmd {
	return s.form.Init()
}

func (s *newKeyScreen) Update(msg tea.Msg) (screen, tea.Cmd) {
	form, cmd := s.form.Update(msg)
	if f, ok := form.(*huh.Form); ok {
		s.form = f
	}

	if s.form.State == huh.StateCompleted {
		if s.namespace == "" || s.key == "" {
			return s, func() tea.Msg { return errMsg("Namespace and key are required") }
		}
		return s, s.save()
	}

	if s.form.State == huh.StateAborted {
		return s, func() tea.Msg { return popScreenMsg{} }
	}

	return s, cmd
}

func (s *newKeyScreen) save() tea.Cmd {
	ns, k, v := s.namespace, s.key, s.value
	return func() tea.Msg {
		if err := s.root.store.Set(ns, k, []byte(v)); err != nil {
			return errMsg(fmt.Sprintf("Save failed: %v", err))
		}
		return popScreenMsg{}
	}
}

func (s *newKeyScreen) View() string {
	title := "New Key"
	if s.newNamespace {
		title = "New Namespace + Key"
	}
	var b strings.Builder
	b.WriteString("\n")
	b.WriteString(titleStyle.Render(title))
	b.WriteString("\n")
	b.WriteString(s.form.View())
	return b.String()
}
