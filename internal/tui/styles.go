package tui

import "github.com/charmbracelet/lipgloss"

var (
	// Colors
	colorPrimary   = lipgloss.Color("#7C3AED") // purple
	colorSuccess   = lipgloss.Color("#10B981") // green
	colorError     = lipgloss.Color("#EF4444") // red
	colorMuted     = lipgloss.Color("#6B7280") // gray
	colorBorder    = lipgloss.Color("#4B5563") // gray-600
	colorHighlight = lipgloss.Color("#A78BFA") // purple-light

	// Title style
	titleStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(colorPrimary).
			MarginBottom(1)

	// Selected item in lists
	selectedStyle = lipgloss.NewStyle().
			Foreground(colorHighlight).
			Bold(true)

	// Error bar at bottom
	errorStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#FFFFFF")).
			Background(colorError).
			Padding(0, 1).
			Bold(true)

	// Success message
	successStyle = lipgloss.NewStyle().
			Foreground(colorSuccess).
			Bold(true)

	// Help text at bottom
	helpStyle = lipgloss.NewStyle().
			Foreground(colorMuted)

	// Box border
	boxStyle = lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(colorBorder).
			Padding(1, 2)

	// Detail label
	labelStyle = lipgloss.NewStyle().
			Foreground(colorMuted).
			Width(14)

	// Detail value
	valueStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#E5E7EB"))
)
