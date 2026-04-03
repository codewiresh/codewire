package tui

import (
	"os"

	"github.com/charmbracelet/lipgloss"
)

var (
	renderer = lipgloss.NewRenderer(os.Stderr)

	SuccessStyle = renderer.NewStyle().Foreground(lipgloss.Color("2"))
	ErrorStyle   = renderer.NewStyle().Foreground(lipgloss.Color("1"))
	WarningStyle = renderer.NewStyle().Foreground(lipgloss.Color("3"))
	DimStyle     = renderer.NewStyle().Faint(true)
	BoldStyle    = renderer.NewStyle().Bold(true)
)
