package tui

import (
	"fmt"
	"os"
	"strings"

	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
)

// --- Text Input ---

type inputModel struct {
	input      textinput.Model
	label      string
	defaultVal string
	submitted  bool
	cancelled  bool
}

func newInputModel(label, defaultVal string, echoMode textinput.EchoMode) inputModel {
	ti := textinput.New()
	ti.Focus()
	ti.EchoMode = echoMode
	if defaultVal != "" {
		ti.Placeholder = defaultVal
	}

	return inputModel{
		input:      ti,
		label:      label,
		defaultVal: defaultVal,
	}
}

func (m inputModel) Init() tea.Cmd {
	return textinput.Blink
}

func (m inputModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "enter":
			m.submitted = true
			return m, tea.Quit
		case "ctrl+c", "esc":
			m.cancelled = true
			return m, tea.Quit
		}
	}

	var cmd tea.Cmd
	m.input, cmd = m.input.Update(msg)
	return m, cmd
}

func (m inputModel) View() string {
	if m.defaultVal != "" {
		return fmt.Sprintf("%s [%s]: %s", m.label, m.defaultVal, m.input.View())
	}
	return fmt.Sprintf("%s: %s", m.label, m.input.View())
}

func (m inputModel) Value() string {
	val := strings.TrimSpace(m.input.Value())
	if val == "" {
		return m.defaultVal
	}
	return val
}

// Prompt runs a text input prompt and returns the entered value.
func Prompt(label string) (string, error) {
	return PromptDefault(label, "")
}

// PromptDefault runs a text input with a default value.
func PromptDefault(label, defaultVal string) (string, error) {
	m := newInputModel(label, defaultVal, textinput.EchoNormal)
	p := tea.NewProgram(m, tea.WithOutput(os.Stderr))

	finalModel, err := p.Run()
	if err != nil {
		return "", err
	}

	fm := finalModel.(inputModel)
	if fm.cancelled {
		return "", fmt.Errorf("interrupted")
	}
	return fm.Value(), nil
}

// PromptPassword runs a password input (no echo).
func PromptPassword(label string) (string, error) {
	m := newInputModel(label, "", textinput.EchoNone)
	p := tea.NewProgram(m, tea.WithOutput(os.Stderr))

	finalModel, err := p.Run()
	if err != nil {
		return "", err
	}

	fm := finalModel.(inputModel)
	if fm.cancelled {
		return "", fmt.Errorf("interrupted")
	}
	return strings.TrimSpace(fm.input.Value()), nil
}

// --- Selection ---

type selectModel struct {
	label   string
	options []string
	cursor  int
	chosen  bool
	cancelled bool
}

func (m selectModel) Init() tea.Cmd {
	return nil
}

func (m selectModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "up", "k":
			if m.cursor > 0 {
				m.cursor--
			}
		case "down", "j":
			if m.cursor < len(m.options)-1 {
				m.cursor++
			}
		case "enter":
			m.chosen = true
			return m, tea.Quit
		case "ctrl+c", "esc":
			m.cancelled = true
			return m, tea.Quit
		}
	}
	return m, nil
}

func (m selectModel) View() string {
	var b strings.Builder
	b.WriteString(m.label + "\n")
	for i, opt := range m.options {
		if i == m.cursor {
			b.WriteString(fmt.Sprintf("  %s %s\n", SuccessStyle.Render(">"), BoldStyle.Render(opt)))
		} else {
			b.WriteString(fmt.Sprintf("    %s\n", DimStyle.Render(opt)))
		}
	}
	return b.String()
}

// PromptSelect displays an interactive selection list with arrow keys.
// Returns the selected index.
func PromptSelect(label string, options []string) (int, error) {
	m := selectModel{
		label:   label,
		options: options,
	}
	p := tea.NewProgram(m, tea.WithOutput(os.Stderr))

	finalModel, err := p.Run()
	if err != nil {
		return 0, err
	}

	fm := finalModel.(selectModel)
	if fm.cancelled {
		return 0, fmt.Errorf("interrupted")
	}
	return fm.cursor, nil
}
