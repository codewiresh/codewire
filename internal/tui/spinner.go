package tui

import (
	"fmt"
	"os"
	"time"

	"github.com/charmbracelet/bubbles/spinner"
	tea "github.com/charmbracelet/bubbletea"
)

// PollFunc is called on each tick. Return done=true to stop polling.
// result is displayed on completion; err causes the spinner to stop with an error.
type PollFunc func() (done bool, result string, err error)

// PollResult holds the outcome of a polling spinner.
type PollResult struct {
	Result string
	Err    error
}

type pollModel struct {
	spinner  spinner.Model
	message  string
	start    time.Time
	interval time.Duration
	pollFn   PollFunc
	result   string
	err      error
	done     bool
}

type pollTickMsg struct{}
type pollResultMsg struct {
	done   bool
	result string
	err    error
}

func newPollModel(message string, interval time.Duration, fn PollFunc) pollModel {
	s := spinner.New()
	s.Spinner = spinner.Dot
	return pollModel{
		spinner:  s,
		message:  message,
		start:    time.Now(),
		interval: interval,
		pollFn:   fn,
	}
}

func (m pollModel) Init() tea.Cmd {
	return tea.Batch(m.spinner.Tick, m.schedulePoll())
}

func (m pollModel) schedulePoll() tea.Cmd {
	return tea.Tick(m.interval, func(time.Time) tea.Msg {
		return pollTickMsg{}
	})
}

func (m pollModel) doPoll() tea.Cmd {
	return func() tea.Msg {
		done, result, err := m.pollFn()
		return pollResultMsg{done: done, result: result, err: err}
	}
}

func (m pollModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		if msg.String() == "ctrl+c" {
			m.err = fmt.Errorf("interrupted")
			return m, tea.Quit
		}

	case pollTickMsg:
		return m, m.doPoll()

	case pollResultMsg:
		if msg.err != nil {
			m.err = msg.err
			m.done = true
			return m, tea.Quit
		}
		if msg.done {
			m.result = msg.result
			m.done = true
			return m, tea.Quit
		}
		return m, m.schedulePoll()

	case spinner.TickMsg:
		var cmd tea.Cmd
		m.spinner, cmd = m.spinner.Update(msg)
		return m, cmd
	}

	return m, nil
}

func (m pollModel) View() string {
	elapsed := time.Since(m.start).Truncate(time.Second)
	return fmt.Sprintf("  %s %s %s\n", m.spinner.View(), m.message, DimStyle.Render(elapsed.String()))
}

// RunSpinner runs a polling spinner that calls pollFn at the given interval.
// The spinner displays the message and elapsed time. It stops when pollFn
// returns done=true or an error.
func RunSpinner(message string, interval time.Duration, pollFn PollFunc) (*PollResult, error) {
	m := newPollModel(message, interval, pollFn)
	p := tea.NewProgram(m, tea.WithOutput(os.Stderr))

	finalModel, err := p.Run()
	if err != nil {
		return nil, err
	}

	fm := finalModel.(pollModel)
	return &PollResult{
		Result: fm.result,
		Err:    fm.err,
	}, nil
}
