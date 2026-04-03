package tui

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/spinner"
	tea "github.com/charmbracelet/bubbletea"

	"github.com/codewiresh/codewire/internal/platform"
)

type phaseState struct {
	phase   string
	message string
	status  string // started, completed, failed
	started time.Time
	elapsed time.Duration
}

type podStatusState struct {
	podName      string
	podStatus    string
	restartCount int
	logTail      string
}

// ProvisionResult is returned after the bubbletea program finishes.
type ProvisionResult struct {
	Failed bool
	Total  time.Duration
}

// provisionModel is the bubbletea model for the live provisioning timeline.
type provisionModel struct {
	phases    []phaseState
	podStatus *podStatusState
	startTime time.Time
	spinner   spinner.Model
	done      bool
	failed    bool
	eventCh   <-chan platform.ProvisionEvent
}

type provisionEventMsg platform.ProvisionEvent
type provisionDoneMsg struct{}

func newProvisionModel(ch <-chan platform.ProvisionEvent) provisionModel {
	s := spinner.New()
	s.Spinner = spinner.Dot
	return provisionModel{
		startTime: time.Now(),
		spinner:   s,
		eventCh:   ch,
	}
}

func (m provisionModel) Init() tea.Cmd {
	return tea.Batch(m.spinner.Tick, m.waitForEvent())
}

func (m provisionModel) waitForEvent() tea.Cmd {
	return func() tea.Msg {
		ev, ok := <-m.eventCh
		if !ok {
			return provisionDoneMsg{}
		}
		return provisionEventMsg(ev)
	}
}

func (m provisionModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		if msg.String() == "ctrl+c" || msg.String() == "q" {
			return m, tea.Quit
		}

	case provisionDoneMsg:
		m.done = true
		return m, tea.Quit

	case provisionEventMsg:
		ev := platform.ProvisionEvent(msg)
		m.handleEvent(ev)

		if (ev.Phase == "complete" && ev.Status == "completed") ||
			(ev.Phase == "error" && ev.Status == "failed") {
			m.done = true
			return m, tea.Quit
		}
		return m, m.waitForEvent()

	case spinner.TickMsg:
		var cmd tea.Cmd
		m.spinner, cmd = m.spinner.Update(msg)
		return m, cmd
	}

	return m, nil
}

func (m *provisionModel) handleEvent(ev platform.ProvisionEvent) {
	if ev.Phase == "pod_status" {
		m.handlePodStatus(ev)
		return
	}

	switch ev.Status {
	case "started":
		m.phases = append(m.phases, phaseState{
			phase:   ev.Phase,
			message: ev.Message,
			status:  "started",
			started: time.Now(),
		})
	case "completed":
		for i := len(m.phases) - 1; i >= 0; i-- {
			if m.phases[i].phase == ev.Phase && m.phases[i].status == "started" {
				m.phases[i].status = "completed"
				m.phases[i].elapsed = time.Since(m.phases[i].started)
				break
			}
		}
	case "failed":
		m.failed = true
		for i := len(m.phases) - 1; i >= 0; i-- {
			if m.phases[i].phase == ev.Phase {
				m.phases[i].status = "failed"
				m.phases[i].elapsed = time.Since(m.phases[i].started)
				break
			}
		}
	}
}

func (m *provisionModel) handlePodStatus(ev platform.ProvisionEvent) {
	var meta map[string]any
	if len(ev.Metadata) > 0 {
		json.Unmarshal(ev.Metadata, &meta)
	}
	if meta == nil {
		return
	}
	ps := &podStatusState{}
	if v, ok := meta["pod_name"].(string); ok {
		ps.podName = v
	}
	if v, ok := meta["pod_status"].(string); ok {
		ps.podStatus = v
	}
	if v, ok := meta["restart_count"].(float64); ok {
		ps.restartCount = int(v)
	}
	if v, ok := meta["log_tail"].(string); ok {
		ps.logTail = v
	}
	m.podStatus = ps
}

func (m provisionModel) View() string {
	var lines []string

	for _, p := range m.phases {
		var icon, timing string
		switch p.status {
		case "completed":
			icon = "  " + SuccessStyle.Render("✓")
			timing = fmt.Sprintf("%s", p.elapsed.Truncate(time.Second))
		case "failed":
			icon = "  " + ErrorStyle.Render("✗")
			timing = fmt.Sprintf("FAILED (%s)", p.elapsed.Truncate(time.Second))
		case "started":
			icon = "  " + WarningStyle.Render(m.spinner.View())
			timing = fmt.Sprintf("%s...", time.Since(p.started).Truncate(time.Second))
		}
		lines = append(lines, fmt.Sprintf("%s %-30s %s", icon, p.message, timing))
	}

	if m.podStatus != nil {
		lines = append(lines, "")
		lines = append(lines, fmt.Sprintf("  Pod: %s", m.podStatus.podName))
		statusLine := fmt.Sprintf("  Status: %s", m.podStatus.podStatus)
		if m.podStatus.restartCount > 0 {
			statusLine += fmt.Sprintf(" (%d restarts)", m.podStatus.restartCount)
		}
		lines = append(lines, statusLine)
		if m.podStatus.logTail != "" {
			logLines := strings.Split(m.podStatus.logTail, "\n")
			last := logLines[len(logLines)-1]
			if len(last) > 80 {
				last = last[:80] + "..."
			}
			lines = append(lines, fmt.Sprintf("  Last log: %s", last))
		}
	}

	return strings.Join(lines, "\n") + "\n"
}

// RunProvisionTimeline runs the provisioning timeline bubbletea program.
// It reads events from the channel and renders a live-updating timeline.
// Returns the result with failure status and total duration.
func RunProvisionTimeline(events <-chan platform.ProvisionEvent) (*ProvisionResult, error) {
	m := newProvisionModel(events)
	p := tea.NewProgram(m, tea.WithOutput(os.Stderr))

	finalModel, err := p.Run()
	if err != nil {
		return nil, err
	}

	fm := finalModel.(provisionModel)
	return &ProvisionResult{
		Failed: fm.failed,
		Total:  time.Since(fm.startTime).Truncate(time.Second),
	}, nil
}
