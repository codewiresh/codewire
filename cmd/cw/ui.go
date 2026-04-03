package main

import (
	"fmt"
	"os"
	"text/tabwriter"

	"github.com/charmbracelet/lipgloss"
)

var (
	stdoutRenderer = lipgloss.NewRenderer(os.Stdout)
	stderrRenderer = lipgloss.NewRenderer(os.Stderr)

	boldStyle   = stdoutRenderer.NewStyle().Bold(true)
	dimStyle    = stdoutRenderer.NewStyle().Faint(true)
	greenStyle  = stdoutRenderer.NewStyle().Foreground(lipgloss.Color("2"))
	redStyle    = stdoutRenderer.NewStyle().Foreground(lipgloss.Color("1"))
	yellowStyle = stdoutRenderer.NewStyle().Foreground(lipgloss.Color("3"))

	greenErrStyle  = stderrRenderer.NewStyle().Foreground(lipgloss.Color("2"))
	redErrStyle    = stderrRenderer.NewStyle().Foreground(lipgloss.Color("1"))
	yellowErrStyle = stderrRenderer.NewStyle().Foreground(lipgloss.Color("3"))
)

func bold(s string) string   { return boldStyle.Render(s) }
func dim(s string) string    { return dimStyle.Render(s) }
func green(s string) string  { return greenStyle.Render(s) }
func red(s string) string    { return redStyle.Render(s) }
func yellow(s string) string { return yellowStyle.Render(s) }

func greenErr(s string) string  { return greenErrStyle.Render(s) }
func redErr(s string) string    { return redErrStyle.Render(s) }
func yellowErr(s string) string { return yellowErrStyle.Render(s) }

// stateColor applies color to a state label for stdout.
func stateColor(state string) string {
	switch state {
	case "running", "started", "healthy":
		return green(state)
	case "error", "failed", "unhealthy":
		return red(state)
	case "creating", "pending", "provisioning", "starting", "stopping":
		return yellow(state)
	case "stopped", "destroyed":
		return dim(state)
	default:
		return state
	}
}

// successMsg prints "  ✓ message" to stderr with a green checkmark.
func successMsg(format string, args ...any) {
	msg := fmt.Sprintf(format, args...)
	fmt.Fprintf(os.Stderr, "  %s %s\n", greenErr("✓"), msg)
}

// tableHeader writes a bold header row to a tabwriter (stdout).
func tableHeader(w *tabwriter.Writer, cols ...string) {
	bolded := make([]string, len(cols))
	for i, c := range cols {
		bolded[i] = bold(c)
	}
	for i, c := range bolded {
		if i > 0 {
			fmt.Fprint(w, "\t")
		}
		fmt.Fprint(w, c)
	}
	fmt.Fprintln(w)
}
