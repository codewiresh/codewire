package statusbar

import (
	"fmt"
	"os"
	"time"

	"github.com/charmbracelet/lipgloss"
)

var barStyle = lipgloss.NewRenderer(os.Stdout).NewStyle().Reverse(true)

type StatusBar struct {
	SessionID uint32
	Status    string
	Started   time.Time
	Rows      uint16
	Cols      uint16
	Enabled   bool
}

func New(sessionID uint32, cols, rows uint16) *StatusBar {
	return &StatusBar{
		SessionID: sessionID,
		Status:    "running",
		Started:   time.Now(),
		Rows:      rows,
		Cols:      cols,
		Enabled:   rows >= 5,
	}
}

// PtySize returns the PTY size to report to the node.
// One row shorter when the status bar is enabled.
func (s *StatusBar) PtySize() (cols, rows uint16) {
	if s.Enabled {
		return s.Cols, s.Rows - 1
	}
	return s.Cols, s.Rows
}

// Setup sets the scroll region and draws the initial status bar.
func (s *StatusBar) Setup() []byte {
	if !s.Enabled {
		return nil
	}
	var out []byte
	// Set scroll region to rows 1..(Rows-1), protecting the last row for the bar.
	out = append(out, fmt.Sprintf("\x1b[1;%dr", s.Rows-1)...)
	// Move cursor to top-left of scroll region.
	out = append(out, "\x1b[H"...)
	out = append(out, s.Draw()...)
	return out
}

// Teardown cleans up terminal state. Mode resets are ALWAYS emitted
// even when bar is disabled (child process can hide cursor etc).
func (s *StatusBar) Teardown() []byte {
	var out []byte
	// Exit alternate screen
	out = append(out, "\x1b[?1049l"...)
	// Show cursor
	out = append(out, "\x1b[?25h"...)
	// Pop Kitty keyboard mode
	out = append(out, "\x1b[<u"...)
	// Disable focus event reporting
	out = append(out, "\x1b[?1004l"...)
	// Disable mouse tracking
	out = append(out, "\x1b[?1000l"...)
	// Disable SGR mouse encoding
	out = append(out, "\x1b[?1006l"...)

	// Bar-specific cleanup
	if s.Enabled {
		// Reset scroll region to full terminal.
		out = append(out, "\x1b[r"...)
		// Save cursor
		out = append(out, "\x1b7"...)
		// Move to status bar row and clear it
		out = append(out, fmt.Sprintf("\x1b[%d;1H", s.Rows)...)
		out = append(out, "\x1b[2K"...)
		// Restore cursor
		out = append(out, "\x1b8"...)
	}
	return out
}

// Draw renders the status bar (save cursor, render, restore cursor).
func (s *StatusBar) Draw() []byte {
	if !s.Enabled {
		return nil
	}
	elapsed := time.Since(s.Started)
	age := formatDuration(uint64(elapsed.Seconds()))

	content := fmt.Sprintf(" [cw] session %d | %s | %s | Ctrl+B d",
		s.SessionID, s.Status, age)

	// Pad or truncate to fill the row
	cols := int(s.Cols)
	var padded string
	if len(content) >= cols {
		padded = content[:cols]
	} else {
		padded = fmt.Sprintf("%-*s", cols, content)
	}

	var out []byte
	// Save cursor
	out = append(out, "\x1b7"...)
	// Move to status bar row (last row)
	out = append(out, fmt.Sprintf("\x1b[%d;1H", s.Rows)...)
	// Reverse video + content
	out = append(out, barStyle.Render(padded)...)
	// Restore cursor
	out = append(out, "\x1b8"...)
	return out
}

// Resize updates dimensions, resets the scroll region, and redraws.
func (s *StatusBar) Resize(cols, rows uint16) []byte {
	s.Cols = cols
	s.Rows = rows
	s.Enabled = rows >= 5
	if !s.Enabled {
		return nil
	}
	var out []byte
	// Update scroll region for new dimensions.
	out = append(out, fmt.Sprintf("\x1b[1;%dr", s.Rows-1)...)
	out = append(out, s.Draw()...)
	return out
}

func formatDuration(secs uint64) string {
	if secs < 60 {
		return fmt.Sprintf("%ds", secs)
	}
	if secs < 3600 {
		return fmt.Sprintf("%dm", secs/60)
	}
	return fmt.Sprintf("%dh%dm", secs/3600, (secs%3600)/60)
}
