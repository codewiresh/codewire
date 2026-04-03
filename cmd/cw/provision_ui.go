package main

import (
	"github.com/codewiresh/codewire/internal/platform"
	"github.com/codewiresh/codewire/internal/tui"
)

// runProvisionTimeline runs the bubbletea provisioning timeline.
func runProvisionTimeline(events <-chan platform.ProvisionEvent) (*tui.ProvisionResult, error) {
	return tui.RunProvisionTimeline(events)
}
