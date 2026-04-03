package main

import (
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/spf13/cobra"

	"github.com/codewiresh/codewire/internal/platform"
)

func resourceStatusCmd() *cobra.Command {
	var jsonOutput bool
	var follow bool

	cmd := &cobra.Command{
		Use:   "status <resource-id-or-slug>",
		Short: "Show provisioning status and events for a resource",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			client, err := platform.NewClient()
			if err != nil {
				return err
			}

			resource, err := client.GetResource(args[0])
			if err != nil {
				return fmt.Errorf("get resource: %w", err)
			}

			if jsonOutput {
				events, err := client.GetProvisionEvents(resource.ID)
				if err != nil {
					return fmt.Errorf("get events: %w", err)
				}
				enc := json.NewEncoder(os.Stdout)
				enc.SetIndent("", "  ")
				return enc.Encode(map[string]any{
					"resource": resource,
					"events":   events,
				})
			}

			fmt.Printf("Resource: %s (%s)\n", resource.Name, resource.Type)
			fmt.Printf("Status:   %s\n", resource.Status)
			if resource.ProvisionPhase != "" {
				fmt.Printf("Phase:    %s\n", resource.ProvisionPhase)
			}
			fmt.Println()

			// If following and resource is transitioning, use SSE
			if follow && (resource.Status == "provisioning" || resource.Status == "pending") {
				events := make(chan platform.ProvisionEvent, 64)
				if err := client.StreamProvisionEvents(resource.ID, events); err != nil {
					return fmt.Errorf("stream events: %w", err)
				}
				_, err := runProvisionTimeline(events)
				return err
			}

			// Static display: fetch and render events
			events, err := client.GetProvisionEvents(resource.ID)
			if err != nil {
				// Server may not support this endpoint yet
				if resource.ProvisionError != "" {
					fmt.Printf("  Error: %s\n", resource.ProvisionError)
				}
				return nil
			}

			if len(events) == 0 {
				fmt.Println("  No provisioning events recorded.")
				return nil
			}

			renderStaticTimeline(events)

			if resource.ProvisionError != "" {
				fmt.Printf("\n  Error: %s\n", resource.ProvisionError)
			}

			return nil
		},
	}

	cmd.Flags().BoolVarP(&jsonOutput, "json", "j", false, "Output as JSON")
	cmd.Flags().BoolVarP(&follow, "follow", "f", false, "Follow live provisioning events")
	return cmd
}

func renderStaticTimeline(events []platform.ProvisionEvent) {
	type phaseInfo struct {
		message string
		status  string
		started time.Time
		elapsed time.Duration
	}
	phases := make(map[string]*phaseInfo)
	var order []string

	for _, ev := range events {
		if ev.Phase == "pod_status" {
			continue
		}
		ts, _ := time.Parse(time.RFC3339, ev.CreatedAt)

		if ev.Status == "started" {
			p := &phaseInfo{message: ev.Message, status: "started", started: ts}
			phases[ev.Phase] = p
			order = append(order, ev.Phase)
		} else if pi, ok := phases[ev.Phase]; ok {
			pi.status = ev.Status
			pi.elapsed = ts.Sub(pi.started)
		}
	}

	for _, phase := range order {
		pi := phases[phase]
		var icon, timing string
		switch pi.status {
		case "completed":
			icon = "  " + green("✓")
			timing = fmt.Sprintf("%s", pi.elapsed.Truncate(time.Second))
		case "failed":
			icon = "  " + red("✗")
			timing = fmt.Sprintf("FAILED (%s)", pi.elapsed.Truncate(time.Second))
		default:
			icon = "  " + yellow("◌")
			timing = "(in progress)"
		}
		fmt.Printf("%s %-30s %s\n", icon, pi.message, timing)
	}

	// Show last pod status event
	var lastPod *platform.ProvisionEvent
	for i := len(events) - 1; i >= 0; i-- {
		if events[i].Phase == "pod_status" {
			lastPod = &events[i]
			break
		}
	}
	if lastPod != nil {
		var meta map[string]any
		json.Unmarshal(lastPod.Metadata, &meta)
		if meta != nil {
			fmt.Println()
			if v, ok := meta["pod_name"].(string); ok {
				fmt.Printf("  Pod: %s\n", v)
			}
			statusLine := ""
			if v, ok := meta["pod_status"].(string); ok {
				statusLine = v
			}
			if v, ok := meta["restart_count"].(float64); ok && v > 0 {
				statusLine += fmt.Sprintf(" (%d restarts)", int(v))
			}
			if statusLine != "" {
				fmt.Printf("  Status: %s\n", statusLine)
			}
			if v, ok := meta["log_tail"].(string); ok && v != "" {
				fmt.Printf("  Last log: %s\n", v)
			}
		}
	}
}
