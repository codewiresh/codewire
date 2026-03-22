package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"sync"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/codewiresh/codewire/internal/client"
	"github.com/codewiresh/codewire/internal/platform"
	"github.com/codewiresh/codewire/internal/protocol"
)

type platformListEntry struct {
	Environment   platform.Environment   `json:"environment"`
	Sessions      []protocol.SessionInfo `json:"sessions,omitempty"`
	SessionLookup string                 `json:"session_lookup,omitempty"`
	SessionError  string                 `json:"session_error,omitempty"`
}

func platformListCmd() *cobra.Command {
	var jsonOutput bool
	var statusFilter string
	var localOnly bool
	var includeRuns bool

	cmd := &cobra.Command{
		Use:   "list",
		Short: "List environments and runs",
		Long: "In platform mode: show environments in the current org and runs inside running sandbox environments.\n" +
			"In standalone mode: list local sessions.",
		RunE: func(cmd *cobra.Command, args []string) error {
			if localOnly || !platform.HasConfig() {
				target, err := resolveTarget()
				if err != nil {
					return err
				}
				if target.IsLocal() {
					if err := ensureNode(); err != nil {
						return err
					}
				}
				return client.List(target, jsonOutput, statusFilter)
			}

			orgID, pc, err := getOrgContext(cmd)
			if err != nil {
				return err
			}

			envs, err := pc.ListEnvironments(orgID, "", "", false)
			if err != nil {
				return fmt.Errorf("list environments: %w", err)
			}

			entries := listPlatformEntries(pc, orgID, envs, includeRuns)

			if jsonOutput {
				enc := json.NewEncoder(os.Stdout)
				enc.SetIndent("", "  ")
				return enc.Encode(struct {
					Environments []platformListEntry `json:"environments"`
				}{
					Environments: entries,
				})
			}

			if len(entries) == 0 {
				fmt.Println("No environments.")
				return nil
			}

			return printPlatformEntries(entries)
		},
	}

	cmd.Flags().BoolVarP(&jsonOutput, "json", "j", false, "Output as JSON")
	cmd.Flags().BoolVar(&localOnly, "local", false, "Force local session listing even when platform config exists")
	cmd.Flags().BoolVar(&includeRuns, "runs", false, "Include Codewire runs from inside running sandbox environments")
	cmd.Flags().String("org", "", "Organization ID or slug (default: current org)")
	cmd.Flags().StringVar(&statusFilter, "status", "all", "Filter by status (standalone mode): all, running, completed, killed")
	_ = cmd.RegisterFlagCompletionFunc("status", func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		return []string{"all", "running", "completed", "killed"}, cobra.ShellCompDirectiveNoFileComp
	})
	return cmd
}

func listPlatformEntries(pc *platform.Client, orgID string, envs []platform.Environment, includeRuns bool) []platformListEntry {
	entries := make([]platformListEntry, 0, len(envs))
	if !includeRuns {
		for _, env := range envs {
			entries = append(entries, platformListEntry{Environment: env})
		}
		return entries
	}

	type result struct {
		index int
		entry platformListEntry
	}
	results := make(chan result, len(envs))
	var wg sync.WaitGroup
	for _, env := range envs {
		entries = append(entries, platformListEntry{Environment: env})
	}
	for i, env := range envs {
		wg.Add(1)
		go func(index int, env platform.Environment) {
			defer wg.Done()
			sessions, lookup, errMsg := listEnvironmentRuns(pc, orgID, env)
			results <- result{
				index: index,
				entry: platformListEntry{
					Environment:   env,
					Sessions:      sessions,
					SessionLookup: lookup,
					SessionError:  errMsg,
				},
			}
		}(i, env)
	}
	wg.Wait()
	close(results)
	for result := range results {
		entries[result.index] = result.entry
	}
	return entries
}

func listEnvironmentRuns(pc *platform.Client, orgID string, env platform.Environment) ([]protocol.SessionInfo, string, string) {
	if env.Type != "sandbox" {
		return nil, "unsupported", ""
	}
	if env.State != "running" {
		return nil, "skipped", ""
	}

	result, err := pc.ExecInEnvironment(orgID, env.ID, &platform.ExecRequest{
		Command:    []string{"cw", "list", "--local", "--json"},
		WorkingDir: "/workspace",
		Timeout:    10,
	})
	if err != nil {
		return nil, "unavailable", err.Error()
	}
	if result.ExitCode != 0 {
		return nil, "unavailable", summarizeExecError(result)
	}

	var sessions []protocol.SessionInfo
	if err := json.Unmarshal([]byte(result.Stdout), &sessions); err != nil {
		return nil, "unavailable", fmt.Sprintf("decode runs: %v", err)
	}
	return sessions, "available", ""
}

func summarizeExecError(result *platform.ExecResult) string {
	msg := strings.TrimSpace(result.Stderr)
	if msg == "" {
		msg = strings.TrimSpace(result.Stdout)
	}
	if msg == "" {
		msg = fmt.Sprintf("cw list exited with code %d", result.ExitCode)
	}
	msg = strings.ReplaceAll(msg, "\n", " ")
	if len(msg) > 96 {
		msg = msg[:93] + "..."
	}
	return msg
}

func printPlatformEntries(entries []platformListEntry) error {
	currentRef := currentEnvironmentTargetRef()

	for _, entry := range entries {
		env := entry.Environment
		for _, line := range environmentCardLines(env, currentRef) {
			fmt.Println(line)
		}

		runSummary := "n/a"
		switch entry.SessionLookup {
		case "available":
			runSummary = fmt.Sprintf("%d", len(entry.Sessions))
		case "unavailable":
			runSummary = "?"
		case "":
			runSummary = "--"
		}

		if entry.SessionLookup == "available" {
			if len(entry.Sessions) == 0 {
				fmt.Println("  runs: none")
			} else {
				fmt.Printf("  runs: %s\n", runSummary)
				w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
				tableHeader(w, "  ID", "NAME", "STATUS", "AGE", "COMMAND")
				for _, session := range entry.Sessions {
					name := session.Name
					if name == "" {
						name = "-"
					}
					fmt.Fprintf(w, "  %d\t%s\t%s\t%s\t%s\n",
						session.ID,
						name,
						stateColor(session.Status),
						timeAgo(session.CreatedAt),
						truncateRunCommand(session.Prompt),
					)
				}
				if err := w.Flush(); err != nil {
					return err
				}
			}
		} else if entry.SessionLookup == "unavailable" && entry.SessionError != "" {
			fmt.Printf("  runs: unavailable (%s)\n", entry.SessionError)
		}

		fmt.Println()
	}
	return nil
}

func truncateRunCommand(prompt string) string {
	prompt = strings.TrimSpace(prompt)
	if prompt == "" {
		return "-"
	}
	if len(prompt) > 60 {
		return prompt[:57] + "..."
	}
	return prompt
}
