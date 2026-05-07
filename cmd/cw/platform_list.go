package main

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
	"sync"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/codewiresh/codewire/internal/client"
	cwconfig "github.com/codewiresh/codewire/internal/config"
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
	var output string
	var statusFilter string
	var localOnly bool
	var includeRuns bool
	var networkFilter string

	cmd := &cobra.Command{
		Use:   "list",
		Short: "List environments, with optional runs inside them",
		Long: `In platform mode, list environments in the current org.

Add --runs to also inspect Codewire runs inside running sandbox environments.

In standalone mode, this falls back to listing local runs.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			jsonOutput, err := wantsJSON(output)
			if err != nil {
				return err
			}
			if localOnly || !platform.HasConfig() {
				target, err := resolveTarget()
				if err != nil {
					return err
				}
				if target.IsLocal() {
					if err := ensureNode(); err != nil {
						return err
					}
					if jsonOutput {
						return client.List(target, true, statusFilter)
					}
					sessions, err := client.ListFiltered(target, statusFilter)
					if err != nil {
						return err
					}
					localNodes, err := listLocalNodeEntries()
					if err != nil {
						return err
					}
					return printLocalTargetEntries(sessions, localNodes)
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

			entries := listPlatformEntries(pc, orgID, filterEnvironmentsByNetwork(envs, networkFilter), includeRuns)

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

	addOutputFlag(cmd, &output, "Output format (text|json)")
	cmd.Flags().BoolVar(&localOnly, "local", false, "Force local session listing even when platform config exists")
	cmd.Flags().BoolVar(&includeRuns, "runs", false, "Include Codewire runs from inside running sandbox environments")
	cmd.Flags().StringVar(&networkFilter, "network", "", "Only show environments in the specified network")
	cmd.Flags().String("org", "", "Organization ID or slug (default: current org)")
	cmd.Flags().StringVar(&statusFilter, "status", "running", "Filter by status (standalone mode, default: running): all, running, completed, killed")
	_ = cmd.RegisterFlagCompletionFunc("status", func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		return []string{"all", "running", "completed", "killed"}, cobra.ShellCompDirectiveNoFileComp
	})
	return cmd
}

type localNodeEntry struct {
	Instance cwconfig.LocalInstance
	Status   string
}

func listLocalNodeEntries() ([]localNodeEntry, error) {
	state, err := loadLocalInstancesForCLI()
	if err != nil {
		return nil, err
	}
	if state == nil || len(state.Instances) == 0 {
		return nil, nil
	}

	names := sortedLocalInstanceNames(state)
	entries := make([]localNodeEntry, 0, len(names))
	for _, name := range names {
		instance := state.Instances[name]
		status, err := localRuntimeStatus(&instance)
		if err != nil {
			status = "unknown"
		}
		entries = append(entries, localNodeEntry{Instance: instance, Status: status})
	}
	return entries, nil
}

func printLocalTargetEntries(sessions []protocol.SessionInfo, localNodes []localNodeEntry) error {
	if len(sessions) == 0 && len(localNodes) == 0 {
		fmt.Println("No sessions or local nodes.")
		return nil
	}

	fmt.Println("Runs")
	if len(sessions) == 0 {
		fmt.Println("  none")
	} else {
		printStandaloneSessionTable(sessions)
	}

	fmt.Println()
	fmt.Println("Local Nodes")
	if len(localNodes) == 0 {
		fmt.Println("  none")
		return nil
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	tableHeader(w, "NAME", "BACKEND", "STATE", "PORTS", "IMAGE", "REPO")
	for _, entry := range localNodes {
		instance := entry.Instance
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\n",
			instance.Name,
			instance.Backend,
			stateColor(entry.Status),
			localPortSummary(&instance),
			instance.Image,
			instance.RepoPath,
		)
	}
	return w.Flush()
}

func printStandaloneSessionTable(sessions []protocol.SessionInfo) {
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	tableHeader(w, "ID", "NAME", "STATUS", "AGE", "COMMAND")
	for _, session := range sessions {
		name := session.Name
		if name == "" {
			name = "-"
		}
		fmt.Fprintf(w, "%d\t%s\t%s\t%s\t%s\n",
			session.ID,
			name,
			stateColor(session.Status),
			timeAgo(session.CreatedAt),
			truncateRunCommand(session.Prompt),
		)
	}
	_ = w.Flush()
}

func filterEnvironmentsByNetwork(envs []platform.Environment, network string) []platform.Environment {
	network = strings.TrimSpace(network)
	if network == "" {
		return envs
	}

	filtered := make([]platform.Environment, 0, len(envs))
	for _, env := range envs {
		if env.Network == nil {
			continue
		}
		if strings.TrimSpace(*env.Network) == network {
			filtered = append(filtered, env)
		}
	}
	return filtered
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
		Command:    []string{"cw", "list", "--local", "--output", "json"},
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
	combined := strings.TrimSpace(strings.Join([]string{
		strings.TrimSpace(result.Stdout),
		strings.TrimSpace(result.Stderr),
	}, "\n"))
	lower := strings.ToLower(combined)
	if strings.Contains(lower, "exec: cw: not found") || strings.Contains(lower, "cw: not found") {
		return "codewire CLI missing in image"
	}
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
	grouped, order := groupPlatformEntriesByNetwork(entries)
	showNetworkHeaders := len(order) > 1

	firstGroup := true
	for _, network := range order {
		if showNetworkHeaders {
			if !firstGroup {
				fmt.Println()
			}
			fmt.Printf("Network: %s\n\n", network)
			firstGroup = false
		}

		for _, entry := range grouped[network] {
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
					tableHeader(w, "    ID", "NAME", "STATUS", "AGE", "COMMAND")
					for _, session := range entry.Sessions {
						name := session.Name
						if name == "" {
							name = "-"
						}
						fmt.Fprintf(w, "    %d\t%s\t%s\t%s\t%s\n",
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
	}
	return nil
}

func groupPlatformEntriesByNetwork(entries []platformListEntry) (map[string][]platformListEntry, []string) {
	grouped := make(map[string][]platformListEntry, len(entries))
	seen := make(map[string]struct{}, len(entries))
	for _, entry := range entries {
		network := platformEntryNetworkLabel(entry)
		grouped[network] = append(grouped[network], entry)
		seen[network] = struct{}{}
	}

	order := make([]string, 0, len(seen))
	for network := range seen {
		order = append(order, network)
	}
	sort.Slice(order, func(i, j int) bool {
		left := order[i]
		right := order[j]
		if left == "No Network" {
			return false
		}
		if right == "No Network" {
			return true
		}
		return left < right
	})
	return grouped, order
}

func platformEntryNetworkLabel(entry platformListEntry) string {
	if entry.Environment.Network == nil || strings.TrimSpace(*entry.Environment.Network) == "" {
		return "No Network"
	}
	return strings.TrimSpace(*entry.Environment.Network)
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
