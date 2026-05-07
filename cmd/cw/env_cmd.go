package main

import (
	"fmt"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	cwclient "github.com/codewiresh/codewire/internal/client"
	cwconfig "github.com/codewiresh/codewire/internal/config"
	"github.com/codewiresh/codewire/internal/platform"
)

// loadCodewireYAML is a convenience wrapper around config.LoadCodewireConfig.
func loadCodewireYAML(path string) (*cwconfig.CodewireConfig, error) {
	return cwconfig.LoadCodewireConfig(path)
}

func envParentCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "env",
		Short:   "Manage environments",
		Aliases: []string{"environment"},
	}
	cmd.PersistentFlags().String("org", "", "Organization ID or slug (default: current org)")
	cmd.AddCommand(envCreateCmd())
	cmd.AddCommand(envListCmd())
	cmd.AddCommand(envInfoCmd())
	cmd.AddCommand(envStopCmd())
	cmd.AddCommand(envStartCmd())
	cmd.AddCommand(envRmCmd())
	cmd.AddCommand(envCpCmd())
	cmd.AddCommand(envPruneCmd())
	cmd.AddCommand(envNukeCmd())
	cmd.AddCommand(envLogsCmd())
	cmd.AddCommand(portParentCmd())
	cmd.AddCommand(envProtectCmd())
	cmd.AddCommand(envUnprotectCmd())
	cmd.AddCommand(envCancelDeleteCmd())
	cmd.AddCommand(envExtendCmd())
	cmd.AddCommand(envAccessCmd())
	return cmd
}

// parseRepoSpec splits "url@branch" into (url, branch).
// If no "@" is present, branch is empty.
func parseRepoSpec(spec string) (string, string) {
	// Don't split on @ inside the user@host part of SSH/HTTPS URLs.
	// The branch delimiter is the last @ that appears after a "/" or at the end.
	idx := strings.LastIndex(spec, "@")
	if idx == -1 {
		return spec, ""
	}
	// Ensure the @ is after a path separator (not in user@host).
	url := spec[:idx]
	branch := spec[idx+1:]
	if !strings.Contains(url, "/") {
		// No slash before @, so this is user@host, not url@branch.
		return spec, ""
	}
	return url, branch
}

func strPtrOrNil(s string) *string {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	return &s
}

func intPtrOrNil(v int) *int {
	if v <= 0 {
		return nil
	}
	return &v
}

func boolPtrOrNil(value bool, set bool) *bool {
	if !set {
		return nil
	}
	return &value
}

func durationSecondsPtr(raw string) *int {
	if strings.TrimSpace(raw) == "" {
		return nil
	}
	d, err := time.ParseDuration(raw)
	if err != nil {
		return nil
	}
	secs := int(d.Seconds())
	return &secs
}

func requestHasAgent(req *platform.CreateEnvironmentRequest, agentType string) bool {
	for _, agent := range req.Agents {
		if agent.Type == agentType {
			return true
		}
	}
	return req.Agent == agentType
}

func getDefaultOrg() (string, *platform.Client, error) {
	return getOrgContext(nil)
}

func normalizeEnvRef(ref string) string {
	return strings.TrimSpace(ref)
}

func shortEnvID(id string) string {
	if idx := strings.Index(id, "-"); idx > 0 {
		return id[:idx]
	}
	if len(id) > 8 {
		return id[:8]
	}
	return id
}

func envDisplayRefs(env platform.Environment) []string {
	var refs []string
	if env.Name != nil && *env.Name != "" {
		refs = append(refs, *env.Name)
	}
	if env.ID != "" {
		refs = append(refs, shortEnvID(env.ID), env.ID)
	}
	return refs
}

func envCompletionDescription(env platform.Environment, ref string) string {
	var parts []string
	if ref != env.ID {
		parts = append(parts, env.ID)
	}
	if env.Name != nil && *env.Name != "" && ref != *env.Name {
		parts = append(parts, *env.Name)
	}
	if env.CreatedAt != "" {
		parts = append(parts, timeAgo(env.CreatedAt))
	}
	return strings.Join(parts, " ")
}

func envSSHRef(env platform.Environment) string {
	if env.Type != "sandbox" || env.State != "running" {
		return "--"
	}
	return shortEnvID(env.ID)
}

func envConnectHint(env platform.Environment) string {
	ref := envSSHRef(env)
	if ref == "--" {
		return "--"
	}
	return "cw shell " + ref
}

func environmentStateLabel(env platform.Environment) string {
	if env.DeletionGraceUntil != nil && env.State != "destroyed" && env.State != "destroying" {
		return stateColor("deleting")
	}
	return stateColor(env.State)
}

func environmentDisplayName(env platform.Environment) string {
	if env.Name != nil && strings.TrimSpace(*env.Name) != "" {
		return *env.Name
	}
	return env.ID
}

func currentEnvironmentTargetRef() string {
	if cfg, err := loadCLIConfigForTarget(); err == nil {
		if target := currentTargetConfig(cfg); target.Kind == "env" {
			return target.Ref
		}
	}
	return ""
}

func environmentCardLines(env platform.Environment, currentRef string) []string {
	marker := ""
	if currentRef != "" && env.ID == currentRef {
		marker = " " + green("(current)")
	}

	protectTag := ""
	if env.Protected {
		protectTag = " [protected]"
	}

	lines := []string{
		fmt.Sprintf("%s [%s]  %s  %s%s%s",
			bold(environmentDisplayName(env)),
			dim(shortEnvID(env.ID)),
			environmentStateLabel(env),
			timeAgo(env.CreatedAt),
			marker,
			protectTag,
		),
		fmt.Sprintf("  %s  %dm/%dMB  ttl %s",
			env.Type,
			env.CPUMillicores,
			env.MemoryMB,
			envTTLString(env),
		),
	}
	if env.Network != nil && strings.TrimSpace(*env.Network) != "" {
		lines = append(lines, fmt.Sprintf("  network: %s", *env.Network))
	}
	if env.DeletionGraceUntil != nil {
		lines = append(lines, fmt.Sprintf("  deleting at: %s", *env.DeletionGraceUntil))
	}
	if hint := envConnectHint(env); hint != "--" {
		lines = append(lines, fmt.Sprintf("  connect: %s", hint))
	} else {
		lines = append(lines, "  connect: --")
	}
	return lines
}

func envTTLString(env platform.Environment) string {
	if env.ShutdownAt == nil {
		return "--"
	}
	shutdownTime, err := time.Parse(time.RFC3339, *env.ShutdownAt)
	if err != nil {
		return "--"
	}
	remaining := time.Until(shutdownTime)
	if remaining > 0 {
		return fmt.Sprintf("%dm", int(remaining.Minutes()))
	}
	return "expired"
}

func printEnvListEntries(envs []platform.Environment) {
	currentRef := currentEnvironmentTargetRef()

	for i, e := range envs {
		for _, line := range environmentCardLines(e, currentRef) {
			fmt.Println(line)
		}
		if i < len(envs)-1 {
			fmt.Println()
		}
	}
}

func filterEnvCompletions(envs []platform.Environment, toComplete string) []string {
	needle := strings.ToLower(normalizeEnvRef(toComplete))
	seen := make(map[string]bool)
	var completions []string

	for _, env := range envs {
		for _, ref := range envDisplayRefs(env) {
			if seen[ref] {
				continue
			}
			if needle != "" && !strings.HasPrefix(strings.ToLower(ref), needle) {
				continue
			}
			seen[ref] = true
			description := envCompletionDescription(env, ref)
			if description != "" {
				completions = append(completions, ref+"\t"+description)
				continue
			}
			completions = append(completions, ref)
		}
	}

	return completions
}

func resolveEnvIDFromList(envs []platform.Environment, ref string) (string, error) {
	ref = normalizeEnvRef(ref)
	if ref == "" {
		return "", fmt.Errorf("environment reference cannot be empty")
	}

	var exactNameMatches []platform.Environment
	var prefixMatches []platform.Environment
	for _, e := range envs {
		if e.ID == ref {
			return e.ID, nil
		}
		if e.Name != nil && *e.Name == ref {
			exactNameMatches = append(exactNameMatches, e)
		}
		if strings.HasPrefix(e.ID, ref) {
			prefixMatches = append(prefixMatches, e)
		}
	}

	switch len(exactNameMatches) {
	case 1:
		return exactNameMatches[0].ID, nil
	case 0:
		// Fall through to unique UUID prefix lookup below.
	default:
		ids := make([]string, len(exactNameMatches))
		for i, m := range exactNameMatches {
			ids[i] = m.ID
		}
		return "", fmt.Errorf("multiple environments named %q, use ID: %s", ref, strings.Join(ids, ", "))
	}

	switch len(prefixMatches) {
	case 1:
		return prefixMatches[0].ID, nil
	case 0:
		return "", fmt.Errorf("environment %q not found", ref)
	default:
		ids := make([]string, len(prefixMatches))
		for i, m := range prefixMatches {
			ids[i] = m.ID
		}
		return "", fmt.Errorf("environment %q matched multiple IDs, use a longer prefix or full ID: %s", ref, strings.Join(ids, ", "))
	}
}

func resolveEnvID(client *platform.Client, orgID, ref string) (string, error) {
	ref = normalizeEnvRef(ref)
	if ref == "" {
		return "", fmt.Errorf("environment reference cannot be empty")
	}

	// Fast path: if it looks like a UUID, try direct lookup.
	if len(ref) >= 36 && strings.Contains(ref, "-") {
		if _, err := client.GetEnvironment(orgID, ref); err == nil {
			return ref, nil
		}
	}

	// Name lookup: list all and filter by name.
	envs, err := client.ListEnvironments(orgID, "", "", false)
	if err != nil {
		return "", fmt.Errorf("list environments: %w", err)
	}

	return resolveEnvIDFromList(envs, ref)
}

var listEnvironmentsForCompletion = func(cmd *cobra.Command) ([]platform.Environment, error) {
	orgID, client, err := getOrgContext(cmd)
	if err != nil {
		return nil, err
	}
	return client.ListEnvironments(orgID, "", "", false)
}

func envCompletionFunc(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
	envs, err := listEnvironmentsForCompletion(cmd)
	if err != nil {
		return nil, cobra.ShellCompDirectiveNoFileComp
	}

	return filterEnvCompletions(envs, toComplete), cobra.ShellCompDirectiveNoFileComp
}

func timeAgo(s string) string {
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return s
	}
	d := time.Since(t)
	switch {
	case d < time.Minute:
		return fmt.Sprintf("%ds ago", int(d.Seconds()))
	case d < time.Hour:
		return fmt.Sprintf("%dm ago", int(d.Minutes()))
	case d < 24*time.Hour:
		return fmt.Sprintf("%dh ago", int(d.Hours()))
	default:
		return fmt.Sprintf("%dd ago", int(d.Hours()/24))
	}
}

func printDetectionSummary(detection *platform.DetectionResult) {
	if detection == nil {
		return
	}

	fmt.Fprintf(os.Stderr, "\nDetected: %s", detection.Language)
	if detection.Framework != "" {
		fmt.Fprintf(os.Stderr, " (%s)", detection.Framework)
	}
	if detection.ProjectType != "" {
		fmt.Fprintf(os.Stderr, " [%s]", detection.ProjectType)
	}
	fmt.Fprintln(os.Stderr)
	if detection.PresetImage != "" {
		fmt.Fprintf(os.Stderr, "  Image:    %s\n", detection.PresetImage)
	}
	if detection.InstallCommand != "" {
		fmt.Fprintf(os.Stderr, "  Install:  %s\n", detection.InstallCommand)
	}
	if detection.StartupScript != "" {
		lines := strings.Split(detection.StartupScript, "\n")
		if len(lines) == 1 {
			fmt.Fprintf(os.Stderr, "  Script:   %s\n", detection.StartupScript)
		} else {
			fmt.Fprintf(os.Stderr, "  Script:   %s (+%d lines)\n", lines[0], len(lines)-1)
		}
	}
	if len(detection.AppPorts) > 0 {
		var portParts []string
		for _, p := range detection.AppPorts {
			portParts = append(portParts, fmt.Sprintf("%s:%d", p.Label, p.Port))
		}
		fmt.Fprintf(os.Stderr, "  Ports:    %s\n", strings.Join(portParts, ", "))
	}
	if detection.SetupNotes != "" {
		fmt.Fprintf(os.Stderr, "  Notes:    %s\n", detection.SetupNotes)
	}
	fmt.Fprintln(os.Stderr)
}

type relayEnrollment struct {
	RelayURL        string
	NetworkID       string
	InviteToken     string
	EnrollmentToken string
}

var createRelayInvite = cwclient.CreateInvite
var createRelayNodeEnrollment = cwclient.CreateNodeEnrollment

type relayNetworkBootstrap struct {
	RelayURL  string
	AuthToken string
	NetworkID string
}

func resolveRelayNetworkBootstrap(dir string, assumeYes bool, requestedNetwork string, disableNetwork bool) (*relayNetworkBootstrap, error) {
	if disableNetwork {
		return nil, nil
	}
	requestedNetwork = strings.TrimSpace(requestedNetwork)

	cfg, err := cwconfig.LoadConfig(dir)
	if err != nil {
		if requestedNetwork != "" {
			return nil, fmt.Errorf("relay is not configured locally (run 'cw login' and 'cw network create/use' first)")
		}
		return nil, nil
	}
	if cfg.RelayURL == nil || *cfg.RelayURL == "" {
		if requestedNetwork != "" {
			return nil, fmt.Errorf("relay URL is not configured locally")
		}
		return nil, nil
	}

	networkID := requestedNetwork
	if networkID == "" {
		if cfg.RelaySelectedNetwork == nil || strings.TrimSpace(*cfg.RelaySelectedNetwork) == "" {
			return nil, nil
		}
		if cfg.RelayAutoJoinPrivate == nil {
			approved := assumeYes
			if !assumeYes {
				approved, err = promptConfirm(fmt.Sprintf("New environments will auto-join your private network %q for remote access. Continue", *cfg.RelaySelectedNetwork))
				if err != nil {
					return nil, err
				}
			}
			cfg.RelayAutoJoinPrivate = &approved
			if err := cwconfig.SaveConfig(dir, cfg); err != nil {
				return nil, fmt.Errorf("saving relay consent: %w", err)
			}
		}
		if !*cfg.RelayAutoJoinPrivate {
			return nil, nil
		}
		networkID = *cfg.RelaySelectedNetwork
	}

	relayURL, authToken, _, err := cwclient.LoadRelayAuth(dir, cwclient.RelayAuthOptions{})
	if err != nil {
		if requestedNetwork != "" {
			return nil, fmt.Errorf("relay user auth is not configured locally (run 'cw login' for hosted Codewire, or set CODEWIRE_RELAY_AUTH_TOKEN for a standalone relay)")
		}
		return nil, nil
	}

	return &relayNetworkBootstrap{
		RelayURL:  relayURL,
		AuthToken: authToken,
		NetworkID: networkID,
	}, nil
}

func resolveRelayEnrollment(dir string, assumeYes bool, requestedNetwork string, disableNetwork bool) (*relayEnrollment, error) {
	bootstrap, err := resolveRelayNetworkBootstrap(dir, assumeYes, requestedNetwork, disableNetwork)
	if err != nil || bootstrap == nil {
		return nil, err
	}

	invite, err := createRelayInvite(dir, cwclient.RelayAuthOptions{
		RelayURL:  bootstrap.RelayURL,
		AuthToken: bootstrap.AuthToken,
		NetworkID: bootstrap.NetworkID,
	}, 1, "24h")
	if err != nil {
		return nil, fmt.Errorf("create relay invite for env: %w", err)
	}

	return &relayEnrollment{
		RelayURL:    bootstrap.RelayURL,
		NetworkID:   bootstrap.NetworkID,
		InviteToken: invite.Token,
	}, nil
}

func createLocalRelayNodeEnrollment(dir string, bootstrap *relayNetworkBootstrap, nodeName string) (*relayEnrollment, error) {
	if bootstrap == nil {
		return nil, nil
	}
	nodeName = strings.TrimSpace(nodeName)
	if nodeName == "" {
		return nil, fmt.Errorf("node name is required")
	}

	enrollment, err := createRelayNodeEnrollment(dir, cwclient.RelayAuthOptions{
		RelayURL:  bootstrap.RelayURL,
		AuthToken: bootstrap.AuthToken,
		NetworkID: bootstrap.NetworkID,
	}, nodeName, 1, "10m")
	if err != nil {
		return nil, fmt.Errorf("create relay node enrollment for local runtime: %w", err)
	}

	return &relayEnrollment{
		RelayURL:        bootstrap.RelayURL,
		NetworkID:       bootstrap.NetworkID,
		EnrollmentToken: enrollment.EnrollmentToken,
	}, nil
}

func envCreateCmd() *cobra.Command {
	var (
		presetSlug    string
		presetID      string
		name          string
		ttl           string
		cpu           int
		memory        int
		disk          int
		repoFlags     []string
		branch        string
		image         string
		install       string
		startup       string
		agent         string
		envVars       []string
		secretProject string
		noOrgSecrets  bool
		noUserSecrets bool
		follow        bool
		noWait        bool
		yes           bool
		network       string
		noNetwork     bool
		writePreset   bool
		savePreset    string
	)

	cmd := &cobra.Command{
		Use:   "create [repo-url ...]",
		Short: "Create a new environment",
		Long: `Create a new environment. Smart create detects configuration from a repo URL.

Multiple repos can be specified as positional args or with --repo flags.
Use url@branch syntax to specify a branch per repo.

Examples:
  cw env create https://github.com/foo/bar
  cw env create https://github.com/foo/frontend https://github.com/foo/api
  cw env create --repo github.com/foo/frontend@main --repo git.noel.sh/foo/backend
  cw env create --preset go --name my-env
  cw env create --image go --name my-env
  cw env create --secrets my-project https://github.com/foo/bar
  cw env create --network project-alpha https://github.com/foo/bar`,
		Args: cobra.ArbitraryArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			orgID, client, resolved, err := resolvePresetAuthoring(cmd, &presetAuthoringOptions{
				Args:              args,
				RepoFlags:         repoFlags,
				PresetSlug:        presetSlug,
				PresetID:          presetID,
				Name:              name,
				TTL:               ttl,
				CPU:               cpu,
				Memory:            memory,
				Disk:              disk,
				Branch:            branch,
				Image:             image,
				Install:           install,
				Startup:           startup,
				Agent:             agent,
				EnvVars:           envVars,
				SecretProject:     secretProject,
				NoOrgSecrets:      noOrgSecrets,
				NoUserSecrets:     noUserSecrets,
				Yes:               yes,
				AllowCodewireYAML: true,
				PromptOnAnalyze:   true,
				PromptOnDetection: true,
				ShowDetection:     true,
			})
			if err != nil {
				return err
			}

			req := resolved.Request

			enrollment, err := resolveRelayEnrollment(dataDir(), yes, network, noNetwork)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Warning: relay enrollment failed (%v), continuing without network\n", err)
				enrollment = nil
			}
			if enrollment != nil {
				if req.EnvVars == nil {
					req.EnvVars = make(map[string]string)
				}
				for key, value := range map[string]string{
					"CODEWIRE_RELAY_URL":          enrollment.RelayURL,
					"CODEWIRE_RELAY_NETWORK":      enrollment.NetworkID,
					"CODEWIRE_RELAY_INVITE_TOKEN": enrollment.InviteToken,
				} {
					if _, exists := req.EnvVars[key]; exists {
						return fmt.Errorf("%s is reserved for relay bootstrap", key)
					}
					req.EnvVars[key] = value
				}
			}
			if cpu > 0 {
				req.CPUMillicores = &cpu
			}
			if memory > 0 {
				req.MemoryMB = &memory
			}
			if disk > 0 {
				req.DiskGB = &disk
			}
			if ttl != "" {
				d, err := time.ParseDuration(ttl)
				if err != nil {
					return fmt.Errorf("invalid --ttl duration: %w", err)
				}
				secs := int(d.Seconds())
				req.TTLSeconds = &secs
			}

			if noOrgSecrets {
				f := false
				req.IncludeOrgSecrets = &f
			}
			if noUserSecrets {
				f := false
				req.IncludeUserSecrets = &f
			}

			var env *platform.Environment
			err = withReauth(client, func() error {
				var createErr error
				env, createErr = client.CreateEnvironment(orgID, req)
				return createErr
			})
			if err != nil {
				return fmt.Errorf("create environment: %w", err)
			}

			if writePreset {
				if err := writeResolvedCodewireYAML("codewire.yaml", req); err != nil {
					return fmt.Errorf("write codewire.yaml: %w", err)
				}
				successMsg("Preset written: codewire.yaml")
			}
			if strings.TrimSpace(savePreset) != "" {
				presetReq, err := createPresetRequestFromEnvironment(savePreset, req)
				if err != nil {
					return err
				}
				preset, err := client.CreatePreset(orgID, presetReq)
				if err != nil {
					return fmt.Errorf("save preset: %w", err)
				}
				successMsg("Preset saved: %s (%s).", preset.Name, preset.ID)
			}

			envName := env.ID
			if env.Name != nil {
				envName = *env.Name
			}
			successMsg("Environment created: %s", envName)
			fmt.Fprintf(os.Stderr, "  ID:    %s\n", env.ID)
			fmt.Fprintf(os.Stderr, "  State: %s\n", env.State)
			fmt.Fprintf(os.Stderr, "  Type:  %s\n", env.Type)
			fmt.Fprintf(os.Stderr, "  CPU:   %dm\n", env.CPUMillicores)
			fmt.Fprintf(os.Stderr, "  Mem:   %dMB\n", env.MemoryMB)
			fmt.Fprintf(os.Stderr, "  Disk:  %dGB\n", env.DiskGB)

			if !noWait && follow {
				fmt.Println()
				if err := followEnvironmentLogs(client, orgID, env.ID); err != nil {
					fmt.Fprintf(os.Stderr, "Warning: could not follow logs: %v\n", err)
				}
			}
			return nil
		},
	}

	cmd.Flags().StringVar(&presetSlug, "preset", "", "Preset slug (e.g. go, node, python)")
	cmd.Flags().StringVar(&presetID, "preset-id", "", "Preset ID (exact)")
	cmd.Flags().StringVar(&name, "name", "", "Environment name")
	cmd.Flags().StringVar(&ttl, "ttl", "", "Time to live (e.g. 1h, 30m)")
	cmd.Flags().IntVar(&cpu, "cpu", 0, "CPU in millicores")
	cmd.Flags().IntVar(&memory, "memory", 0, "Memory in MB")
	cmd.Flags().IntVar(&disk, "disk", 0, "Disk in GB")
	cmd.Flags().StringArrayVar(&repoFlags, "repo", nil, "Git repo URL (repeatable, url@branch syntax)")
	cmd.Flags().StringVar(&branch, "branch", "", "Branch to checkout")
	cmd.Flags().StringVar(&image, "image", "", "Container image (shorthand: full → ghcr.io/codewiresh/full)")
	cmd.Flags().StringVar(&install, "install", "", "Install command")
	cmd.Flags().StringVar(&startup, "startup", "", "Startup script")
	cmd.Flags().StringVar(&agent, "agent", "", "AI agent (claude-code)")
	cmd.Flags().StringSliceVar(&envVars, "env", nil, "Env vars (KEY=val)")
	cmd.Flags().StringVar(&secretProject, "secrets", "", "Secret project to bind")
	cmd.Flags().BoolVar(&noOrgSecrets, "no-org-secrets", false, "Don't inject org-level secrets")
	cmd.Flags().BoolVar(&noUserSecrets, "no-user-secrets", false, "Don't inject user-level secrets")
	cmd.Flags().StringVar(&network, "network", "", "Join a specific relay network on boot (requires relay auth in local config)")
	cmd.Flags().BoolVar(&noNetwork, "no-network", false, "Don't join the selected private relay network")
	cmd.Flags().BoolVarP(&follow, "follow", "f", true, "Watch startup progress and wait for readiness (default: true)")
	cmd.Flags().BoolVar(&noWait, "no-wait", false, "Return immediately after creation instead of waiting for startup")
	cmd.Flags().BoolVarP(&yes, "yes", "y", false, "Skip confirmation prompts")
	cmd.Flags().BoolVar(&writePreset, "write-preset", false, "Write the resolved preset to ./codewire.yaml after creation")
	cmd.Flags().StringVar(&savePreset, "save-preset", "", "Save the resolved preset to the server after creation")
	return cmd
}

func envListCmd() *cobra.Command {
	var (
		envType string
		state   string
		all     bool
	)

	cmd := &cobra.Command{
		Use:     "list",
		Short:   "List environments",
		Aliases: []string{"ls"},
		RunE: func(cmd *cobra.Command, args []string) error {
			orgID, client, err := getOrgContext(cmd)
			if err != nil {
				return err
			}

			envs, err := client.ListEnvironments(orgID, envType, state, all)
			if err != nil {
				return fmt.Errorf("list environments: %w", err)
			}

			if len(envs) == 0 {
				fmt.Println("No environments found.")
				return nil
			}

			printEnvListEntries(envs)
			return nil
		},
	}

	cmd.Flags().StringVar(&envType, "type", "", "Filter by type (coder, sandbox)")
	cmd.Flags().StringVar(&state, "state", "", "Filter by state")
	cmd.Flags().BoolVarP(&all, "all", "a", false, "Include destroyed environments")
	return cmd
}

func envInfoCmd() *cobra.Command {
	return &cobra.Command{
		Use:               "info <id-or-name>",
		Short:             "Show environment details",
		Args:              cobra.ExactArgs(1),
		ValidArgsFunction: envCompletionFunc,
		RunE: func(cmd *cobra.Command, args []string) error {
			orgID, client, err := getOrgContext(cmd)
			if err != nil {
				return err
			}

			envID, err := resolveEnvID(client, orgID, args[0])
			if err != nil {
				return err
			}

			env, err := client.GetEnvironment(orgID, envID)
			if err != nil {
				return fmt.Errorf("get environment: %w", err)
			}

			envName := "--"
			if env.Name != nil {
				envName = *env.Name
			}

			fmt.Printf("%-14s %s\n", bold("ID:"), dim(env.ID))
			fmt.Printf("%-14s %s\n", bold("Name:"), envName)
			fmt.Printf("%-14s %s\n", bold("Type:"), env.Type)
			fmt.Printf("%-14s %s\n", bold("State:"), environmentStateLabel(*env))
			fmt.Printf("%-14s %s\n", bold("DesiredState:"), stateColor(env.DesiredState))
			fmt.Printf("%-14s %s\n", bold("PresetID:"), dim(env.PresetID))
			if env.Network != nil && strings.TrimSpace(*env.Network) != "" {
				fmt.Printf("%-14s %s\n", bold("Network:"), *env.Network)
			}
			fmt.Printf("CPU:           %dm\n", env.CPUMillicores)
			fmt.Printf("Memory:        %dMB\n", env.MemoryMB)
			fmt.Printf("Disk:          %dGB\n", env.DiskGB)
			fmt.Printf("CreatedBy:     %s\n", env.CreatedBy)
			fmt.Printf("CreatedAt:     %s\n", env.CreatedAt)
			if env.StartedAt != nil {
				fmt.Printf("StartedAt:     %s\n", *env.StartedAt)
			}
			if env.StoppedAt != nil {
				fmt.Printf("StoppedAt:     %s\n", *env.StoppedAt)
			}
			if env.ShutdownAt != nil {
				fmt.Printf("ShutdownAt:    %s\n", *env.ShutdownAt)
			}
			if env.TTLSeconds != nil {
				fmt.Printf("TTL:           %ds\n", *env.TTLSeconds)
			}
			if env.ErrorReason != nil {
				fmt.Printf("ErrorReason:   %s\n", *env.ErrorReason)
			}
			fmt.Printf("Recoverable:   %v\n", env.Recoverable)
			fmt.Printf("TotalRunning:  %ds\n", env.TotalRunningSeconds)
			if env.Protected {
				fmt.Printf("%-14s %s\n", bold("Protected:"), "yes")
			}
			if env.DeletionGraceUntil != nil {
				fmt.Printf("%-14s %s\n", bold("DeletingAt:"), *env.DeletionGraceUntil)
			}
			return nil
		},
	}
}

func envStopCmd() *cobra.Command {
	return &cobra.Command{
		Use:               "stop <id-or-name>",
		Short:             "Stop an environment",
		Args:              cobra.ExactArgs(1),
		ValidArgsFunction: envCompletionFunc,
		RunE: func(cmd *cobra.Command, args []string) error {
			orgID, client, err := getOrgContext(cmd)
			if err != nil {
				return err
			}

			envID, err := resolveEnvID(client, orgID, args[0])
			if err != nil {
				return err
			}

			resp, err := client.StopEnvironment(orgID, envID)
			if err != nil {
				return fmt.Errorf("stop environment: %w", err)
			}
			successMsg("Environment %s: %s.", args[0], resp.Status)
			return nil
		},
	}
}

func envStartCmd() *cobra.Command {
	return &cobra.Command{
		Use:               "start <id-or-name>",
		Short:             "Start an environment",
		Args:              cobra.ExactArgs(1),
		ValidArgsFunction: envCompletionFunc,
		RunE: func(cmd *cobra.Command, args []string) error {
			orgID, client, err := getOrgContext(cmd)
			if err != nil {
				return err
			}

			envID, err := resolveEnvID(client, orgID, args[0])
			if err != nil {
				return err
			}

			resp, err := client.StartEnvironment(orgID, envID)
			if err != nil {
				return fmt.Errorf("start environment: %w", err)
			}
			successMsg("Environment %s: %s.", args[0], resp.Status)
			return nil
		},
	}
}

func envRmCmd() *cobra.Command {
	return &cobra.Command{
		Use:               "rm <id-or-name>",
		Short:             "Delete an environment",
		Aliases:           []string{"delete"},
		Args:              cobra.ExactArgs(1),
		ValidArgsFunction: envCompletionFunc,
		RunE: func(cmd *cobra.Command, args []string) error {
			orgID, client, err := getOrgContext(cmd)
			if err != nil {
				return err
			}

			envID, err := resolveEnvID(client, orgID, args[0])
			if err != nil {
				return err
			}

			if err := client.DeleteEnvironment(orgID, envID); err != nil {
				errStr := err.Error()
				if strings.Contains(errStr, "deletion_pending") || strings.Contains(errStr, "202") {
					fmt.Fprintf(os.Stderr, "  Environment %s scheduled for deletion (grace period).\n  Use 'cw env cancel-delete %s' to cancel.\n", args[0], args[0])
					return nil
				}
				if strings.Contains(errStr, "environment_protected") {
					return fmt.Errorf("environment is protected. Run 'cw env unprotect %s' first", args[0])
				}
				if strings.Contains(errStr, "access_denied") {
					return fmt.Errorf("access denied: only the environment owner can delete it")
				}
				return fmt.Errorf("delete environment: %w", err)
			}
			successMsg("Environment %s deleted.", args[0])
			return nil
		},
	}
}

func envPruneCmd() *cobra.Command {
	var (
		yes    bool
		state  string
		dryRun bool
	)

	cmd := &cobra.Command{
		Use:   "prune",
		Short: "Bulk delete stale environments",
		Long:  "Delete environments stuck in error, creating, or pending states.",
		RunE: func(cmd *cobra.Command, args []string) error {
			orgID, client, err := getOrgContext(cmd)
			if err != nil {
				return err
			}

			pruneStates := make(map[string]bool)
			for _, s := range strings.Split(state, ",") {
				s = strings.TrimSpace(s)
				if s != "" {
					pruneStates[s] = true
				}
			}

			envs, err := client.ListEnvironments(orgID, "", "", false)
			if err != nil {
				return fmt.Errorf("list environments: %w", err)
			}

			var targets []platform.Environment
			var skippedProtected int
			for _, e := range envs {
				if pruneStates[e.State] {
					if e.Protected {
						skippedProtected++
						continue
					}
					targets = append(targets, e)
				}
			}

			if skippedProtected > 0 {
				fmt.Fprintf(os.Stderr, "  Skipped %d protected environment(s).\n", skippedProtected)
			}

			if len(targets) == 0 {
				fmt.Println("No environments to prune.")
				return nil
			}

			w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
			tableHeader(w, "ID", "NAME", "STATE", "AGE")
			for _, e := range targets {
				name := "--"
				if e.Name != nil {
					name = *e.Name
				}
				fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", dim(e.ID), name, stateColor(e.State), timeAgo(e.CreatedAt))
			}
			w.Flush()
			fmt.Println()

			if dryRun {
				fmt.Printf("Would prune %d environments (dry run).\n", len(targets))
				return nil
			}

			if !yes {
				answer, err := prompt(fmt.Sprintf("Delete %d environments? [y/N] ", len(targets)))
				if err != nil {
					return err
				}
				if strings.ToLower(answer) != "y" {
					fmt.Println("Aborted.")
					return nil
				}
			}

			deleted := 0
			for _, e := range targets {
				if err := client.DeleteEnvironment(orgID, e.ID); err != nil {
					fmt.Fprintf(os.Stderr, "Failed to delete %s: %v\n", e.ID, err)
					continue
				}
				label := e.ID
				if e.Name != nil {
					label = fmt.Sprintf("%s (%s)", e.ID, *e.Name)
				}
				successMsg("Deleted %s.", label)
				deleted++
			}

			successMsg("Pruned %d environments.", deleted)
			return nil
		},
	}

	cmd.Flags().BoolVarP(&yes, "yes", "y", false, "Skip confirmation prompt")
	cmd.Flags().StringVar(&state, "state", "error,creating,pending", "Comma-separated states to prune")
	cmd.Flags().BoolVar(&dryRun, "dry-run", false, "Show what would be pruned without deleting")
	return cmd
}

func envNukeCmd() *cobra.Command {
	var yes bool

	cmd := &cobra.Command{
		Use:   "nuke",
		Short: "Delete ALL environments",
		Long:  "Delete every environment in the current org. Requires typed confirmation unless --yes is passed.",
		RunE: func(cmd *cobra.Command, args []string) error {
			orgID, client, err := getOrgContext(cmd)
			if err != nil {
				return err
			}

			envs, err := client.ListEnvironments(orgID, "", "", false)
			if err != nil {
				return fmt.Errorf("list environments: %w", err)
			}

			// Filter out protected environments.
			var targets []platform.Environment
			var skippedProtected int
			for _, e := range envs {
				if e.Protected {
					skippedProtected++
					continue
				}
				targets = append(targets, e)
			}

			if skippedProtected > 0 {
				fmt.Fprintf(os.Stderr, "  Skipped %d protected environment(s).\n", skippedProtected)
			}

			if len(targets) == 0 {
				fmt.Println("No environments to nuke.")
				return nil
			}
			envs = targets

			cfg, _ := platform.LoadConfig()
			orgLabel := orgID
			if cfg != nil && cfg.DefaultOrg != "" {
				orgLabel = cfg.DefaultOrg
			}

			fmt.Printf("This will DELETE ALL %d environments in org %q.\n\n", len(envs), orgLabel)

			w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
			tableHeader(w, "ID", "NAME", "STATE")
			for _, e := range envs {
				name := "--"
				if e.Name != nil {
					name = *e.Name
				}
				fmt.Fprintf(w, "%s\t%s\t%s\n", dim(e.ID), name, stateColor(e.State))
			}
			w.Flush()
			fmt.Println()

			if !yes {
				expected := fmt.Sprintf("nuke %d environments", len(envs))
				answer, err := prompt(fmt.Sprintf("Type %q to confirm: ", expected))
				if err != nil {
					return err
				}
				if answer != expected {
					fmt.Println("Aborted.")
					return nil
				}
			}

			deleted := 0
			for _, e := range envs {
				if err := client.DeleteEnvironment(orgID, e.ID); err != nil {
					fmt.Fprintf(os.Stderr, "Failed to delete %s: %v\n", e.ID, err)
					continue
				}
				label := e.ID
				if e.Name != nil {
					label = fmt.Sprintf("%s (%s)", e.ID, *e.Name)
				}
				successMsg("Deleted %s.", label)
				deleted++
			}

			successMsg("Nuked %d environments.", deleted)
			return nil
		},
	}

	cmd.Flags().BoolVarP(&yes, "yes", "y", false, "Skip typed confirmation")
	return cmd
}

func envLogsCmd() *cobra.Command {
	var follow bool

	cmd := &cobra.Command{
		Use:               "logs <id>",
		Short:             "Show environment setup logs",
		Args:              cobra.ExactArgs(1),
		ValidArgsFunction: envCompletionFunc,
		RunE: func(cmd *cobra.Command, args []string) error {
			orgID, client, err := getOrgContext(cmd)
			if err != nil {
				return err
			}

			envID, err := resolveEnvID(client, orgID, args[0])
			if err != nil {
				return err
			}

			if follow {
				return followEnvironmentLogs(client, orgID, envID)
			}

			// Non-follow: fetch and print historical logs.
			logs, err := client.GetEnvironmentLogs(orgID, envID)
			if err != nil {
				return fmt.Errorf("get environment logs: %w", err)
			}
			if len(logs) == 0 {
				fmt.Println("No logs yet.")
				return nil
			}

			phases := make(map[string]time.Time)
			for _, ev := range logs {
				// Use the event's own created_at for elapsed calculation.
				if ev.Status == "started" {
					t, err := time.Parse(time.RFC3339, ev.CreatedAt)
					if err == nil {
						phases[ev.Phase] = t
					}
				}
				renderEnvLogEventHistorical(ev, phases)
			}
			return nil
		},
	}

	cmd.Flags().BoolVarP(&follow, "follow", "f", true, "Follow live logs (default: true)")
	return cmd
}

// renderEnvLogEventHistorical prints a historical log event with server-side timestamps.
func renderEnvLogEventHistorical(ev platform.EnvironmentLog, phases map[string]time.Time) {
	switch ev.Status {
	case "started":
		fmt.Fprintf(os.Stderr, "  %s %s...\n", yellowErr("◌"), ev.Message)
	case "completed":
		elapsed := ""
		if start, ok := phases[ev.Phase]; ok {
			end, err := time.Parse(time.RFC3339, ev.CreatedAt)
			if err == nil {
				elapsed = fmt.Sprintf("  %s", end.Sub(start).Truncate(time.Second))
			}
		}
		fmt.Fprintf(os.Stderr, "  %s %s%s\n", greenErr("✓"), ev.Message, elapsed)
	case "warning":
		fmt.Fprintf(os.Stderr, "  %s %s\n", yellowErr("!"), ev.Message)
	case "failed":
		fmt.Fprintf(os.Stderr, "  %s %s\n", redErr("✗"), ev.Message)
	default:
		fmt.Fprintf(os.Stderr, "  · %s\n", ev.Message)
	}
}

// codewireSlugs are image names that resolve to ghcr.io/codewiresh/<slug>.
var codewireSlugs = map[string]bool{
	"base": true, "full": true,
}

// expandImageRef applies Docker-like image name expansion:
//   - Has registry domain (first segment contains "." or ":") → as-is
//   - Known codewire slug (base, full, etc.) → ghcr.io/codewiresh/<slug>
//   - No "/" → docker.io/library/<image> (official image)
//   - One "/" → docker.io/<image> (user image)
func expandImageRef(image string) string {
	// Split name from tag.
	name, tag, hasTag := strings.Cut(image, ":")

	// Check if first path segment looks like a registry domain.
	if slash := strings.Index(name, "/"); slash > 0 {
		firstSeg := name[:slash]
		if strings.Contains(firstSeg, ".") || strings.Contains(firstSeg, ":") {
			return image // fully qualified
		}
	}

	if codewireSlugs[name] {
		ref := "ghcr.io/codewiresh/" + name
		if hasTag {
			return ref + ":" + tag
		}
		return ref + ":latest"
	}

	if !strings.Contains(name, "/") {
		// Bare name → Docker Hub official image.
		ref := "docker.io/library/" + name
		if hasTag {
			return ref + ":" + tag
		}
		return ref + ":latest"
	}

	// user/repo → Docker Hub user image.
	ref := "docker.io/" + name
	if hasTag {
		return ref + ":" + tag
	}
	return ref + ":latest"
}

// ── Protection commands ───────────────────────────────────────────────

func envProtectCmd() *cobra.Command {
	return &cobra.Command{
		Use:               "protect <id-or-name>",
		Short:             "Protect an environment from deletion",
		Args:              cobra.ExactArgs(1),
		ValidArgsFunction: envCompletionFunc,
		RunE: func(cmd *cobra.Command, args []string) error {
			orgID, client, err := getOrgContext(cmd)
			if err != nil {
				return err
			}
			envID, err := resolveEnvID(client, orgID, args[0])
			if err != nil {
				return err
			}
			resp, err := client.ProtectEnvironment(orgID, envID)
			if err != nil {
				return fmt.Errorf("protect environment: %w", err)
			}
			successMsg("Environment %s: %s.", args[0], resp.Status)
			return nil
		},
	}
}

func envUnprotectCmd() *cobra.Command {
	return &cobra.Command{
		Use:               "unprotect <id-or-name>",
		Short:             "Remove deletion protection from an environment",
		Args:              cobra.ExactArgs(1),
		ValidArgsFunction: envCompletionFunc,
		RunE: func(cmd *cobra.Command, args []string) error {
			orgID, client, err := getOrgContext(cmd)
			if err != nil {
				return err
			}
			envID, err := resolveEnvID(client, orgID, args[0])
			if err != nil {
				return err
			}
			resp, err := client.UnprotectEnvironment(orgID, envID)
			if err != nil {
				return fmt.Errorf("unprotect environment: %w", err)
			}
			successMsg("Environment %s: %s.", args[0], resp.Status)
			return nil
		},
	}
}

func envCancelDeleteCmd() *cobra.Command {
	return &cobra.Command{
		Use:               "cancel-delete <id-or-name>",
		Short:             "Cancel a pending environment deletion",
		Args:              cobra.ExactArgs(1),
		ValidArgsFunction: envCompletionFunc,
		RunE: func(cmd *cobra.Command, args []string) error {
			orgID, client, err := getOrgContext(cmd)
			if err != nil {
				return err
			}
			envID, err := resolveEnvID(client, orgID, args[0])
			if err != nil {
				return err
			}
			resp, err := client.CancelDeletion(orgID, envID)
			if err != nil {
				return fmt.Errorf("cancel deletion: %w", err)
			}
			successMsg("Environment %s: %s.", args[0], resp.Status)
			return nil
		},
	}
}

func envExtendCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:               "extend <id-or-name>",
		Short:             "Extend the TTL of an environment",
		Args:              cobra.ExactArgs(1),
		ValidArgsFunction: envCompletionFunc,
		RunE: func(cmd *cobra.Command, args []string) error {
			orgID, client, err := getOrgContext(cmd)
			if err != nil {
				return err
			}
			envID, err := resolveEnvID(client, orgID, args[0])
			if err != nil {
				return err
			}
			hours, _ := cmd.Flags().GetInt("hours")
			if hours <= 0 {
				hours = 1
			}
			resp, err := client.ExtendTTL(orgID, envID, hours*3600)
			if err != nil {
				return fmt.Errorf("extend TTL: %w", err)
			}
			successMsg("Environment %s: %s (%d hours added).", args[0], resp.Status, hours)
			return nil
		},
	}
	cmd.Flags().Int("hours", 1, "Hours to extend TTL by")
	return cmd
}

// ── Access management ─────────────────────────────────────────────────

func envAccessCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "access",
		Short: "Manage environment access",
	}
	cmd.AddCommand(envAccessListCmd())
	cmd.AddCommand(envAccessGrantCmd())
	cmd.AddCommand(envAccessRevokeCmd())
	return cmd
}

func envAccessListCmd() *cobra.Command {
	return &cobra.Command{
		Use:               "list <id-or-name>",
		Short:             "List access grants for an environment",
		Args:              cobra.ExactArgs(1),
		ValidArgsFunction: envCompletionFunc,
		RunE: func(cmd *cobra.Command, args []string) error {
			orgID, client, err := getOrgContext(cmd)
			if err != nil {
				return err
			}
			envID, err := resolveEnvID(client, orgID, args[0])
			if err != nil {
				return err
			}
			grants, err := client.ListAccess(orgID, envID)
			if err != nil {
				return fmt.Errorf("list access: %w", err)
			}
			if len(grants) == 0 {
				fmt.Println("No explicit access grants (creator has implicit owner access).")
				return nil
			}
			tw := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
			fmt.Fprintln(tw, "USER ID\tPERMISSION\tGRANTED BY\tCREATED AT")
			for _, g := range grants {
				fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", g.UserID, g.Permission, g.GrantedBy, g.CreatedAt)
			}
			tw.Flush()
			return nil
		},
	}
}

func envAccessGrantCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "grant <id-or-name>",
		Short: "Grant a user access to an environment",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			orgID, client, err := getOrgContext(cmd)
			if err != nil {
				return err
			}
			envID, err := resolveEnvID(client, orgID, args[0])
			if err != nil {
				return err
			}
			userID, _ := cmd.Flags().GetString("user")
			permission, _ := cmd.Flags().GetString("permission")
			if userID == "" {
				return fmt.Errorf("--user is required")
			}
			if permission == "" {
				permission = "viewer"
			}
			err = client.GrantAccess(orgID, envID, &platform.GrantAccessRequest{
				UserID:     userID,
				Permission: permission,
			})
			if err != nil {
				return fmt.Errorf("grant access: %w", err)
			}
			successMsg("Granted %s access to %s for user %s.", permission, args[0], userID)
			return nil
		},
	}
	cmd.Flags().String("user", "", "User ID to grant access to")
	cmd.Flags().String("permission", "viewer", "Permission level: owner, operator, or viewer")
	_ = cmd.MarkFlagRequired("user")
	return cmd
}

func envAccessRevokeCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "revoke <id-or-name>",
		Short: "Revoke a user's access to an environment",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			orgID, client, err := getOrgContext(cmd)
			if err != nil {
				return err
			}
			envID, err := resolveEnvID(client, orgID, args[0])
			if err != nil {
				return err
			}
			userID, _ := cmd.Flags().GetString("user")
			if userID == "" {
				return fmt.Errorf("--user is required")
			}
			err = client.RevokeAccess(orgID, envID, userID)
			if err != nil {
				return fmt.Errorf("revoke access: %w", err)
			}
			successMsg("Revoked access for user %s on %s.", userID, args[0])
			return nil
		},
	}
	cmd.Flags().String("user", "", "User ID to revoke access from")
	_ = cmd.MarkFlagRequired("user")
	return cmd
}
