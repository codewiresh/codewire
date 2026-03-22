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
	cmd.AddCommand(envExecCmd())
	cmd.AddCommand(envCpCmd())
	cmd.AddCommand(envPruneCmd())
	cmd.AddCommand(envNukeCmd())
	cmd.AddCommand(envLogsCmd())
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

func envCompletionFunc(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
	orgID, client, err := getOrgContext(cmd)
	if err != nil {
		return nil, cobra.ShellCompDirectiveNoFileComp
	}
	envs, err := client.ListEnvironments(orgID, "", "", false)
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
	if detection.TemplateImage != "" {
		fmt.Fprintf(os.Stderr, "  Image:    %s\n", detection.TemplateImage)
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

type envRelayEnrollment struct {
	RelayURL    string
	NetworkID   string
	InviteToken string
}

func resolveEnvRelayEnrollment(dir string, assumeYes bool, requestedNetwork string, disableNetwork bool) (*envRelayEnrollment, error) {
	if disableNetwork {
		return nil, nil
	}
	requestedNetwork = strings.TrimSpace(requestedNetwork)

	cfg, err := cwconfig.LoadConfig(dir)
	if err != nil {
		if requestedNetwork != "" {
			return nil, fmt.Errorf("relay is not configured locally (run 'cw relay setup' or 'cw relay create' first)")
		}
		return nil, nil
	}
	if cfg.RelayURL == nil || *cfg.RelayURL == "" {
		if requestedNetwork != "" {
			return nil, fmt.Errorf("relay URL is not configured locally")
		}
		return nil, nil
	}
	if cfg.RelaySession == nil || *cfg.RelaySession == "" {
		if requestedNetwork != "" {
			return nil, fmt.Errorf("relay auth is not configured locally (run 'cw login' or set CODEWIRE_RELAY_SESSION')")
		}
		return nil, nil
	}

	networkID := requestedNetwork
	if networkID == "" {
		if cfg.RelayNetwork == nil || strings.TrimSpace(*cfg.RelayNetwork) == "" {
			return nil, nil
		}
		if cfg.RelayAutoJoinPrivate == nil {
			approved := assumeYes
			if !assumeYes {
				approved, err = promptConfirm(fmt.Sprintf("New environments will auto-join your private network %q for remote access. Continue", *cfg.RelayNetwork))
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
		networkID = *cfg.RelayNetwork
	}

	invite, err := cwclient.CreateInvite(dir, cwclient.RelayAuthOptions{
		RelayURL:  *cfg.RelayURL,
		AuthToken: *cfg.RelaySession,
		NetworkID: networkID,
	}, 1, "24h")
	if err != nil {
		return nil, fmt.Errorf("create relay invite for env: %w", err)
	}

	return &envRelayEnrollment{
		RelayURL:    *cfg.RelayURL,
		NetworkID:   networkID,
		InviteToken: invite.Token,
	}, nil
}

func envCreateCmd() *cobra.Command {
	var (
		templateSlug  string
		templateID    string
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
  cw env create --template go --name my-env
  cw env create --image go --name my-env
  cw env create --secrets my-project https://github.com/foo/bar
  cw env create --network project-alpha https://github.com/foo/bar`,
		Args: cobra.ArbitraryArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			// Collect repos from positional args + --repo flags.
			var repoURL string
			var repos []platform.RepoEntry

			allRepoSpecs := append(args, repoFlags...)
			for _, spec := range allRepoSpecs {
				u, b := parseRepoSpec(spec)
				repos = append(repos, platform.RepoEntry{URL: u, Branch: b})
			}

			// Single repo: also set repoURL for backward compat.
			if len(repos) == 1 {
				repoURL = repos[0].URL
				if repos[0].Branch != "" && branch == "" {
					branch = repos[0].Branch
				}
			} else if len(repos) > 1 {
				repoURL = repos[0].URL
			}

			// 0-arg support: look for ./codewire.yaml
			if templateSlug == "" && templateID == "" && image == "" && repoURL == "" {
				cfg, err := loadCodewireYAML("codewire.yaml")
				if err == nil {
					fmt.Println("Using ./codewire.yaml")
					if cfg.Template != "" && templateSlug == "" {
						templateSlug = cfg.Template
					}
					if cfg.Install != "" && install == "" {
						install = cfg.Install
					}
					if cfg.Startup != "" && startup == "" {
						startup = cfg.Startup
					}
					if cfg.Secrets != "" && secretProject == "" {
						secretProject = cfg.Secrets
					}
					if cfg.Agent != "" && agent == "" {
						agent = cfg.Agent
					}
					if cfg.CPU > 0 && cpu == 0 {
						cpu = cfg.CPU
					}
					if cfg.Memory > 0 && memory == 0 {
						memory = cfg.Memory
					}
					if cfg.Disk > 0 && disk == 0 {
						disk = cfg.Disk
					}
					if cfg.IncludeOrgSecrets != nil && !*cfg.IncludeOrgSecrets {
						noOrgSecrets = true
					}
					if cfg.IncludeUserSecrets != nil && !*cfg.IncludeUserSecrets {
						noUserSecrets = true
					}
					for k, v := range cfg.Env {
						envVars = append(envVars, k+"="+v)
					}
				} else {
					// No codewire.yaml — try to infer repo URL from git remote.
					if url, b, err := detectLocalRepo("."); err == nil && url != "" {
						repoURL = url
						if branch == "" {
							branch = b
						}
						fmt.Printf("Using repo: %s\n", repoURL)
					} else {
						return fmt.Errorf("provide a repo URL, --image, or --template")
					}
				}
			}

			orgID, client, err := getOrgContext(cmd)
			if err != nil {
				return err
			}

			var (
				detection        *platform.DetectionResult
				preparedAppPorts []platform.AppPort
			)
			if repoURL != "" || templateSlug != "" || templateID != "" || image != "" {
				var analyze *bool
				if repoURL != "" && templateSlug == "" && templateID == "" && image == "" && !yes {
					idx, promptErr := promptSelect("Do you want to auto analyze for setup suggestions?", []string{"Yes", "No"})
					if promptErr != nil {
						return promptErr
					}
					v := idx == 0
					analyze = &v
				}

				prepared, prepErr := client.PrepareLaunch(orgID, &platform.PrepareLaunchRequest{
					TemplateID:         strPtrOrNil(templateID),
					TemplateSlug:       templateSlug,
					Name:               strPtrOrNil(name),
					CPUMillicores:      intPtrOrNil(cpu),
					MemoryMB:           intPtrOrNil(memory),
					DiskGB:             intPtrOrNil(disk),
					TTLSeconds:         durationSecondsPtr(ttl),
					RepoURL:            repoURL,
					Branch:             branch,
					Repos:              repos,
					Image:              image,
					InstallCommand:     install,
					StartupScript:      startup,
					Agent:              agent,
					SecretProject:      secretProject,
					IncludeOrgSecrets:  boolPtrOrNil(!noOrgSecrets, noOrgSecrets),
					IncludeUserSecrets: boolPtrOrNil(!noUserSecrets, noUserSecrets),
					Analyze:            analyze,
				})
				if prepErr != nil {
					return fmt.Errorf("prepare launch: %w", prepErr)
				}

				if prepared.Draft.TemplateID != "" {
					templateID = prepared.Draft.TemplateID
				}
				if templateSlug == "" {
					templateSlug = prepared.Draft.TemplateSlug
				}
				if name == "" {
					name = prepared.Draft.Name
				}
				if repoURL == "" {
					repoURL = prepared.Draft.RepoURL
				}
				if branch == "" {
					branch = prepared.Draft.Branch
				}
				if len(repos) == 0 && len(prepared.Draft.Repos) > 0 {
					repos = prepared.Draft.Repos
				}
				if image == "" {
					image = prepared.Draft.Image
				}
				if install == "" {
					install = prepared.Draft.InstallCommand
				}
				if startup == "" {
					startup = prepared.Draft.StartupScript
				}
				if secretProject == "" {
					secretProject = prepared.Draft.SecretProject
				}
				if agent == "" {
					agent = prepared.Draft.Agent
				}
				if cpu == 0 && prepared.Draft.CPUMillicores != nil {
					cpu = *prepared.Draft.CPUMillicores
				}
				if memory == 0 && prepared.Draft.MemoryMB != nil {
					memory = *prepared.Draft.MemoryMB
				}
				if disk == 0 && prepared.Draft.DiskGB != nil {
					disk = *prepared.Draft.DiskGB
				}
				if ttl == "" && prepared.Draft.TTLSeconds != nil {
					ttl = fmt.Sprintf("%ds", *prepared.Draft.TTLSeconds)
				}
				preparedAppPorts = prepared.Draft.AppPorts
				detection = prepared.Detection
				printDetectionSummary(detection)

				if detection != nil && !yes {
					idx, promptErr := promptSelect("Create environment?", []string{"Yes", "Edit options", "Cancel"})
					if promptErr != nil {
						return promptErr
					}
					switch idx {
					case 2:
						return fmt.Errorf("canceled")
					case 1:
						if v, err := promptDefault("Image", image); err == nil {
							image = v
						}
						if v, err := promptDefault("Install command", install); err == nil {
							install = v
						}
						if v, err := promptDefault("Startup script", startup); err == nil {
							startup = v
						}
						if v, err := promptDefault("Environment name", name); err == nil {
							name = v
						}
					}
				}
			}

			// Parse env vars from KEY=val format.
			parsedEnvVars := make(map[string]string)
			for _, ev := range envVars {
				parts := strings.SplitN(ev, "=", 2)
				if len(parts) != 2 {
					return fmt.Errorf("invalid --env format %q, expected KEY=val", ev)
				}
				parsedEnvVars[parts[0]] = parts[1]
			}

			// Image expansion with Docker-like semantics.
			if image != "" {
				image = expandImageRef(image)
			}

			req := &platform.CreateEnvironmentRequest{
				TemplateID:     templateID,
				TemplateSlug:   templateSlug,
				Name:           name,
				RepoURL:        repoURL,
				Branch:         branch,
				Image:          image,
				InstallCommand: install,
				StartupScript:  startup,
				Agent:          agent,
				SecretProject:  secretProject,
			}
			if len(repos) > 0 {
				req.Repos = repos
			}
			if len(preparedAppPorts) > 0 {
				req.AppPorts = preparedAppPorts
			} else if detection != nil && len(detection.AppPorts) > 0 && len(req.AppPorts) == 0 {
				req.AppPorts = detection.AppPorts
			}
			if len(parsedEnvVars) > 0 {
				req.EnvVars = parsedEnvVars
			}

			enrollment, err := resolveEnvRelayEnrollment(dataDir(), yes, network, noNetwork)
			if err != nil {
				return err
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

			// Resolve Claude OAuth token if agent is claude-code.
			if agent == "claude-code" {
				token := resolveClaudeOAuthToken()
				if token != "" {
					req.AgentEnv = map[string]string{
						"CLAUDE_CODE_OAUTH_TOKEN": token,
					}
				}
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

	cmd.Flags().StringVar(&templateSlug, "template", "", "Template slug (e.g. go, node, python)")
	cmd.Flags().StringVar(&templateID, "template-id", "", "Template ID (exact)")
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
	cmd.Flags().BoolVar(&noNetwork, "no-network", false, "Don't join the default private relay network")
	cmd.Flags().BoolVarP(&follow, "follow", "f", true, "Watch startup progress and wait for readiness (default: true)")
	cmd.Flags().BoolVar(&noWait, "no-wait", false, "Return immediately after creation instead of waiting for startup")
	cmd.Flags().BoolVarP(&yes, "yes", "y", false, "Skip confirmation prompts")
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

			w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
			tableHeader(w, "ID", "NAME", "STATE", "TYPE", "CPU/MEM", "TTL", "SSH", "CREATED")
			for _, e := range envs {
				envName := "--"
				if e.Name != nil {
					envName = bold(*e.Name)
				}

				cpuMem := fmt.Sprintf("%dm/%dMB", e.CPUMillicores, e.MemoryMB)

				ttlStr := "--"
				if e.ShutdownAt != nil {
					shutdownTime, err := time.Parse(time.RFC3339, *e.ShutdownAt)
					if err == nil {
						remaining := time.Until(shutdownTime)
						if remaining > 0 {
							ttlStr = fmt.Sprintf("%dm", int(remaining.Minutes()))
						} else {
							ttlStr = "expired"
						}
					}
				}

				sshHost := ""
				if e.Type == "sandbox" && e.State == "running" {
					sshHost = "cw-" + e.ID
				}

				fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
					dim(e.ID), envName, stateColor(e.State), e.Type, cpuMem, ttlStr, sshHost, timeAgo(e.CreatedAt))
			}
			return w.Flush()
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
			fmt.Printf("%-14s %s\n", bold("State:"), stateColor(env.State))
			fmt.Printf("%-14s %s\n", bold("DesiredState:"), stateColor(env.DesiredState))
			fmt.Printf("%-14s %s\n", bold("TemplateID:"), dim(env.TemplateID))
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
			for _, e := range envs {
				if pruneStates[e.State] {
					targets = append(targets, e)
				}
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

			if len(envs) == 0 {
				fmt.Println("No environments to nuke.")
				return nil
			}

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
		Short:             "Show environment startup logs",
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
