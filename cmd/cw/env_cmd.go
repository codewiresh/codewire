package main

import (
	"fmt"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

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
	cmd.AddCommand(envCreateCmd())
	cmd.AddCommand(envListCmd())
	cmd.AddCommand(envInfoCmd())
	cmd.AddCommand(envStopCmd())
	cmd.AddCommand(envStartCmd())
	cmd.AddCommand(envRmCmd())
	cmd.AddCommand(envExecCmd())
	cmd.AddCommand(envSSHCmd())
	cmd.AddCommand(envCpCmd())
	return cmd
}

func getDefaultOrg() (string, *platform.Client, error) {
	client, err := platform.NewClient()
	if err != nil {
		return "", nil, err
	}
	cfg, err := platform.LoadConfig()
	if err != nil {
		return "", nil, err
	}
	if cfg.DefaultOrg == "" {
		return "", nil, fmt.Errorf("no default org set. Run 'cw login' and set a default org")
	}
	return cfg.DefaultOrg, client, nil
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

func envCreateCmd() *cobra.Command {
	var (
		templateSlug   string
		templateID     string
		name           string
		ttl            string
		cpu            int
		memory         int
		disk           int
		repoURL        string
		branch         string
		image          string
		install        string
		startup        string
		agent          string
		envVars        []string
		secretProject  string
		noOrgSecrets   bool
		noUserSecrets  bool
	)

	cmd := &cobra.Command{
		Use:   "create [repo-url]",
		Short: "Create a new environment",
		Long: `Create a new environment. Smart create detects configuration from a repo URL.

Examples:
  cw env create https://github.com/foo/bar
  cw env create --template go --name my-env
  cw env create --image go --name my-env
  cw env create --secrets my-project https://github.com/foo/bar`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			// Positional arg is repo URL.
			if len(args) == 1 {
				repoURL = args[0]
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

			orgID, client, err := getDefaultOrg()
			if err != nil {
				return err
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

			// Image shorthand: if no slash, resolve to workspace image.
			if image != "" && !strings.Contains(image, "/") {
				image = "ghcr.io/codewiresh/workspace-" + image + ":latest"
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
			if len(parsedEnvVars) > 0 {
				req.EnvVars = parsedEnvVars
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
			fmt.Printf("Environment created: %s\n", envName)
			fmt.Printf("  ID:    %s\n", env.ID)
			fmt.Printf("  State: %s\n", env.State)
			fmt.Printf("  Type:  %s\n", env.Type)
			fmt.Printf("  CPU:   %dm\n", env.CPUMillicores)
			fmt.Printf("  Mem:   %dMB\n", env.MemoryMB)
			fmt.Printf("  Disk:  %dGB\n", env.DiskGB)
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
	cmd.Flags().StringVar(&repoURL, "repo", "", "Git repo URL")
	cmd.Flags().StringVar(&branch, "branch", "", "Branch to checkout")
	cmd.Flags().StringVar(&image, "image", "", "Container image (shorthand: go → workspace-go)")
	cmd.Flags().StringVar(&install, "install", "", "Install command")
	cmd.Flags().StringVar(&startup, "startup", "", "Startup script")
	cmd.Flags().StringVar(&agent, "agent", "", "AI agent (claude-code)")
	cmd.Flags().StringSliceVar(&envVars, "env", nil, "Env vars (KEY=val)")
	cmd.Flags().StringVar(&secretProject, "secrets", "", "Secret project to bind")
	cmd.Flags().BoolVar(&noOrgSecrets, "no-org-secrets", false, "Don't inject org-level secrets")
	cmd.Flags().BoolVar(&noUserSecrets, "no-user-secrets", false, "Don't inject user-level secrets")
	return cmd
}

func envListCmd() *cobra.Command {
	var (
		envType string
		state   string
	)

	cmd := &cobra.Command{
		Use:     "list",
		Short:   "List environments",
		Aliases: []string{"ls"},
		RunE: func(cmd *cobra.Command, args []string) error {
			orgID, client, err := getDefaultOrg()
			if err != nil {
				return err
			}

			envs, err := client.ListEnvironments(orgID, envType, state)
			if err != nil {
				return fmt.Errorf("list environments: %w", err)
			}

			if len(envs) == 0 {
				fmt.Println("No environments found.")
				return nil
			}

			w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
			fmt.Fprintln(w, "ID\tNAME\tSTATE\tTYPE\tCPU/MEM\tTTL\tCREATED")
			for _, e := range envs {
				envName := "--"
				if e.Name != nil {
					envName = *e.Name
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

				fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
					e.ID, envName, e.State, e.Type, cpuMem, ttlStr, timeAgo(e.CreatedAt))
			}
			return w.Flush()
		},
	}

	cmd.Flags().StringVar(&envType, "type", "", "Filter by type (coder, sandbox)")
	cmd.Flags().StringVar(&state, "state", "", "Filter by state")
	return cmd
}

func envInfoCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "info <id>",
		Short: "Show environment details",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			orgID, client, err := getDefaultOrg()
			if err != nil {
				return err
			}

			env, err := client.GetEnvironment(orgID, args[0])
			if err != nil {
				return fmt.Errorf("get environment: %w", err)
			}

			envName := "--"
			if env.Name != nil {
				envName = *env.Name
			}

			fmt.Printf("ID:            %s\n", env.ID)
			fmt.Printf("Name:          %s\n", envName)
			fmt.Printf("Type:          %s\n", env.Type)
			fmt.Printf("State:         %s\n", env.State)
			fmt.Printf("DesiredState:  %s\n", env.DesiredState)
			fmt.Printf("TemplateID:    %s\n", env.TemplateID)
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
		Use:   "stop <id>",
		Short: "Stop an environment",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			orgID, client, err := getDefaultOrg()
			if err != nil {
				return err
			}

			resp, err := client.StopEnvironment(orgID, args[0])
			if err != nil {
				return fmt.Errorf("stop environment: %w", err)
			}
			fmt.Printf("Environment %s: %s\n", args[0], resp.Status)
			return nil
		},
	}
}

func envStartCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "start <id>",
		Short: "Start an environment",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			orgID, client, err := getDefaultOrg()
			if err != nil {
				return err
			}

			resp, err := client.StartEnvironment(orgID, args[0])
			if err != nil {
				return fmt.Errorf("start environment: %w", err)
			}
			fmt.Printf("Environment %s: %s\n", args[0], resp.Status)
			return nil
		},
	}
}

func envRmCmd() *cobra.Command {
	return &cobra.Command{
		Use:     "rm <id>",
		Short:   "Delete an environment",
		Aliases: []string{"delete"},
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			orgID, client, err := getDefaultOrg()
			if err != nil {
				return err
			}

			if err := client.DeleteEnvironment(orgID, args[0]); err != nil {
				return fmt.Errorf("delete environment: %w", err)
			}
			fmt.Printf("Environment %s deleted.\n", args[0])
			return nil
		},
	}
}

