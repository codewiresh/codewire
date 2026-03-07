package main

import (
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"path"
	"runtime"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/codewiresh/codewire/internal/platform"
)

func launchCmd() *cobra.Command {
	var (
		branch         string
		templateName   string
		templateID     string
		resourceID     string
		noWait         bool
		yes            bool
		cpu            string
		memory         string
		image          string
		installCommand string
		startupScript  string
	)

	cmd := &cobra.Command{
		Use:   "launch <repo-url|directory>",
		Short: "Create a workspace from a repo URL or local directory",
		Long:  "Create a new workspace on the default Coder resource, cloning the given repository.\nUses AI to detect the project type and configure the workspace automatically.\n\nPass '.' or a local directory to detect the git remote and use that.",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			repoURL := args[0]

			// Detect local directory → resolve git remote
			if isLocalPath(repoURL) {
				detected, detectedBranch, err := detectLocalRepo(repoURL)
				if err != nil {
					return fmt.Errorf("detect local repo: %w", err)
				}
				repoURL = detected
				if branch == "" && detectedBranch != "" {
					branch = detectedBranch
				}
				fmt.Printf("Detected remote: %s", repoURL)
				if branch != "" {
					fmt.Printf(" (branch: %s)", branch)
				}
				fmt.Println()
			}

			client, err := platform.NewClient()
			if err != nil {
				return err
			}

			// Check GitHub connection if detection might fail
			ghStatus, ghErr := client.GetGitHubStatus()
			if ghErr == nil && !ghStatus.Connected {
				fmt.Println("Tip: Connect GitHub for private repo access: cw github login")
			}

			// Call detection endpoint first (before resource resolution)
			fmt.Printf("Analyzing %s...\n", repoURL)
			detection, err := client.DetectRepo(repoURL, branch)
			if err != nil {
				errMsg := err.Error()
				if (ghStatus == nil || !ghStatus.Connected) && (strings.Contains(errMsg, "404") || strings.Contains(errMsg, "failed to fetch repo")) {
					fmt.Printf("Detection failed (possibly private repo): %v\n", err)
					fmt.Println("Connect GitHub for private repo access: cw github login")
				} else {
					fmt.Printf("Detection failed: %v\nFalling back to defaults.\n", err)
				}
				detection = nil
			}

			// Derive workspace name
			wsName := deriveWorkspaceName(repoURL)
			if detection != nil && detection.SuggestedName != "" {
				wsName = detection.SuggestedName
			}

			// Apply detection results, CLI flags override
			if detection != nil {
				fmt.Printf("\nDetected: %s", detection.Language)
				if detection.Framework != "" {
					fmt.Printf(" (%s)", detection.Framework)
				}
				fmt.Println()
				if detection.TemplateImage != "" {
					fmt.Printf("  Image:    %s\n", detection.TemplateImage)
				}
				if detection.InstallCommand != "" {
					fmt.Printf("  Install:  %s\n", detection.InstallCommand)
				}
				if detection.StartupScript != "" {
					lines := strings.Split(detection.StartupScript, "\n")
					if len(lines) == 1 {
						fmt.Printf("  Script:   %s\n", detection.StartupScript)
					} else {
						fmt.Printf("  Script:   %s (+%d lines)\n", lines[0], len(lines)-1)
					}
				}
				if len(detection.Services) > 0 {
					var svcParts []string
					for _, s := range detection.Services {
						svcParts = append(svcParts, fmt.Sprintf("%s:%d", s.Name, s.Port))
					}
					fmt.Printf("  Services: %s\n", strings.Join(svcParts, ", "))
				}
				if detection.SetupNotes != "" {
					fmt.Printf("  Notes:    %s\n", detection.SetupNotes)
				}
				fmt.Println()

				// Use detected values as defaults; CLI flags override
				if image == "" {
					image = detection.TemplateImage
				}
				if installCommand == "" {
					installCommand = detection.InstallCommand
				}
				if startupScript == "" {
					startupScript = detection.StartupScript
				}
				if cpu == "" {
					cpu = detection.CPU
				}
				if memory == "" {
					memory = detection.Memory
				}
			}

			// Confirm unless --yes
			if !yes {
				idx, err := promptSelect("Launch workspace?", []string{"Yes", "Edit options", "Cancel"})
				if err != nil {
					return err
				}
				switch idx {
				case 2: // Cancel
					return fmt.Errorf("canceled")
				case 1: // Edit options
					if v, err := promptDefault("Image", image); err == nil {
						image = v
					}
					if v, err := promptDefault("Install command", installCommand); err == nil {
						installCommand = v
					}
					if v, err := promptDefault("Startup script", startupScript); err == nil {
						startupScript = v
					}
					if v, err := promptDefault("CPU cores", cpu); err == nil {
						cpu = v
					}
					if v, err := promptDefault("Memory (GB)", memory); err == nil {
						memory = v
					}
					if v, err := promptDefault("Workspace name", wsName); err == nil {
						wsName = v
					}
				}
			}

			// Resolve resource ID
			resID := resourceID
			if resID == "" {
				cfg, err := platform.LoadConfig()
				if err != nil || cfg.DefaultResource == "" {
					return fmt.Errorf("no default resource set (run 'cw setup' or pass --resource)")
				}
				resID = cfg.DefaultResource
			}

			// Use auto-launch template by name
			tmplName := templateName
			if tmplName == "" && templateID == "" {
				tmplName = "auto-launch"
			}

			// Build git_repos JSON from the repo URL
			gitRepos := map[string]string{wsName: repoURL}
			gitReposJSON, _ := json.Marshal(gitRepos)

			// Build rich parameters
			var params []platform.RichParameterValue
			params = append(params, platform.RichParameterValue{Name: "project_name", Value: wsName})
			params = append(params, platform.RichParameterValue{Name: "git_repos", Value: string(gitReposJSON)})
			if branch != "" {
				params = append(params, platform.RichParameterValue{Name: "issue_branch", Value: branch})
			}
			if installCommand != "" {
				params = append(params, platform.RichParameterValue{Name: "install_command", Value: installCommand})
			}
			if startupScript != "" {
				params = append(params, platform.RichParameterValue{Name: "startup_script", Value: startupScript})
			}
			if image != "" {
				params = append(params, platform.RichParameterValue{Name: "image", Value: image})
			}
			if cpu != "" {
				params = append(params, platform.RichParameterValue{Name: "cpu", Value: cpu})
			}
			if memory != "" {
				params = append(params, platform.RichParameterValue{Name: "memory", Value: memory})
			}

			// Pass Claude OAuth token (preferred) or API key for workspace auth.
			// Priority: CLAUDE_CODE_OAUTH_TOKEN env > ~/.claude/.credentials.json > CLAUDE_API_KEY > ANTHROPIC_API_KEY
			if token := resolveClaudeOAuthToken(); token != "" {
				params = append(params, platform.RichParameterValue{Name: "claude_code_oauth_token", Value: token})
			}
			if key := os.Getenv("CLAUDE_API_KEY"); key != "" {
				params = append(params, platform.RichParameterValue{Name: "claude_api_key", Value: key})
			} else if key := os.Getenv("ANTHROPIC_API_KEY"); key != "" {
				params = append(params, platform.RichParameterValue{Name: "claude_api_key", Value: key})
			}

			fmt.Printf("Creating workspace %q...\n", wsName)
			ws, err := client.CreateWorkspace(resID, &platform.CreateWorkspaceRequest{
				Name:         wsName,
				TemplateID:   templateID,
				TemplateName: tmplName,
				RichParams:   params,
			})
			if err != nil {
				return fmt.Errorf("create workspace: %w", err)
			}

			if noWait {
				_ = platform.SetCurrentWorkspace(ws.Name)
				fmt.Printf("Workspace %q is now active. (status: %s)\n", ws.Name, ws.Status)
				return nil
			}

			// Wait for workspace to be running
			fmt.Print("Waiting for workspace to start...")
			ws, err = client.WaitForWorkspace(resID, ws.ID, 5*time.Minute)
			if err != nil {
				fmt.Println(" timeout")
				return err
			}
			fmt.Printf(" %s\n", ws.Status)

			if ws.Status != "running" {
				return fmt.Errorf("workspace ended with status: %s", ws.Status)
			}

			_ = platform.SetCurrentWorkspace(ws.Name)
			fmt.Printf("\nWorkspace %q is now active.\n", ws.Name)
			fmt.Printf("  cw run -- <command>  # Run in workspace\n")
			fmt.Printf("  cw open              # Open in browser\n")
			return nil
		},
	}

	cmd.Flags().StringVar(&branch, "branch", "", "Branch to checkout (default: repo default)")
	cmd.Flags().StringVar(&templateName, "template", "", "Template name (default: auto-launch)")
	cmd.Flags().StringVar(&templateID, "template-id", "", "Template ID")
	cmd.Flags().StringVar(&resourceID, "resource", "", "Resource ID (default: from config)")
	cmd.Flags().BoolVar(&noWait, "no-wait", false, "Don't wait for workspace to start")
	cmd.Flags().BoolVarP(&yes, "yes", "y", false, "Skip confirmation prompt")
	cmd.Flags().StringVar(&cpu, "cpu", "", "CPU cores (default: from detection)")
	cmd.Flags().StringVar(&memory, "memory", "", "Memory in GB (default: from detection)")
	cmd.Flags().StringVar(&image, "image", "", "Template image (default: from detection)")
	cmd.Flags().StringVar(&installCommand, "install-command", "", "Install command (default: from detection)")
	cmd.Flags().StringVar(&startupScript, "startup-script", "", "Startup script (default: from detection)")
	return cmd
}

func openCmd() *cobra.Command {
	var resourceID string

	cmd := &cobra.Command{
		Use:   "open [workspace]",
		Short: "Open workspace in browser",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			explicit := ""
			if len(args) > 0 {
				explicit = args[0]
			}
			wsName := resolveWorkspaceName(explicit)
			if wsName == "" {
				wsName = platform.GetCurrentWorkspace()
			}
			if wsName == "" {
				return fmt.Errorf("no workspace specified\n\nUsage: cw <workspace> open\n   or: cw open <workspace>")
			}

			client, err := platform.NewClient()
			if err != nil {
				return err
			}

			resID := resourceID
			if resID == "" {
				cfg, _ := platform.LoadConfig()
				if cfg != nil {
					resID = cfg.DefaultResource
				}
			}
			if resID == "" {
				return fmt.Errorf("no resource specified (pass --resource or run 'cw setup')")
			}

			res, err := client.GetResource(resID)
			if err != nil {
				return fmt.Errorf("get resource: %w", err)
			}

			var domain string
			if m, ok := (*res.Metadata)["domain"].(string); ok {
				domain = m
			}
			if domain == "" {
				return fmt.Errorf("resource has no domain")
			}

			wsURL := fmt.Sprintf("https://%s/@admin/%s", domain, wsName)
			fmt.Printf("Opening %s\n", wsURL)
			return openBrowser(wsURL)
		},
	}

	cmd.Flags().StringVar(&resourceID, "resource", "", "Resource ID (default: from config)")
	return cmd
}

func workspaceStartCmd() *cobra.Command {
	var resourceID string

	cmd := &cobra.Command{
		Use:   "start [workspace]",
		Short: "Start a stopped workspace",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			explicit := ""
			if len(args) > 0 {
				explicit = args[0]
			}
			wsName := resolveWorkspaceName(explicit)
			if wsName == "" {
				wsName = platform.GetCurrentWorkspace()
			}
			if wsName == "" {
				return fmt.Errorf("no workspace specified\n\nUsage: cw <workspace> start\n   or: cw start <workspace>")
			}

			client, resID, err := resolveResourceClient(resourceID)
			if err != nil {
				return err
			}
			if err := client.StartWorkspace(resID, wsName); err != nil {
				return fmt.Errorf("start workspace: %w", err)
			}
			fmt.Println("Workspace starting.")
			return nil
		},
	}

	cmd.Flags().StringVar(&resourceID, "resource", "", "Resource ID (default: from config)")
	return cmd
}

func workspaceStopCmd() *cobra.Command {
	var resourceID string

	cmd := &cobra.Command{
		Use:   "stop [workspace]",
		Short: "Stop a running workspace",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			explicit := ""
			if len(args) > 0 {
				explicit = args[0]
			}
			wsName := resolveWorkspaceName(explicit)
			if wsName == "" {
				wsName = platform.GetCurrentWorkspace()
			}
			if wsName == "" {
				return fmt.Errorf("no workspace specified\n\nUsage: cw <workspace> stop\n   or: cw stop <workspace>")
			}

			client, resID, err := resolveResourceClient(resourceID)
			if err != nil {
				return err
			}
			if err := client.StopWorkspace(resID, wsName); err != nil {
				return fmt.Errorf("stop workspace: %w", err)
			}
			fmt.Println("Workspace stopping.")
			return nil
		},
	}

	cmd.Flags().StringVar(&resourceID, "resource", "", "Resource ID (default: from config)")
	return cmd
}

func workspacesListCmd() *cobra.Command {
	var (
		resourceID string
		jsonOutput bool
	)

	cmd := &cobra.Command{
		Use:   "workspaces",
		Short: "List workspaces on a resource",
		RunE: func(cmd *cobra.Command, args []string) error {
			client, resID, err := resolveResourceClient(resourceID)
			if err != nil {
				return err
			}

			resp, err := client.ListWorkspaces(resID)
			if err != nil {
				return fmt.Errorf("list workspaces: %w", err)
			}

			if jsonOutput {
				enc := json.NewEncoder(os.Stdout)
				enc.SetIndent("", "  ")
				return enc.Encode(resp.Workspaces)
			}

			if len(resp.Workspaces) == 0 {
				fmt.Println("No workspaces.")
				return nil
			}

			for _, ws := range resp.Workspaces {
				fmt.Printf("  %-20s %-10s %s\n", ws.Name, ws.Status, ws.TemplateDisplayName)
			}
			return nil
		},
	}

	cmd.Flags().StringVar(&resourceID, "resource", "", "Resource ID (default: from config)")
	cmd.Flags().BoolVarP(&jsonOutput, "json", "j", false, "Output as JSON")
	return cmd
}

// ── Helpers ──────────────────────────────────────────────────────────

func resolveResourceClient(resourceID string) (*platform.Client, string, error) {
	client, err := platform.NewClient()
	if err != nil {
		return nil, "", err
	}
	resID := resourceID
	if resID == "" {
		cfg, _ := platform.LoadConfig()
		if cfg != nil {
			resID = cfg.DefaultResource
		}
	}
	if resID == "" {
		return nil, "", fmt.Errorf("no resource specified (pass --resource or run 'cw setup')")
	}
	return client, resID, nil
}

func deriveWorkspaceName(repoURL string) string {
	u, err := url.Parse(repoURL)
	if err != nil {
		// Fall back to simple parsing
		parts := strings.Split(repoURL, "/")
		name := parts[len(parts)-1]
		return strings.TrimSuffix(name, ".git")
	}
	name := path.Base(u.Path)
	return strings.TrimSuffix(name, ".git")
}

func openBrowser(url string) error {
	var cmd string
	switch runtime.GOOS {
	case "darwin":
		cmd = "open"
	case "linux":
		cmd = "xdg-open"
	case "windows":
		cmd = "start"
	default:
		return fmt.Errorf("unsupported platform")
	}
	return exec.Command(cmd, url).Start()
}

// isLocalPath returns true if the argument looks like a local directory (not a URL).
func isLocalPath(arg string) bool {
	if arg == "." || arg == ".." {
		return true
	}
	if strings.HasPrefix(arg, "/") || strings.HasPrefix(arg, "./") || strings.HasPrefix(arg, "../") {
		return true
	}
	// Not a URL if it doesn't contain "://" or "@"
	if !strings.Contains(arg, "://") && !strings.Contains(arg, "@") && !strings.Contains(arg, ".") {
		return true
	}
	return false
}

// detectLocalRepo reads the git origin remote from a local directory and returns the HTTPS URL + current branch.
func detectLocalRepo(dir string) (string, string, error) {
	// Get the origin remote URL
	remoteCmd := exec.Command("git", "-C", dir, "remote", "get-url", "origin")
	remoteOut, err := remoteCmd.Output()
	if err != nil {
		return "", "", fmt.Errorf("not a git repository or no 'origin' remote: %w", err)
	}
	remoteURL := strings.TrimSpace(string(remoteOut))

	// Normalize to HTTPS
	repoURL := normalizeGitURL(remoteURL)

	// Get current branch
	branchCmd := exec.Command("git", "-C", dir, "rev-parse", "--abbrev-ref", "HEAD")
	branchOut, err := branchCmd.Output()
	if err != nil {
		return repoURL, "", nil
	}
	branch := strings.TrimSpace(string(branchOut))
	if branch == "HEAD" {
		branch = "" // detached HEAD
	}

	return repoURL, branch, nil
}

// resolveClaudeOAuthToken returns the Claude Code OAuth token from env or credentials file.
func resolveClaudeOAuthToken() string {
	if token := os.Getenv("CLAUDE_CODE_OAUTH_TOKEN"); token != "" {
		return token
	}

	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	data, err := os.ReadFile(path.Join(home, ".claude", ".credentials.json"))
	if err != nil {
		return ""
	}
	var creds struct {
		ClaudeAiOauth struct {
			AccessToken string `json:"accessToken"`
		} `json:"claudeAiOauth"`
	}
	if err := json.Unmarshal(data, &creds); err != nil {
		return ""
	}
	return creds.ClaudeAiOauth.AccessToken
}

// normalizeGitURL converts SSH git URLs to HTTPS.
func normalizeGitURL(rawURL string) string {
	rawURL = strings.TrimSpace(rawURL)
	rawURL = strings.TrimSuffix(rawURL, ".git")

	// git@github.com:owner/repo → https://github.com/owner/repo
	if strings.HasPrefix(rawURL, "git@") {
		rawURL = strings.TrimPrefix(rawURL, "git@")
		rawURL = strings.Replace(rawURL, ":", "/", 1)
		return "https://" + rawURL
	}

	// ssh://git@github.com/owner/repo → https://github.com/owner/repo
	if strings.HasPrefix(rawURL, "ssh://") {
		rawURL = strings.TrimPrefix(rawURL, "ssh://")
		rawURL = strings.TrimPrefix(rawURL, "git@")
		return "https://" + rawURL
	}

	return rawURL
}
