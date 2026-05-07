package main

import (
	"encoding/json"
	"fmt"
	"os"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"github.com/codewiresh/codewire/internal/platform"
	"github.com/codewiresh/codewire/internal/tui"
)

func loginCmd() *cobra.Command {
	var serverURL string
	var usePassword bool

	cmd := &cobra.Command{
		Use:   "login",
		Short: "Sign in to Codewire",
		RunE: func(cmd *cobra.Command, args []string) error {
			// Determine server URL
			url := serverURL
			if url == "" {
				cfg, err := platform.LoadConfig()
				if err != nil {
					return fmt.Errorf("no server configured (run 'cw setup' first, or pass --server)")
				}
				url = cfg.ServerURL
			}

			client := platform.NewClientWithURL(url)

			var displayName string

			if usePassword {
				name, err := loginWithPassword(client)
				if err != nil {
					return err
				}
				displayName = name
			} else {
				name, err := loginWithDevice(client)
				if err != nil {
					return err
				}
				displayName = name
			}

			// Save config
			cfg := &platform.PlatformConfig{
				ServerURL:    url,
				SessionToken: client.SessionToken,
			}
			// Preserve existing defaults if re-logging in
			if existing, err := platform.LoadConfig(); err == nil {
				cfg.DefaultOrg = existing.DefaultOrg
			}
			if err := platform.SaveConfig(cfg); err != nil {
				return fmt.Errorf("save config: %w", err)
			}

			successMsg("Logged in as %s.", displayName)
			return nil
		},
	}

	cmd.Flags().StringVar(&serverURL, "server", "", "Codewire server URL")
	cmd.Flags().BoolVar(&usePassword, "password", false, "Use email/password login instead of browser")
	return cmd
}

func loginWithPassword(client *platform.Client) (string, error) {
	email, err := prompt("Email: ")
	if err != nil {
		return "", err
	}
	password, err := promptPassword("Password: ")
	if err != nil {
		return "", err
	}

	resp, err := client.Login(email, password)
	if err != nil {
		return "", fmt.Errorf("login failed: %w", err)
	}

	// Handle 2FA
	if resp.TwoFactorRequired {
		code, err := prompt("2FA Code: ")
		if err != nil {
			return "", err
		}
		authResp, err := client.ValidateTOTP(code, resp.TwoFactorToken)
		if err != nil {
			return "", fmt.Errorf("2FA validation failed: %w", err)
		}
		if authResp.Session == nil {
			return "", fmt.Errorf("no session returned after 2FA")
		}
	} else if resp.Session == nil {
		return "", fmt.Errorf("no session returned")
	}

	name := ""
	if resp.User != nil {
		name = resp.User.Name
		if name == "" {
			name = resp.User.Email
		}
	}
	return name, nil
}

func loginWithDevice(client *platform.Client) (string, error) {
	dauth, err := client.DeviceAuthorize()
	if err != nil {
		return "", fmt.Errorf("device auth failed: %w", err)
	}

	fmt.Println("Opening browser to authorize...")
	fmt.Printf("If browser doesn't open, visit: %s\n", dauth.VerificationURI)
	fmt.Printf("Your code: %s\n", dauth.UserCode)

	_ = openBrowser(dauth.VerificationURI)

	interval := time.Duration(dauth.Interval) * time.Second
	if interval < 5*time.Second {
		interval = 5 * time.Second
	}
	expiresIn := dauth.ExpiresIn
	if expiresIn <= 0 {
		expiresIn = 300
	}
	deadline := time.Now().Add(time.Duration(expiresIn) * time.Second)

	var resultName string

	res, err := tui.RunSpinner("Waiting for authorization...", interval, func() (bool, string, error) {
		if time.Now().After(deadline) {
			return false, "", fmt.Errorf("timed out waiting for authorization")
		}

		resp, statusCode, err := client.DeviceToken(dauth.DeviceCode)
		if err != nil {
			if statusCode == 410 {
				return false, "", fmt.Errorf("device code expired")
			}
			if statusCode == 403 {
				return false, "", fmt.Errorf("authorization denied")
			}
			return false, "", nil // transient error, retry
		}

		if statusCode == 202 {
			if resp.Status == "slow_down" {
				interval *= 2
			}
			return false, "", nil
		}

		if client.SessionToken == "" {
			return false, "", fmt.Errorf("device auth approved but no session token received (status %d, session_token=%q)", statusCode, resp.SessionToken)
		}

		if resp.User != nil {
			name := resp.User.Name
			if name == "" {
				name = resp.User.Email
			}
			resultName = name
			return true, name, nil
		}
		resultName = "(unknown)"
		return true, "(unknown)", nil
	})
	if err != nil {
		return "", err
	}
	if res.Err != nil {
		return "", res.Err
	}

	return resultName, nil
}

func logoutCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "logout",
		Short: "Sign out of Codewire",
		RunE: func(cmd *cobra.Command, args []string) error {
			client, err := platform.NewClient()
			if err != nil {
				// Not logged in, just clean up config
				_ = platform.DeleteConfig()
				successMsg("Logged out.")
				return nil
			}
			_ = client.Logout()
			_ = platform.DeleteConfig()
			successMsg("Logged out.")
			return nil
		},
	}
}

func whoamiCmd() *cobra.Command {
	var output string

	cmd := &cobra.Command{
		Use:   "whoami",
		Short: "Show current user and server",
		RunE: func(cmd *cobra.Command, args []string) error {
			jsonOutput, err := wantsJSON(output)
			if err != nil {
				return err
			}
			client, err := platform.NewClient()
			if err != nil {
				return err
			}

			resp, err := client.GetSession()
			if err != nil {
				return fmt.Errorf("session check failed: %w", err)
			}
			if resp.User == nil {
				return fmt.Errorf("not logged in (session expired?)")
			}

			if jsonOutput {
				enc := json.NewEncoder(os.Stdout)
				enc.SetIndent("", "  ")
				return enc.Encode(resp.User)
			}

			cfg, _ := platform.LoadConfig()
			fmt.Printf("%-10s %s (%s)\n", bold("User:"), resp.User.Name, resp.User.Email)
			fmt.Printf("%-10s %s\n", bold("Server:"), client.ServerURL)
			if cfg != nil && cfg.DefaultOrg != "" {
				fmt.Printf("%-10s %s\n", bold("Org:"), cfg.DefaultOrg)
			}
			return nil
		},
	}

	addOutputFlag(cmd, &output, "Output format (text|json)")
	return cmd
}

func orgsCmd() *cobra.Command {
	setCmd := orgSetCmd()
	cmd := &cobra.Command{
		Use:     "org",
		Short:   "Manage organizations",
		Aliases: []string{"orgs"},
		RunE: func(cmd *cobra.Command, args []string) error {
			return setCmd.RunE(setCmd, nil)
		},
	}
	cmd.AddCommand(orgsListCmd(), orgCurrentCmd(), setCmd, orgsCreateCmd(), orgsDeleteCmd(), orgsInviteCmd())
	return cmd
}

func orgsListCmd() *cobra.Command {
	var output string

	cmd := &cobra.Command{
		Use:   "list",
		Short: "List organizations",
		RunE: func(cmd *cobra.Command, args []string) error {
			jsonOutput, err := wantsJSON(output)
			if err != nil {
				return err
			}
			client, err := platform.NewClient()
			if err != nil {
				return err
			}

			orgs, err := client.ListOrgs()
			if err != nil {
				return fmt.Errorf("list orgs: %w", err)
			}

			if jsonOutput {
				enc := json.NewEncoder(os.Stdout)
				enc.SetIndent("", "  ")
				return enc.Encode(orgs)
			}

			if len(orgs) == 0 {
				fmt.Println("No organizations found.")
				return nil
			}

			cfg, _ := platform.LoadConfig()
			w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
			tableHeader(w, "NAME", "SLUG", "ROLE", "RESOURCES")
			for _, org := range orgs {
				marker := ""
				if cfg != nil && cfg.DefaultOrg == org.ID {
					marker = " *"
				}
				fmt.Fprintf(w, "%s%s\t%s\t%s\t%d\n", org.Name, marker, org.Slug, org.Role, len(org.Resources))
			}
			return w.Flush()
		},
	}

	addOutputFlag(cmd, &output, "Output format (text|json)")
	return cmd
}

func orgCurrentCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "current",
		Short: "Show the current organization",
		RunE: func(cmd *cobra.Command, args []string) error {
			orgID, pc, err := getDefaultOrg()
			if err != nil {
				return err
			}

			orgs, err := pc.ListOrgs()
			if err != nil {
				return fmt.Errorf("list orgs: %w", err)
			}

			for _, org := range orgs {
				if org.ID != orgID {
					continue
				}

				fmt.Printf("%-10s %s\n", bold("Name:"), org.Name)
				fmt.Printf("%-10s %s\n", bold("Slug:"), org.Slug)
				fmt.Printf("%-10s %s\n", bold("ID:"), org.ID)
				fmt.Printf("%-10s %s\n", bold("Role:"), org.Role)
				return nil
			}

			return fmt.Errorf("current organization %q not found", orgID)
		},
	}
}

func orgSetCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "set [id-or-slug]",
		Short: "Set the current organization",
		Long:  "Set the current organization by ID or slug. With no argument, presents an interactive selection list.",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			pc, err := platform.NewClient()
			if err != nil {
				return err
			}

			orgs, err := pc.ListOrgs()
			if err != nil {
				return fmt.Errorf("list orgs: %w", err)
			}
			if len(orgs) == 0 {
				return fmt.Errorf("no organizations found")
			}

			var selected platform.OrgWithRole
			switch len(args) {
			case 1:
				orgID, err := resolveOrgID(pc, args[0])
				if err != nil {
					return err
				}

				found := false
				for i := range orgs {
					if orgs[i].ID == orgID {
						selected = orgs[i]
						found = true
						break
					}
				}
				if !found {
					return fmt.Errorf("organization %q not found", args[0])
				}
			default:
				if len(orgs) == 1 {
					selected = orgs[0]
					break
				}

				cfg, _ := platform.LoadConfig()
				options := make([]string, len(orgs))
				for i, org := range orgs {
					marker := ""
					if cfg != nil && cfg.DefaultOrg == org.ID {
						marker = " (current)"
					}
					options[i] = fmt.Sprintf("%s [%s]%s", org.Name, org.Slug, marker)
				}

				idx, err := promptSelect("Select organization:", options)
				if err != nil {
					return err
				}
				selected = orgs[idx]
			}

			cfg, err := platform.LoadConfig()
			if err != nil {
				return err
			}

			cfg.DefaultOrg = selected.ID

			if err := platform.SaveConfig(cfg); err != nil {
				return fmt.Errorf("save config: %w", err)
			}

			successMsg("Current org set to %s (%s).", selected.Name, selected.Slug)
			return nil
		},
	}
}

func resourcesCmd() *cobra.Command {
	listCmd := resourcesListCmd()
	cmd := &cobra.Command{
		Use:   "resources",
		Short: "List platform resources",
		RunE: func(cmd *cobra.Command, args []string) error {
			return listCmd.RunE(listCmd, nil)
		},
	}
	cmd.AddCommand(listCmd)
	return cmd
}

func resourcesListCmd() *cobra.Command {
	var output string
	var orgFlag string

	cmd := &cobra.Command{
		Use:   "list",
		Short: "List resources",
		RunE: func(cmd *cobra.Command, args []string) error {
			jsonOutput, err := wantsJSON(output)
			if err != nil {
				return err
			}
			client, err := platform.NewClient()
			if err != nil {
				return err
			}

			resources, err := client.ListResources()
			if err != nil {
				return fmt.Errorf("list resources: %w", err)
			}

			orgLabels := map[string]string{}
			if orgs, err := client.ListOrgs(); err == nil {
				for _, org := range orgs {
					label := org.Slug
					if label == "" {
						label = org.Name
					}
					orgLabels[org.ID] = label
				}
			}

			if orgFlag != "" {
				orgID, err := resolveOrgID(client, orgFlag)
				if err != nil {
					return err
				}
				filtered := resources[:0]
				for _, r := range resources {
					if r.OrgID == orgID {
						filtered = append(filtered, r)
					}
				}
				resources = filtered
			}

			if jsonOutput {
				enc := json.NewEncoder(os.Stdout)
				enc.SetIndent("", "  ")
				return enc.Encode(resources)
			}

			if len(resources) == 0 {
				fmt.Println("No resources found.")
				return nil
			}

			w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
			tableHeader(w, "ORG", "NAME", "SLUG", "TYPE", "STATUS", "HEALTH")
			for _, r := range resources {
				orgLabel := orgLabels[r.OrgID]
				if orgLabel == "" {
					orgLabel = r.OrgID
				}
				fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\n", orgLabel, r.Name, r.Slug, r.Type, stateColor(r.Status), stateColor(r.HealthStatus))
			}
			return w.Flush()
		},
	}

	addOutputFlag(cmd, &output, "Output format (text|json)")
	cmd.Flags().StringVar(&orgFlag, "org", "", "Organization ID or slug")
	return cmd
}

func resourcesGetCmd() *cobra.Command {
	var output string

	cmd := &cobra.Command{
		Use:   "get <id-or-slug>",
		Short: "Get resource details",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			jsonOutput, err := wantsJSON(output)
			if err != nil {
				return err
			}
			client, err := platform.NewClient()
			if err != nil {
				return err
			}

			resource, err := client.GetResource(args[0])
			if err != nil {
				return fmt.Errorf("get resource: %w", err)
			}

			if jsonOutput {
				enc := json.NewEncoder(os.Stdout)
				enc.SetIndent("", "  ")
				return enc.Encode(resource)
			}

			fmt.Printf("%-10s %s\n", bold("Name:"), resource.Name)
			fmt.Printf("%-10s %s\n", bold("Slug:"), resource.Slug)
			fmt.Printf("%-10s %s\n", bold("Type:"), resource.Type)
			fmt.Printf("%-10s %s\n", bold("Status:"), stateColor(resource.Status))
			fmt.Printf("%-10s %s\n", bold("Health:"), stateColor(resource.HealthStatus))
			fmt.Printf("%-10s %s\n", bold("Plan:"), resource.BillingPlan)
			fmt.Printf("%-10s %s\n", bold("Created:"), resource.CreatedAt)
			return nil
		},
	}

	addOutputFlag(cmd, &output, "Output format (text|json)")
	return cmd
}
