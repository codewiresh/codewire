package main

import (
	"fmt"
	"time"

	"github.com/spf13/cobra"

	"github.com/codewiresh/codewire/internal/platform"
	"github.com/codewiresh/codewire/internal/tui"
)

func githubCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "github",
		Short: "Manage GitHub connection for private repo access",
	}

	cmd.AddCommand(githubLoginCmd(), githubLogoutCmd(), githubStatusCmd())
	return cmd
}

func githubLoginCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "login",
		Short: "Connect GitHub account via device flow",
		RunE: func(cmd *cobra.Command, args []string) error {
			client, err := platform.NewClient()
			if err != nil {
				return fmt.Errorf("not logged in — run 'cw setup' first to connect to Codewire")
			}
			return setupGitHub(client)
		},
	}
}

func githubLogoutCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "logout",
		Short: "Disconnect GitHub account",
		RunE: func(cmd *cobra.Command, args []string) error {
			client, err := platform.NewClient()
			if err != nil {
				return fmt.Errorf("not logged in — run 'cw setup' first to connect to Codewire")
			}
			if err := client.DisconnectGitHub(); err != nil {
				return fmt.Errorf("disconnect github: %w", err)
			}
			fmt.Println("GitHub disconnected.")
			return nil
		},
	}
}

func githubStatusCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "status",
		Short: "Show GitHub connection status",
		RunE: func(cmd *cobra.Command, args []string) error {
			client, err := platform.NewClient()
			if err != nil {
				return fmt.Errorf("not logged in — run 'cw setup' first to connect to Codewire")
			}
			status, err := client.GetGitHubStatus()
			if err != nil {
				return fmt.Errorf("github status: %w", err)
			}
			if !status.Connected {
				fmt.Println("GitHub: not connected")
				fmt.Println("  Run 'cw github login' to connect.")
				return nil
			}
			fmt.Printf("GitHub: connected as @%s\n", status.Username)
			if status.InstallationID != nil {
				fmt.Printf("  Installation ID: %d\n", *status.InstallationID)
			}
			if status.ConnectedAt != nil {
				fmt.Printf("  Connected: %s\n", *status.ConnectedAt)
			}
			return nil
		},
	}
}

// setupGitHub runs the full device flow: fetch config, request device code,
// display code + open browser, poll for token, check installation, save token.
func setupGitHub(client *platform.Client) error {
	// Fetch server's GitHub App config
	ghCfg, err := client.GetGitHubConfig()
	if err != nil {
		return fmt.Errorf("fetch github config: %w", err)
	}
	if ghCfg.ClientID == "" {
		return fmt.Errorf("GitHub App not configured on server")
	}

	// Request device code
	deviceCode, err := platform.RequestDeviceCode(ghCfg.ClientID)
	if err != nil {
		return fmt.Errorf("request device code: %w", err)
	}

	// Display instructions
	fmt.Println()
	fmt.Printf("  Open: %s\n", deviceCode.VerificationURI)
	fmt.Printf("  Code: %s\n", deviceCode.UserCode)
	fmt.Println()

	// Try to open browser
	_ = openBrowser(deviceCode.VerificationURI)

	// Poll for token with spinner
	type tokenResult struct {
		resp *platform.GitHubTokenResponse
		err  error
	}
	ch := make(chan tokenResult, 1)
	go func() {
		resp, err := platform.PollForToken(ghCfg.ClientID, deviceCode.DeviceCode, deviceCode.Interval)
		ch <- tokenResult{resp, err}
	}()

	var tokenResp *platform.GitHubTokenResponse
	res, spinErr := tui.RunSpinner("Waiting for authorization...", time.Second, func() (bool, string, error) {
		select {
		case r := <-ch:
			if r.err != nil {
				return false, "", r.err
			}
			tokenResp = r.resp
			return true, "done", nil
		default:
			return false, "", nil
		}
	})
	if spinErr != nil {
		return spinErr
	}
	if res.Err != nil {
		return res.Err
	}

	// Fetch username
	username, err := platform.FetchGitHubUsername(tokenResp.AccessToken)
	if err != nil {
		fmt.Printf("  Warning: could not fetch username: %v\n", err)
	} else {
		fmt.Printf("  Authenticated as @%s\n", username)
	}

	// Check for app installation
	var installationID *int64
	if ghCfg.AppSlug != "" {
		instID, err := platform.FetchInstallationID(tokenResp.AccessToken, ghCfg.AppSlug)
		if err != nil {
			fmt.Printf("  Warning: could not check installation: %v\n", err)
		} else if instID == 0 {
			fmt.Printf("\n  The GitHub App is not installed on your account.\n")
			fmt.Printf("  Install it at: https://github.com/apps/%s/installations/new\n", ghCfg.AppSlug)
			fmt.Println("  (You can do this later — private repo access requires installation)")
		} else {
			installationID = &instID
			fmt.Printf("  App installed (ID: %d)\n", instID)
		}
	}

	// Compute expiry timestamps
	saveReq := &platform.SaveGitHubTokenRequest{
		AccessToken:    tokenResp.AccessToken,
		RefreshToken:   tokenResp.RefreshToken,
		TokenType:      tokenResp.TokenType,
		GitHubUsername: username,
		InstallationID: installationID,
	}
	if tokenResp.ExpiresIn > 0 {
		saveReq.ExpiresAt = time.Now().Add(time.Duration(tokenResp.ExpiresIn) * time.Second).Format(time.RFC3339)
	}
	if tokenResp.RefreshTokenExpiresIn > 0 {
		saveReq.RefreshTokenExpiresAt = time.Now().Add(time.Duration(tokenResp.RefreshTokenExpiresIn) * time.Second).Format(time.RFC3339)
	}

	// Save token to server
	if err := client.SaveGitHubToken(saveReq); err != nil {
		return fmt.Errorf("save token: %w", err)
	}

	fmt.Println("  GitHub connected.")
	return nil
}
