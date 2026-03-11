package main

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/codewiresh/codewire/internal/update"
)

func updateCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "update",
		Short: "Update cw to the latest version",
		RunE: func(cmd *cobra.Command, args []string) error {
			if version == "dev" {
				return fmt.Errorf("cannot update a dev build — install a release build first")
			}

			fmt.Println("Checking for updates...")
			latest, err := update.FetchLatestVersion()
			if err != nil {
				return fmt.Errorf("checking for updates: %w", err)
			}

			if !update.IsNewer(version, latest) {
				fmt.Printf("Already up to date (%s).\n", version)
				return nil
			}

			fmt.Printf("New version available: %s → %s\n", version, latest)
			fmt.Printf("Downloading %s...\n", latest)
			if err := update.SelfUpdate(version, latest); err != nil {
				return err
			}

			fmt.Printf("Updated to %s.\n", latest)
			return nil
		},
	}
}
