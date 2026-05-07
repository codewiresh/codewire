package main

import (
	"encoding/json"
	"fmt"
	"os"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/codewiresh/codewire/internal/platform"
)

func secretsCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "secrets",
		Short: "Manage secrets and secret projects",
	}
	cmd.AddCommand(
		secretsCreateCmd(),
		secretsListCmd(),
		secretsSetCmd(),
		secretsDeleteCmd(),
		secretsRmCmd(),
		secretsRenameCmd(),
		secretsUserCmd(),
		secretsOrgCmd(),
	)
	return cmd
}

// ── cw secrets create <name> ─────────────────────────────────────────

func secretsCreateCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "create <name>",
		Short: "Create a secret project",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			orgID, client, err := getDefaultOrg()
			if err != nil {
				return err
			}

			project, err := client.CreateSecretProject(orgID, args[0])
			if err != nil {
				return fmt.Errorf("create secret project: %w", err)
			}

			successMsg("Secret project %q created. (id: %s)", project.Name, project.ID)
			return nil
		},
	}
	return cmd
}

// ── cw secrets list [name] ──────────────────────────────────────────

func secretsListCmd() *cobra.Command {
	var output string

	cmd := &cobra.Command{
		Use:   "list [project-name]",
		Short: "List secret projects, or secrets in a project",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			jsonOutput, err := wantsJSON(output)
			if err != nil {
				return err
			}
			oid, client, err := getDefaultOrg()
			if err != nil {
				return err
			}

			if len(args) == 0 {
				// List all secret projects.
				projects, err := client.ListSecretProjects(oid)
				if err != nil {
					return fmt.Errorf("list secret projects: %w", err)
				}

				if jsonOutput {
					enc := json.NewEncoder(os.Stdout)
					enc.SetIndent("", "  ")
					return enc.Encode(projects)
				}

				if len(projects) == 0 {
					fmt.Println("No secret projects found.")
					return nil
				}

				w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
				tableHeader(w, "NAME", "SECRETS", "CREATED")
				for _, p := range projects {
					fmt.Fprintf(w, "%s\t%d\t%s\n", p.Name, p.SecretCount, p.CreatedAt)
				}
				return w.Flush()
			}

			// List secrets in a specific project.
			projectName := args[0]
			project, err := findProjectByName(client, oid, projectName)
			if err != nil {
				return err
			}

			secrets, err := client.ListProjectSecrets(oid, project.ID)
			if err != nil {
				return fmt.Errorf("list project secrets: %w", err)
			}

			if jsonOutput {
				enc := json.NewEncoder(os.Stdout)
				enc.SetIndent("", "  ")
				return enc.Encode(secrets)
			}

			if len(secrets) == 0 {
				fmt.Printf("No secrets in project %q.\n", projectName)
				return nil
			}

			w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
			tableHeader(w, "KEY", "CREATED", "UPDATED")
			for _, s := range secrets {
				fmt.Fprintf(w, "%s\t%s\t%s\n", s.Key, s.CreatedAt, s.UpdatedAt)
			}
			return w.Flush()
		},
	}

	addOutputFlag(cmd, &output, "Output format (text|json)")
	return cmd
}

// ── cw secrets set <project> <key> ──────────────────────────────────

func secretsSetCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "set <project> <KEY>",
		Short: "Set a secret in a project (prompts for value)",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			oid, client, err := getDefaultOrg()
			if err != nil {
				return err
			}

			projectName := args[0]
			key := args[1]

			project, err := findProjectByName(client, oid, projectName)
			if err != nil {
				return err
			}

			value, err := promptPassword("Value: ")
			if err != nil {
				return err
			}
			if value == "" {
				return fmt.Errorf("value cannot be empty")
			}

			if err := client.SetProjectSecret(oid, project.ID, key, value); err != nil {
				return fmt.Errorf("set secret: %w", err)
			}

			successMsg("Secret %s set in project %q.", key, projectName)
			return nil
		},
	}
	return cmd
}

// ── cw secrets delete / rm <project> [key] ──────────────────────────

func secretsDeleteCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "delete <project> [key]",
		Aliases: []string{"rm"},
		Short:   "Delete a secret or an entire project",
		Long:    "With key: deletes a single secret. Without key: deletes the entire project (prompts for confirmation).",
		Args:    cobra.RangeArgs(1, 2),
		RunE: func(cmd *cobra.Command, args []string) error {
			oid, client, err := getDefaultOrg()
			if err != nil {
				return err
			}

			projectName := args[0]

			if len(args) == 2 {
				// Delete a specific secret.
				key := args[1]
				project, err := findProjectByName(client, oid, projectName)
				if err != nil {
					return err
				}
				if err := client.DeleteProjectSecret(oid, project.ID, key); err != nil {
					return fmt.Errorf("delete secret: %w", err)
				}
				successMsg("Secret %s deleted from project %q.", key, projectName)
				return nil
			}

			// Delete entire project — confirm first.
			project, err := findProjectByName(client, oid, projectName)
			if err != nil {
				return err
			}

			ok, err := promptConfirm(fmt.Sprintf("Delete secret project %q and all its secrets? [Y/n]", projectName))
			if err != nil {
				return err
			}
			if !ok {
				fmt.Println("Canceled.")
				return nil
			}

			if err := client.DeleteSecretProject(oid, project.ID); err != nil {
				return fmt.Errorf("delete secret project: %w", err)
			}
			successMsg("Secret project %q deleted.", projectName)
			return nil
		},
	}
	return cmd
}

// secretsRmCmd is an alias for delete at the top level.
func secretsRmCmd() *cobra.Command {
	cmd := secretsDeleteCmd()
	cmd.Use = "rm <project> [key]"
	cmd.Aliases = nil
	return cmd
}

// ── cw secrets rename <project> <old-key> <new-key> ────────────────

func secretsRenameCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "rename <project> <old-key> <new-key>",
		Short: "Rename a secret key in a project",
		Args:  cobra.ExactArgs(3),
		RunE: func(cmd *cobra.Command, args []string) error {
			oid, client, err := getDefaultOrg()
			if err != nil {
				return err
			}

			projectName := args[0]
			oldKey := args[1]
			newKey := args[2]

			project, err := findProjectByName(client, oid, projectName)
			if err != nil {
				return err
			}

			if err := client.RenameProjectSecret(oid, project.ID, oldKey, newKey); err != nil {
				return fmt.Errorf("rename secret: %w", err)
			}

			successMsg("Secret %s renamed to %s in project %q.", oldKey, newKey, projectName)
			return nil
		},
	}
	return cmd
}

// ── cw secrets user ──────────────────────────────────────────────────

func secretsUserCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "user",
		Short: "Manage user-scoped secrets",
	}
	cmd.AddCommand(
		secretsUserListCmd(),
		secretsUserSetCmd(),
		secretsUserDeleteCmd(),
		secretsUserRenameCmd(),
	)
	return cmd
}

func secretsUserListCmd() *cobra.Command {
	var output string

	cmd := &cobra.Command{
		Use:   "list",
		Short: "List your user secrets",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			jsonOutput, err := wantsJSON(output)
			if err != nil {
				return err
			}
			client, err := platform.NewClient()
			if err != nil {
				return err
			}

			secrets, err := client.ListUserSecrets()
			if err != nil {
				return fmt.Errorf("list user secrets: %w", err)
			}

			if jsonOutput {
				enc := json.NewEncoder(os.Stdout)
				enc.SetIndent("", "  ")
				return enc.Encode(secrets)
			}

			if len(secrets) == 0 {
				fmt.Println("No user secrets found.")
				return nil
			}

			w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
			tableHeader(w, "KEY", "CREATED", "UPDATED")
			for _, s := range secrets {
				fmt.Fprintf(w, "%s\t%s\t%s\n", s.Key, s.CreatedAt, s.UpdatedAt)
			}
			return w.Flush()
		},
	}

	addOutputFlag(cmd, &output, "Output format (text|json)")
	return cmd
}

func secretsUserSetCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "set <KEY>",
		Short: "Set a user secret (prompts for value)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			client, err := platform.NewClient()
			if err != nil {
				return err
			}

			key := args[0]

			value, err := promptPassword("Value: ")
			if err != nil {
				return err
			}
			if value == "" {
				return fmt.Errorf("value cannot be empty")
			}

			if err := client.SetUserSecret(key, value); err != nil {
				return fmt.Errorf("set user secret: %w", err)
			}

			successMsg("Secret %s set.", key)
			return nil
		},
	}
	return cmd
}

func secretsUserRenameCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "rename <old-key> <new-key>",
		Short: "Rename a user secret key",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			client, err := platform.NewClient()
			if err != nil {
				return err
			}

			if err := client.RenameUserSecret(args[0], args[1]); err != nil {
				return fmt.Errorf("rename user secret: %w", err)
			}

			successMsg("Secret %s renamed to %s.", args[0], args[1])
			return nil
		},
	}
	return cmd
}

func secretsUserDeleteCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "delete <KEY>",
		Aliases: []string{"rm"},
		Short:   "Delete a user secret",
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			client, err := platform.NewClient()
			if err != nil {
				return err
			}

			key := args[0]

			if err := client.DeleteUserSecret(key); err != nil {
				return fmt.Errorf("delete user secret: %w", err)
			}

			successMsg("Secret %s deleted.", key)
			return nil
		},
	}
	return cmd
}

// ── cw secrets org ──────────────────────────────────────────────────

func secretsOrgCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "org",
		Short: "Manage organization-scoped secrets",
	}
	cmd.AddCommand(
		secretsOrgListCmd(),
		secretsOrgSetCmd(),
		secretsOrgDeleteCmd(),
		secretsOrgRenameCmd(),
	)
	return cmd
}

func secretsOrgListCmd() *cobra.Command {
	var output string

	cmd := &cobra.Command{
		Use:   "list",
		Short: "List organization secrets",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			jsonOutput, err := wantsJSON(output)
			if err != nil {
				return err
			}
			orgID, client, err := getDefaultOrg()
			if err != nil {
				return err
			}

			secrets, err := client.ListSecrets(orgID)
			if err != nil {
				return fmt.Errorf("list org secrets: %w", err)
			}

			if jsonOutput {
				enc := json.NewEncoder(os.Stdout)
				enc.SetIndent("", "  ")
				return enc.Encode(secrets)
			}

			if len(secrets) == 0 {
				fmt.Println("No organization secrets found.")
				return nil
			}

			w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
			tableHeader(w, "KEY", "CREATED", "UPDATED")
			for _, s := range secrets {
				fmt.Fprintf(w, "%s\t%s\t%s\n", s.Key, s.CreatedAt, s.UpdatedAt)
			}
			return w.Flush()
		},
	}

	addOutputFlag(cmd, &output, "Output format (text|json)")
	return cmd
}

func secretsOrgSetCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "set <KEY>",
		Short: "Set an organization secret (prompts for value)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			orgID, client, err := getDefaultOrg()
			if err != nil {
				return err
			}

			key := args[0]

			value, err := promptPassword("Value: ")
			if err != nil {
				return err
			}
			if value == "" {
				return fmt.Errorf("value cannot be empty")
			}

			if err := client.SetSecret(orgID, key, value); err != nil {
				return fmt.Errorf("set org secret: %w", err)
			}

			successMsg("Secret %s set.", key)
			return nil
		},
	}
	return cmd
}

func secretsOrgRenameCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "rename <old-key> <new-key>",
		Short: "Rename an organization secret key",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			orgID, client, err := getDefaultOrg()
			if err != nil {
				return err
			}

			if err := client.RenameSecret(orgID, args[0], args[1]); err != nil {
				return fmt.Errorf("rename org secret: %w", err)
			}

			successMsg("Secret %s renamed to %s.", args[0], args[1])
			return nil
		},
	}
	return cmd
}

func secretsOrgDeleteCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "delete <KEY>",
		Aliases: []string{"rm"},
		Short:   "Delete an organization secret",
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			orgID, client, err := getDefaultOrg()
			if err != nil {
				return err
			}

			key := args[0]

			if err := client.DeleteSecret(orgID, key); err != nil {
				return fmt.Errorf("delete org secret: %w", err)
			}

			successMsg("Secret %s deleted.", key)
			return nil
		},
	}
	return cmd
}

// ── Helpers ─────────────────────────────────────────────────────────

func findProjectByName(client *platform.Client, orgID, name string) (*platform.SecretProject, error) {
	projects, err := client.ListSecretProjects(orgID)
	if err != nil {
		return nil, fmt.Errorf("list secret projects: %w", err)
	}
	for _, p := range projects {
		if p.Name == name {
			return &p, nil
		}
	}
	return nil, fmt.Errorf("secret project %q not found", name)
}
