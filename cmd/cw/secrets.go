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

			fmt.Printf("Secret project %q created. (id: %s)\n", project.Name, project.ID)
			return nil
		},
	}
	return cmd
}

// ── cw secrets list [name] ──────────────────────────────────────────

func secretsListCmd() *cobra.Command {
	var jsonOutput bool

	cmd := &cobra.Command{
		Use:   "list [project-name]",
		Short: "List secret projects, or secrets in a project",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
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
				fmt.Fprintln(w, "NAME\tSECRETS\tCREATED")
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
			fmt.Fprintln(w, "KEY\tCREATED\tUPDATED")
			for _, s := range secrets {
				fmt.Fprintf(w, "%s\t%s\t%s\n", s.Key, s.CreatedAt, s.UpdatedAt)
			}
			return w.Flush()
		},
	}

	cmd.Flags().BoolVarP(&jsonOutput, "json", "j", false, "Output as JSON")
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

			fmt.Printf("Secret %s set in project %q.\n", key, projectName)
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
				fmt.Printf("Secret %s deleted from project %q.\n", key, projectName)
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
			fmt.Printf("Secret project %q deleted.\n", projectName)
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
