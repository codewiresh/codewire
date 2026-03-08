package main

import (
	"fmt"
	"os"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"github.com/codewiresh/codewire/internal/platform"
)

func tmplParentCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "template",
		Short:   "Manage environment templates",
		Aliases: []string{"tmpl"},
	}
	cmd.AddCommand(templateListCmd())
	cmd.AddCommand(templateCreateCmd())
	cmd.AddCommand(templateRmCmd())
	return cmd
}

func templateListCmd() *cobra.Command {
	var envType string

	cmd := &cobra.Command{
		Use:     "list",
		Short:   "List environment templates",
		Aliases: []string{"ls"},
		RunE: func(cmd *cobra.Command, args []string) error {
			orgID, client, err := getDefaultOrg()
			if err != nil {
				return err
			}

			templates, err := client.ListEnvTemplates(orgID, envType)
			if err != nil {
				return fmt.Errorf("list templates: %w", err)
			}

			if len(templates) == 0 {
				fmt.Println("No templates found.")
				return nil
			}

			w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
			fmt.Fprintln(w, "ID\tNAME\tTYPE\tBUILD\tCPU/MEM/DISK\tCREATED")
			for _, t := range templates {
				resources := fmt.Sprintf("%dm/%dMB/%dGB", t.DefaultCPUMillicores, t.DefaultMemoryMB, t.DefaultDiskGB)
				fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\n",
					t.ID, t.Name, t.Type, t.BuildStatus, resources, timeAgo(t.CreatedAt))
			}
			return w.Flush()
		},
	}

	cmd.Flags().StringVar(&envType, "type", "", "Filter by type (coder, sandbox)")
	return cmd
}

func templateCreateCmd() *cobra.Command {
	var (
		tmplType    string
		name        string
		description string
		cpu         int
		memory      int
		disk        int
		ttl         string
		image       string
	)

	cmd := &cobra.Command{
		Use:   "create",
		Short: "Create an environment template",
		RunE: func(cmd *cobra.Command, args []string) error {
			if tmplType == "" {
				return fmt.Errorf("--type is required")
			}
			if name == "" {
				return fmt.Errorf("--name is required")
			}

			orgID, client, err := getDefaultOrg()
			if err != nil {
				return err
			}

			req := &platform.CreateTemplateRequest{
				Type:        tmplType,
				Name:        name,
				Description: description,
				Image:       image,
			}
			if cpu > 0 {
				req.DefaultCPUMillicores = &cpu
			}
			if memory > 0 {
				req.DefaultMemoryMB = &memory
			}
			if disk > 0 {
				req.DefaultDiskGB = &disk
			}
			if ttl != "" {
				d, err := time.ParseDuration(ttl)
				if err != nil {
					return fmt.Errorf("invalid --ttl duration: %w", err)
				}
				secs := int(d.Seconds())
				req.DefaultTTLSeconds = &secs
			}

			tmpl, err := client.CreateEnvTemplate(orgID, req)
			if err != nil {
				return fmt.Errorf("create template: %w", err)
			}

			fmt.Printf("Template created: %s\n", tmpl.Name)
			fmt.Printf("  ID:    %s\n", tmpl.ID)
			fmt.Printf("  Type:  %s\n", tmpl.Type)
			fmt.Printf("  Build: %s\n", tmpl.BuildStatus)
			return nil
		},
	}

	cmd.Flags().StringVar(&tmplType, "type", "", "Template type (required)")
	cmd.Flags().StringVar(&name, "name", "", "Template name (required)")
	cmd.Flags().StringVar(&description, "description", "", "Template description")
	cmd.Flags().IntVar(&cpu, "cpu", 0, "Default CPU in millicores")
	cmd.Flags().IntVar(&memory, "memory", 0, "Default memory in MB")
	cmd.Flags().IntVar(&disk, "disk", 0, "Default disk in GB")
	cmd.Flags().StringVar(&ttl, "ttl", "", "Default TTL (e.g. 1h, 30m)")
	cmd.Flags().StringVar(&image, "image", "", "Container image for sandbox template")
	return cmd
}

func templateRmCmd() *cobra.Command {
	return &cobra.Command{
		Use:     "rm <id>",
		Short:   "Delete an environment template",
		Aliases: []string{"delete"},
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			orgID, client, err := getDefaultOrg()
			if err != nil {
				return err
			}

			if err := client.DeleteEnvTemplate(orgID, args[0]); err != nil {
				return fmt.Errorf("delete template: %w", err)
			}
			fmt.Printf("Template %s deleted.\n", args[0])
			return nil
		},
	}
}
