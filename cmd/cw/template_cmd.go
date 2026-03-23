package main

import (
	"fmt"
	"os"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"github.com/codewiresh/codewire/internal/platform"
)

func presetParentCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "preset",
		Short: "Manage environment presets",
	}
	cmd.AddCommand(presetInitCmd())
	cmd.AddCommand(presetListCmd())
	cmd.AddCommand(presetCreateCmd())
	cmd.AddCommand(presetInfoCmd())
	cmd.AddCommand(presetRmCmd())
	return cmd
}

func presetListCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "list",
		Short:   "List environment presets",
		Aliases: []string{"ls"},
		RunE: func(cmd *cobra.Command, args []string) error {
			orgID, client, err := getDefaultOrg()
			if err != nil {
				return err
			}

			presets, err := client.ListPresets(orgID)
			if err != nil {
				return fmt.Errorf("list presets: %w", err)
			}

			if len(presets) == 0 {
				fmt.Println("No presets found.")
				return nil
			}

			w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
			tableHeader(w, "NAME", "LANGUAGE", "IMAGE", "OFFICIAL", "CPU/MEM/DISK")
			for _, t := range presets {
				slug := "--"
				if t.Slug != nil {
					slug = *t.Slug
				}
				lang := "--"
				if t.Language != nil && *t.Language != "" {
					lang = *t.Language
				}
				official := ""
				if t.Official {
					official = "yes"
				}
				image := "--"
				if t.Image != nil && *t.Image != "" {
					image = *t.Image
				}
				resources := fmt.Sprintf("%dm/%dMB/%dGB", t.DefaultCPUMillicores, t.DefaultMemoryMB, t.DefaultDiskGB)
				fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n",
					slug, lang, image, official, resources)
			}
			return w.Flush()
		},
	}

	return cmd
}

func presetCreateCmd() *cobra.Command {
	var (
		name          string
		image         string
		install       string
		startup       string
		cpu           int
		memory        int
		disk          int
		ttl           string
		description   string
		secretProject string
	)

	cmd := &cobra.Command{
		Use:   "create <slug>",
		Short: "Create an environment preset",
		Long: `Create a preset with a short name (slug) for reuse.

Examples:
  cw preset create my-app --image go --install "go mod download"
  cw preset create my-app --image go --secrets my-project`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			slug := args[0]

			if image == "" {
				return fmt.Errorf("--image is required")
			}

			// Image shorthand: expand bare names (e.g. "full" → ghcr.io/codewiresh/full:latest).
			if image != "" && !containsSlash(image) {
				image = expandImageRef(image)
			}

			orgID, client, err := getDefaultOrg()
			if err != nil {
				return err
			}

			req := &platform.CreatePresetRequest{
				Name:           slug,
				Slug:           slug,
				Description:    description,
				Image:          image,
				InstallCommand: install,
				StartupScript:  startup,
				SecretProject:  secretProject,
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

			if name != "" {
				req.Name = name
			}

			preset, err := client.CreatePreset(orgID, req)
			if err != nil {
				return fmt.Errorf("create preset: %w", err)
			}

			successMsg("Preset created: %s.", preset.Name)
			fmt.Printf("  ID:    %s\n", preset.ID)
			return nil
		},
	}

	cmd.Flags().StringVar(&name, "name", "", "Display name (defaults to slug)")
	cmd.Flags().StringVar(&image, "image", "", "Container image (shorthand: go, node, python)")
	cmd.Flags().StringVar(&install, "install", "", "Default install command")
	cmd.Flags().StringVar(&startup, "startup", "", "Default startup script")
	cmd.Flags().IntVar(&cpu, "cpu", 0, "Default CPU in millicores")
	cmd.Flags().IntVar(&memory, "memory", 0, "Default memory in MB")
	cmd.Flags().IntVar(&disk, "disk", 0, "Default disk in GB")
	cmd.Flags().StringVar(&ttl, "ttl", "", "Default TTL (e.g. 1h, 30m)")
	cmd.Flags().StringVar(&description, "description", "", "Preset description")
	cmd.Flags().StringVar(&secretProject, "secrets", "", "Default secret project to bind")
	return cmd
}

func presetInfoCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "info <slug-or-id>",
		Short: "Show preset details",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			orgID, client, err := getDefaultOrg()
			if err != nil {
				return err
			}

			// Try to find by slug first by listing all presets.
			presets, err := client.ListPresets(orgID)
			if err != nil {
				return fmt.Errorf("list presets: %w", err)
			}

			var preset *platform.Preset
			for i, t := range presets {
				if t.ID == args[0] || (t.Slug != nil && *t.Slug == args[0]) {
					preset = &presets[i]
					break
				}
			}
			if preset == nil {
				return fmt.Errorf("preset not found: %s", args[0])
			}

			slug := "--"
			if preset.Slug != nil {
				slug = *preset.Slug
			}
			lang := "--"
			if preset.Language != nil && *preset.Language != "" {
				lang = *preset.Language
			}

			fmt.Printf("%-10s %s\n", bold("ID:"), dim(preset.ID))
			fmt.Printf("%-10s %s\n", bold("Name:"), preset.Name)
			fmt.Printf("%-10s %s\n", bold("Slug:"), slug)
			fmt.Printf("%-10s %s\n", bold("Language:"), lang)
			if preset.Image != nil && *preset.Image != "" {
				fmt.Printf("%-10s %s\n", bold("Image:"), *preset.Image)
			}
			fmt.Printf("%-10s %v\n", bold("Official:"), preset.Official)
			fmt.Printf("%-10s %s\n", bold("Build:"), preset.BuildStatus)
			fmt.Printf("CPU:      %dm\n", preset.DefaultCPUMillicores)
			fmt.Printf("Memory:   %dMB\n", preset.DefaultMemoryMB)
			fmt.Printf("Disk:     %dGB\n", preset.DefaultDiskGB)
			return nil
		},
	}
}

func presetRmCmd() *cobra.Command {
	return &cobra.Command{
		Use:     "rm <id>",
		Short:   "Delete an environment preset",
		Aliases: []string{"delete"},
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			orgID, client, err := getDefaultOrg()
			if err != nil {
				return err
			}

			if err := client.DeletePreset(orgID, args[0]); err != nil {
				return fmt.Errorf("delete preset: %w", err)
			}
			successMsg("Preset %s deleted.", args[0])
			return nil
		},
	}
}

func containsSlash(s string) bool {
	for _, c := range s {
		if c == '/' {
			return true
		}
	}
	return false
}
