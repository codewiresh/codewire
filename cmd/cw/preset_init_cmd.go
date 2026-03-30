package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"
)

func initCmd() *cobra.Command {
	return newProjectInitCmd("init [repo-url ...]", false)
}

func presetInitCmd() *cobra.Command {
	cmd := newProjectInitCmd("init [repo-url ...]", true)
	cmd.Hidden = true
	cmd.Deprecated = "use 'cw init'"
	return cmd
}

func newProjectInitCmd(use string, legacyPresetAlias bool) *cobra.Command {
	var (
		presetSlug    string
		presetID      string
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
		filePath      string
		force         bool
		savePreset    string
		yes           bool
	)

	short := "Write a codewire.yaml project file"
	long := `Initialize codewire.yaml from direct flags, a repo URL, or server-side preset resolution.

Examples:
  cw init
  cw init --image full --install "pnpm install" --startup "pnpm dev"
  cw init --preset go --save-preset fullstack-dev`
	if legacyPresetAlias {
		short = "Write a codewire.yaml project file (deprecated: use 'cw init')"
		long = `Deprecated alias for 'cw init'.

Initialize codewire.yaml from direct flags, a repo URL, or server-side preset resolution.`
	}

	cmd := &cobra.Command{
		Use:   use,
		Short: short,
		Long:  long,
		Args:  cobra.ArbitraryArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if !force {
				if _, err := os.Stat(filePath); err == nil {
					return fmt.Errorf("%s already exists (use --force to overwrite)", filePath)
				}
			}

			orgID, client, resolved, err := resolvePresetAuthoring(cmd, &presetAuthoringOptions{
				Args:              args,
				RepoFlags:         repoFlags,
				PresetSlug:        presetSlug,
				PresetID:          presetID,
				Name:              name,
				TTL:               ttl,
				CPU:               cpu,
				Memory:            memory,
				Disk:              disk,
				Branch:            branch,
				Image:             image,
				Install:           install,
				Startup:           startup,
				Agent:             agent,
				EnvVars:           envVars,
				SecretProject:     secretProject,
				NoOrgSecrets:      noOrgSecrets,
				NoUserSecrets:     noUserSecrets,
				Yes:               yes,
				AllowCodewireYAML: false,
				PromptOnAnalyze:   false,
				PromptOnDetection: false,
				ShowDetection:     true,
			})
			if err != nil {
				return err
			}

			if err := writeResolvedCodewireYAML(filePath, resolved.Request); err != nil {
				return fmt.Errorf("write codewire.yaml: %w", err)
			}
			successMsg("codewire.yaml written: %s", filePath)

			if strings.TrimSpace(savePreset) != "" {
				presetReq, err := createPresetRequestFromEnvironment(savePreset, resolved.Request)
				if err != nil {
					return err
				}
				preset, err := client.CreatePreset(orgID, presetReq)
				if err != nil {
					return fmt.Errorf("save preset: %w", err)
				}
				successMsg("Preset saved: %s (%s).", preset.Name, preset.ID)
			}

			if !legacyPresetAlias {
				fmt.Fprintln(os.Stderr, "Next:")
				fmt.Fprintln(os.Stderr, "  cw env create")
				fmt.Fprintln(os.Stderr, "  cw local create")
			}
			return nil
		},
	}

	cmd.Flags().StringVar(&presetSlug, "preset", "", "Preset slug (e.g. go, node, python)")
	cmd.Flags().StringVar(&presetID, "preset-id", "", "Preset ID (exact)")
	cmd.Flags().StringVar(&name, "name", "", "Preset or environment name hint")
	cmd.Flags().StringVar(&ttl, "ttl", "", "Time to live (e.g. 1h, 30m)")
	cmd.Flags().IntVar(&cpu, "cpu", 0, "CPU in millicores")
	cmd.Flags().IntVar(&memory, "memory", 0, "Memory in MB")
	cmd.Flags().IntVar(&disk, "disk", 0, "Disk in GB")
	cmd.Flags().StringArrayVar(&repoFlags, "repo", nil, "Git repo URL (repeatable, url@branch syntax)")
	cmd.Flags().StringVar(&branch, "branch", "", "Branch to checkout")
	cmd.Flags().StringVar(&image, "image", "", "Container image (shorthand: full → ghcr.io/codewiresh/full)")
	cmd.Flags().StringVar(&install, "install", "", "Install command")
	cmd.Flags().StringVar(&startup, "startup", "", "Startup script")
	cmd.Flags().StringVar(&agent, "agent", "", "AI agent (claude-code, codex, gemini-cli, aider)")
	cmd.Flags().StringSliceVar(&envVars, "env", nil, "Env vars (KEY=val)")
	cmd.Flags().StringVar(&secretProject, "secrets", "", "Secret project to bind")
	cmd.Flags().BoolVar(&noOrgSecrets, "no-org-secrets", false, "Don't inject org-level secrets")
	cmd.Flags().BoolVar(&noUserSecrets, "no-user-secrets", false, "Don't inject user-level secrets")
	cmd.Flags().StringVar(&filePath, "file", "codewire.yaml", "Path to write")
	cmd.Flags().BoolVar(&force, "force", false, "Overwrite the target file if it exists")
	cmd.Flags().StringVar(&savePreset, "save-preset", "", "Save the resolved preset to the server as well")
	cmd.Flags().BoolVarP(&yes, "yes", "y", false, "Skip confirmation prompts")
	return cmd
}
