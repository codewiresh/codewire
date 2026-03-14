package main

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
)

const (
	sshConfigMarkerStart = "# ---- START CODEWIRE ----"
	sshConfigMarkerEnd   = "# ---- END CODEWIRE ----"
)

type sshConfigOptions struct {
	SSHOptions []string
}

func configSSHCmd() *cobra.Command {
	var (
		configPath string
		sshOptions []string
		dryRun     bool
	)

	cmd := &cobra.Command{
		Use:   "config-ssh",
		Short: "Write OpenSSH config for Codewire environments",
		Long:  "Adds or updates the managed Codewire section in your SSH config so OpenSSH, scp, sftp, rsync, and Remote-SSH can use `cw ssh --stdio` as ProxyCommand.",
		RunE: func(cmd *cobra.Command, args []string) error {
			if strings.HasPrefix(configPath, "~/") {
				home, err := os.UserHomeDir()
				if err != nil {
					return fmt.Errorf("get home dir: %w", err)
				}
				configPath = filepath.Join(home, configPath[2:])
			}

			content, changed, err := renderManagedSSHConfig(configPath, sshConfigOptions{
				SSHOptions: sshOptions,
			})
			if err != nil {
				return err
			}

			if dryRun {
				if _, err := cmd.OutOrStdout().Write(content); err != nil {
					return err
				}
				return nil
			}

			if err := os.MkdirAll(filepath.Dir(configPath), 0o700); err != nil {
				return fmt.Errorf("create ssh config dir: %w", err)
			}
			if err := os.WriteFile(configPath, content, 0o600); err != nil {
				return fmt.Errorf("write ssh config: %w", err)
			}

			if changed {
				fmt.Fprintf(cmd.OutOrStdout(), "Updated %s\n", configPath)
			} else {
				fmt.Fprintf(cmd.OutOrStdout(), "No changes to %s\n", configPath)
			}
			return nil
		},
	}

	cmd.Flags().StringVar(&configPath, "ssh-config-file", defaultSSHConfigPath(), "Path to the SSH config file")
	cmd.Flags().StringArrayVarP(&sshOptions, "ssh-option", "o", nil, "Additional SSH option to add to the managed Codewire host block")
	cmd.Flags().BoolVarP(&dryRun, "dry-run", "n", false, "Print the resulting SSH config instead of writing it")
	return cmd
}

func defaultSSHConfigPath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return "~/.ssh/config"
	}
	return filepath.Join(home, ".ssh", "config")
}

func defaultKnownHostsPath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return "~/.ssh/codewire_known_hosts"
	}
	return filepath.Join(home, ".ssh", "codewire_known_hosts")
}

func renderManagedSSHConfig(configPath string, opts sshConfigOptions) ([]byte, bool, error) {
	existing, err := os.ReadFile(configPath)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, false, fmt.Errorf("read ssh config: %w", err)
	}

	managedSection := sshConfigBlock(opts)
	rendered, err := replaceManagedSSHSection(string(existing), managedSection)
	if err != nil {
		return nil, false, err
	}

	content := []byte(rendered)
	return content, !bytes.Equal(existing, content), nil
}

func sshConfigBlock(opts sshConfigOptions) string {
	var buf strings.Builder
	buf.WriteString(sshConfigMarkerStart)
	buf.WriteString("\n")
	buf.WriteString("# This section is managed by Codewire. Re-run `cw config-ssh` to update it.\n")
	buf.WriteString("Host cw-*\n")
	buf.WriteString("    ProxyCommand cw ssh --stdio %n\n")
	buf.WriteString("    StrictHostKeyChecking accept-new\n")
	buf.WriteString("    UserKnownHostsFile " + defaultKnownHostsPath() + "\n")
	buf.WriteString("    User codewire\n")
	for _, option := range opts.SSHOptions {
		option = strings.TrimSpace(option)
		if option == "" {
			continue
		}
		buf.WriteString("    ")
		buf.WriteString(option)
		buf.WriteString("\n")
	}
	buf.WriteString(sshConfigMarkerEnd)
	return buf.String()
}

func replaceManagedSSHSection(existing, managed string) (string, error) {
	startIdx := strings.Index(existing, sshConfigMarkerStart)
	endIdx := strings.Index(existing, sshConfigMarkerEnd)

	switch {
	case startIdx == -1 && endIdx == -1:
		if existing != "" && !strings.HasSuffix(existing, "\n") {
			existing += "\n"
		}
		if existing != "" {
			existing += "\n"
		}
		return existing + managed + "\n", nil
	case startIdx == -1 || endIdx == -1 || endIdx < startIdx:
		return "", fmt.Errorf("malformed ssh config: Codewire markers are incomplete")
	}

	endIdx += len(sshConfigMarkerEnd)
	if endIdx < len(existing) && existing[endIdx] == '\n' {
		endIdx++
	}
	return existing[:startIdx] + managed + "\n" + existing[endIdx:], nil
}

func writeSSHConfig() error {
	content, _, err := renderManagedSSHConfig(defaultSSHConfigPath(), sshConfigOptions{})
	if err != nil {
		return err
	}

	configPath := defaultSSHConfigPath()
	if err := os.MkdirAll(filepath.Dir(configPath), 0o700); err != nil {
		return fmt.Errorf("create .ssh dir: %w", err)
	}
	return os.WriteFile(configPath, content, 0o600)
}
