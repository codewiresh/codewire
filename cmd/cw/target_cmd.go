package main

import (
	"fmt"
	"strings"

	"github.com/spf13/cobra"

	cwconfig "github.com/codewiresh/codewire/internal/config"
	"github.com/codewiresh/codewire/internal/platform"
)

var (
	loadCLIConfigForTarget = func() (*cwconfig.Config, error) {
		return cwconfig.LoadConfig(dataDir())
	}
	saveCLIConfigForTarget = func(cfg *cwconfig.Config) error {
		return cwconfig.SaveConfig(dataDir(), cfg)
	}
	resolveNamedExecutionTarget = func(ref string) (*cwconfig.CurrentTargetConfig, error) {
		ref = strings.TrimSpace(ref)
		if ref == "" {
			return nil, fmt.Errorf("target is required")
		}
		if ref == "local" {
			return &cwconfig.CurrentTargetConfig{
				Kind: "local",
				Ref:  "local",
				Name: "local",
			}, nil
		}

		orgID, client, err := getDefaultOrg()
		if err != nil {
			return nil, err
		}
		envID, err := resolveEnvID(client, orgID, ref)
		if err != nil {
			return nil, err
		}
		env, err := client.GetEnvironment(orgID, envID)
		if err != nil {
			return nil, fmt.Errorf("get environment: %w", err)
		}

		name := envID
		if env.Name != nil && strings.TrimSpace(*env.Name) != "" {
			name = *env.Name
		}
		return &cwconfig.CurrentTargetConfig{
			Kind: "env",
			Ref:  envID,
			Name: name,
		}, nil
	}
)

func currentTargetConfig(cfg *cwconfig.Config) *cwconfig.CurrentTargetConfig {
	if cfg == nil || cfg.CurrentTarget == nil || strings.TrimSpace(cfg.CurrentTarget.Kind) == "" {
		return &cwconfig.CurrentTargetConfig{
			Kind: "local",
			Ref:  "local",
			Name: "local",
		}
	}
	return cfg.CurrentTarget
}

func selectedExecutionTarget(ref string) (*cwconfig.CurrentTargetConfig, error) {
	if strings.TrimSpace(ref) != "" {
		return resolveNamedExecutionTarget(ref)
	}

	cfg, err := loadCLIConfigForTarget()
	if err != nil {
		cfg = &cwconfig.Config{}
	}
	return currentTargetConfig(cfg), nil
}

func requireEnvironmentTarget(ref string) (*cwconfig.CurrentTargetConfig, error) {
	target, err := selectedExecutionTarget(ref)
	if err != nil {
		return nil, err
	}
	if target.Kind != "env" {
		return nil, fmt.Errorf("current target is %q; select an environment with 'cw use <env>' or pass one explicitly", target.Kind)
	}
	return target, nil
}

func targetCompletionFunc(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
	completions := []string{"local"}
	if strings.TrimSpace(toComplete) != "" && !strings.HasPrefix("local", strings.ToLower(strings.TrimSpace(toComplete))) {
		completions = nil
	}
	envCompletions, directive := envCompletionFunc(cmd, args, toComplete)
	completions = append(completions, envCompletions...)
	return completions, directive
}

func useCmd() *cobra.Command {
	return &cobra.Command{
		Use:               "use <target>",
		Short:             "Set the current execution target",
		Args:              cobra.ExactArgs(1),
		ValidArgsFunction: targetCompletionFunc,
		RunE: func(cmd *cobra.Command, args []string) error {
			target, err := resolveNamedExecutionTarget(args[0])
			if err != nil {
				return err
			}

			cfg, err := loadCLIConfigForTarget()
			if err != nil {
				cfg = &cwconfig.Config{}
			}
			cfg.CurrentTarget = target
			if err := saveCLIConfigForTarget(cfg); err != nil {
				return fmt.Errorf("save current target: %w", err)
			}

			if target.Kind == "local" {
				successMsg("Current target set to local.")
				return nil
			}
			successMsg("Current target set to %s (%s).", target.Name, shortEnvID(target.Ref))
			return nil
		},
	}
}

func currentCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "current",
		Short: "Show the current execution target",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := loadCLIConfigForTarget()
			if err != nil {
				cfg = &cwconfig.Config{}
			}
			target := currentTargetConfig(cfg)

			fmt.Printf("%-10s %s\n", bold("Kind:"), target.Kind)
			if target.Kind == "local" {
				fmt.Printf("%-10s %s\n", bold("Target:"), "local")
				return nil
			}

			fmt.Printf("%-10s %s\n", bold("Target:"), target.Name)
			fmt.Printf("%-10s %s\n", bold("ID:"), target.Ref)
			fmt.Printf("%-10s %s\n", bold("ShortID:"), shortEnvID(target.Ref))

			if client, err := platform.NewClient(); err == nil {
				if orgID, orgErr := resolveOrgID(client, ""); orgErr == nil {
					if env, envErr := client.GetEnvironment(orgID, target.Ref); envErr == nil {
						if env.Name != nil && strings.TrimSpace(*env.Name) != "" {
							fmt.Printf("%-10s %s\n", bold("Name:"), *env.Name)
						}
						fmt.Printf("%-10s %s\n", bold("State:"), stateColor(env.State))
					}
				}
			}

			return nil
		},
	}
}
