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
		if state, err := loadLocalInstancesForCLI(); err == nil && state != nil {
			if key, instance, localErr := resolveLocalInstance(state, ref); localErr == nil && instance != nil {
				return &cwconfig.CurrentTargetConfig{
					Kind: "local",
					Ref:  key,
					Name: instance.Name,
				}, nil
			}
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

func targetSummaryLine(target *cwconfig.CurrentTargetConfig, env *platform.Environment) string {
	if target == nil || target.Kind == "local" && target.Ref == "local" {
		return "local"
	}
	if target.Kind == "local" {
		instance := lookupLocalInstanceForTarget(target)
		name := target.Name
		if instance != nil && strings.TrimSpace(instance.Name) != "" {
			name = instance.Name
		}
		if strings.TrimSpace(name) == "" {
			name = target.Ref
		}
		summary := name
		if instance != nil && strings.TrimSpace(instance.Backend) != "" {
			summary += " [" + instance.Backend + "]"
			if status, err := localRuntimeStatus(instance); err == nil && strings.TrimSpace(status) != "" {
				summary += " " + status
			}
		}
		return summary
	}

	name := target.Name
	if env != nil && env.Name != nil && strings.TrimSpace(*env.Name) != "" {
		name = *env.Name
	}
	if strings.TrimSpace(name) == "" {
		name = target.Ref
	}

	summary := fmt.Sprintf("%s [%s]", name, shortEnvID(target.Ref))
	if env != nil && strings.TrimSpace(env.State) != "" {
		summary += " " + env.State
	}
	return summary
}

func lookupEnvironmentForTarget(target *cwconfig.CurrentTargetConfig) *platform.Environment {
	if target == nil || target.Kind != "env" {
		return nil
	}
	client, err := platform.NewClient()
	if err != nil {
		return nil
	}
	orgID, err := resolveOrgID(client, "")
	if err != nil {
		return nil
	}
	env, err := client.GetEnvironment(orgID, target.Ref)
	if err != nil {
		return nil
	}
	return env
}

func lookupLocalInstanceForTarget(target *cwconfig.CurrentTargetConfig) *cwconfig.LocalInstance {
	if target == nil || target.Kind != "local" || strings.TrimSpace(target.Ref) == "" || target.Ref == "local" {
		return nil
	}
	state, err := loadLocalInstancesForCLI()
	if err != nil || state == nil {
		return nil
	}
	instance, ok := state.Instances[target.Ref]
	if !ok {
		return nil
	}
	return &instance
}

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
	if state, err := loadLocalInstancesForCLI(); err == nil && state != nil {
		for _, name := range sortedLocalInstanceNames(state) {
			if strings.TrimSpace(toComplete) == "" || strings.HasPrefix(strings.ToLower(name), strings.ToLower(strings.TrimSpace(toComplete))) {
				completions = append(completions, name)
			}
		}
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

			if target.Kind == "local" && target.Ref == "local" {
				successMsg("Current target set to local.")
				return nil
			}
			if target.Kind == "local" {
				successMsg("Current target set to %s.", target.Name)
				return nil
			}
			successMsg("Current target set to %s (%s).", target.Name, shortEnvID(target.Ref))
			return nil
		},
	}
}

func currentCmd() *cobra.Command {
	var verbose bool

	cmd := &cobra.Command{
		Use:   "current",
		Short: "Show the current execution target",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := loadCLIConfigForTarget()
			if err != nil {
				cfg = &cwconfig.Config{}
			}
			target := currentTargetConfig(cfg)
			env := lookupEnvironmentForTarget(target)

			if !verbose {
				fmt.Println(targetSummaryLine(target, env))
				return nil
			}

			fmt.Printf("%-10s %s\n", bold("Kind:"), target.Kind)
			if target.Kind == "local" && target.Ref == "local" {
				fmt.Printf("%-10s %s\n", bold("Target:"), "local")
				return nil
			}
			if target.Kind == "local" {
				fmt.Printf("%-10s %s\n", bold("Target:"), target.Name)
				if instance := lookupLocalInstanceForTarget(target); instance != nil {
					fmt.Printf("%-10s %s\n", bold("Backend:"), instance.Backend)
					fmt.Printf("%-10s %s\n", bold("Runtime:"), instance.RuntimeName)
					if status, err := localRuntimeStatus(instance); err == nil {
						fmt.Printf("%-10s %s\n", bold("State:"), stateColor(status))
					}
				}
				return nil
			}

			fmt.Printf("%-10s %s\n", bold("Target:"), target.Name)
			fmt.Printf("%-10s %s\n", bold("ID:"), target.Ref)
			fmt.Printf("%-10s %s\n", bold("ShortID:"), shortEnvID(target.Ref))

			if env != nil {
				if env.Name != nil && strings.TrimSpace(*env.Name) != "" {
					fmt.Printf("%-10s %s\n", bold("Name:"), *env.Name)
				}
				fmt.Printf("%-10s %s\n", bold("State:"), stateColor(env.State))
			}

			return nil
		},
	}

	cmd.Flags().BoolVarP(&verbose, "verbose", "v", false, "Show full target details")
	return cmd
}
