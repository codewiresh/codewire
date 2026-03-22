package main

import (
	"fmt"
	"os"
	osExec "os/exec"

	"github.com/spf13/cobra"

	"github.com/codewiresh/codewire/internal/platform"
)

var execInEnvironmentTarget = func(envID, workDir string, timeout int, command []string) (*platform.ExecResult, error) {
	orgID, client, err := getDefaultOrg()
	if err != nil {
		return nil, err
	}
	return client.ExecInEnvironment(orgID, envID, &platform.ExecRequest{
		Command:    command,
		WorkingDir: workDir,
		Timeout:    timeout,
	})
}

var execLocally = func(workDir string, command []string) error {
	if len(command) == 0 {
		return fmt.Errorf("no command specified")
	}
	cmd := osExec.Command(command[0], command[1:]...)
	cmd.Dir = workDir
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		if exitErr, ok := err.(*osExec.ExitError); ok {
			os.Exit(exitErr.ExitCode())
		}
		return err
	}
	return nil
}

func execCmd() *cobra.Command {
	var (
		workDir string
		timeout int
		on      string
	)

	cmd := &cobra.Command{
		Use:   "exec -- <command> [args...]",
		Short: "Execute a one-shot command on the current target",
		Long:  "Run a one-shot command on the current target. For environment targets, uses the platform exec API. For local targets, executes directly on the host.",
		Args:  cobra.ArbitraryArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			cmdArgs := args
			if dash := cmd.ArgsLenAtDash(); dash >= 0 {
				cmdArgs = args[dash:]
			}
			if len(cmdArgs) == 0 {
				return fmt.Errorf("no command specified. Usage: cw exec -- <command>")
			}

			target, err := selectedExecutionTarget(on)
			if err != nil {
				return err
			}

			switch target.Kind {
			case "local":
				if workDir == "" {
					workDir, _ = os.Getwd()
				}
				return execLocally(workDir, cmdArgs)
			case "env":
				if workDir == "" {
					workDir = "/workspace"
				}
				result, err := execInEnvironmentTarget(target.Ref, workDir, timeout, cmdArgs)
				if err != nil {
					return fmt.Errorf("exec: %w", err)
				}
				if result.Stdout != "" {
					fmt.Print(result.Stdout)
				}
				if result.Stderr != "" {
					fmt.Fprint(os.Stderr, result.Stderr)
				}
				if result.ExitCode != 0 {
					os.Exit(result.ExitCode)
				}
				return nil
			default:
				return fmt.Errorf("unsupported target kind %q", target.Kind)
			}
		},
	}

	cmd.Flags().StringVar(&on, "on", "", "Override the current target for this command")
	cmd.Flags().StringVarP(&workDir, "workdir", "w", "", "Working directory (default: cwd for local, /workspace for env)")
	cmd.Flags().IntVar(&timeout, "timeout", 30, "Timeout in seconds for environment exec")
	return cmd
}
