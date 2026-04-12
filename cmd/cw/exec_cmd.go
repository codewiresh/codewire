package main

import (
	"fmt"
	"os"
	osExec "os/exec"
	"strings"

	"github.com/spf13/cobra"

	cwconfig "github.com/codewiresh/codewire/internal/config"
	"github.com/codewiresh/codewire/internal/guestagent"
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

var execInLocalRuntimeTarget = func(instance *cwconfig.LocalInstance, workDir string, command []string, allocTTY ...bool) error {
	wantTTY := len(allocTTY) > 0 && allocTTY[0]
	if instance == nil {
		return fmt.Errorf("local instance is required")
	}
	if len(command) == 0 {
		return fmt.Errorf("no command specified")
	}

	var cmd *osExec.Cmd
	switch instance.Backend {
	case "docker":
		args := []string{"exec", "-i"}
		if wantTTY {
			args = append(args, "-t")
		}
		if strings.TrimSpace(workDir) != "" {
			args = append(args, "-w", workDir)
		}
		args = append(args, instance.RuntimeName)
		args = append(args, command...)
		cmd = osExec.Command("docker", args...)
	case "incus":
		args := []string{"exec"}
		if strings.TrimSpace(workDir) != "" {
			args = append(args, "--cwd", workDir)
		}
		args = append(args, instance.RuntimeName, "--")
		args = append(args, command...)
		cmd = osExec.Command("incus", args...)
	case "lima":
		// Lima runs a Docker container inside the VM. Route exec through it.
		name := limaInstanceName(instance)

		// Verify the command exists inside the container, not the VM.
		checkOut, checkErr := localRunCommand("limactl", "shell", "--workdir", "/", name,
			"sudo", "docker", "exec", limaContainerName, "which", command[0])
		if checkErr != nil {
			return fmt.Errorf("%q not found inside Lima instance %q\n%s", command[0], name, strings.TrimSpace(string(checkOut)))
		}

		wd := workDir
		if wd == "" {
			wd = instance.Workdir
		}

		// limactl shell <vm> sudo docker exec -i [-t] -w <wd> cw-workspace <command...>
		dockerArgs := []string{"sudo", "docker", "exec", "-i"}
		if wantTTY {
			dockerArgs = append(dockerArgs, "-t")
		}
		if strings.TrimSpace(wd) != "" {
			dockerArgs = append(dockerArgs, "-w", wd)
		}
		dockerArgs = append(dockerArgs, limaContainerName)
		dockerArgs = append(dockerArgs, command...)

		args := []string{"shell", "--workdir", "/", name}
		args = append(args, dockerArgs...)
		cmd = osExec.Command("limactl", args...)
	case "firecracker":
		vsockPath := instance.FirecrackerSocket + ".vsock"
		agent, err := guestagent.DialVsockUDS(vsockPath)
		if err != nil {
			return fmt.Errorf("connect to guest agent: %w\n  Is the VM running? Check: cw local list", err)
		}
		defer agent.Close()
		wd := workDir
		if wd == "" {
			wd = instance.Workdir
		}
		exitCode, execErr := agent.Exec(command, wd)
		if execErr != nil {
			return execErr
		}
		os.Exit(exitCode)
		return nil
	default:
		return fmt.Errorf("unsupported local backend %q", instance.Backend)
	}

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
		workDir     string
		timeout     int
		on          string
		interactive bool
		tty         bool
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
				if target.Ref != "" && target.Ref != "local" {
					instance := lookupLocalInstanceForTarget(target)
					if instance == nil {
						return fmt.Errorf("local instance not found: %s", target.Ref)
					}
					if workDir == "" {
						workDir = instance.Workdir
						if workDir == "" {
							workDir = localWorkspacePath
						}
					}
					return execInLocalRuntimeTarget(instance, workDir, cmdArgs, interactive && tty)
				}
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
	cmd.Flags().BoolVarP(&interactive, "interactive", "i", false, "Keep stdin open")
	cmd.Flags().BoolVarP(&tty, "tty", "t", false, "Allocate a pseudo-TTY")
	return cmd
}
