package main

import (
	"bytes"
	"fmt"
	"os"
	osExec "os/exec"
	"strings"

	"github.com/spf13/cobra"

	cwconfig "github.com/codewiresh/codewire/internal/config"
	"github.com/codewiresh/codewire/internal/guestagent"
	"github.com/codewiresh/codewire/internal/platform"
)

// execBufferedResult is the JSON shape produced by `cw exec --json`. SDK
// consumers decode this directly.
type execBufferedResult struct {
	ExitCode int    `json:"exit_code"`
	Stdout   string `json:"stdout"`
	Stderr   string `json:"stderr"`
}

// execInLocalRuntimeBuffered runs command inside the local VM and captures
// stdout/stderr into buffers instead of streaming. Supported backends: docker,
// incus, lima. For firecracker the guest-agent protocol does not currently
// expose captured output; callers should route around this for now.
func execInLocalRuntimeBuffered(instance *cwconfig.LocalInstance, workDir string, command []string) (*execBufferedResult, error) {
	if instance == nil {
		return nil, fmt.Errorf("local instance is required")
	}
	if len(command) == 0 {
		return nil, fmt.Errorf("no command specified")
	}

	var cmd *osExec.Cmd
	switch instance.Backend {
	case "docker":
		args := []string{"exec", "-i"}
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
		name := limaInstanceName(instance)
		wd := workDir
		if wd == "" {
			wd = instance.Workdir
		}
		dockerArgs := []string{"sudo", "docker", "exec", "-i"}
		if strings.TrimSpace(wd) != "" {
			dockerArgs = append(dockerArgs, "-w", wd)
		}
		dockerArgs = append(dockerArgs, limaContainerName)
		dockerArgs = append(dockerArgs, command...)
		args := []string{"shell", "--workdir", "/", name}
		args = append(args, dockerArgs...)
		cmd = osExec.Command("limactl", args...)
	case "firecracker":
		return nil, fmt.Errorf("cw exec --json is not yet supported for the firecracker backend")
	default:
		return nil, fmt.Errorf("unsupported local backend %q", instance.Backend)
	}

	var stdoutBuf, stderrBuf bytes.Buffer
	cmd.Stdin = os.Stdin
	cmd.Stdout = &stdoutBuf
	cmd.Stderr = &stderrBuf
	runErr := cmd.Run()
	exitCode := 0
	if runErr != nil {
		if exitErr, ok := runErr.(*osExec.ExitError); ok {
			exitCode = exitErr.ExitCode()
		} else {
			return nil, runErr
		}
	}
	return &execBufferedResult{
		ExitCode: exitCode,
		Stdout:   stdoutBuf.String(),
		Stderr:   stderrBuf.String(),
	}, nil
}

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

var localRuntimeTerminalEnvKeys = []string{
	"TERM",
	"COLORTERM",
	"TERM_PROGRAM",
	"TERM_PROGRAM_VERSION",
	"LC_TERMINAL",
	"LC_TERMINAL_VERSION",
	"KITTY_WINDOW_ID",
	"KITTY_PUBLIC_KEY",
	"KITTY_INSTALLATION_DIR",
	"WEZTERM_PANE",
	"WT_SESSION",
	"WT_PROFILE_ID",
	"VTE_VERSION",
}

func normalizeLocalRuntimeTERM(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return "xterm-256color"
	}

	switch value {
	case "xterm", "xterm-color", "xterm-256color", "screen", "screen-256color", "vt100", "linux", "dumb":
		return value
	default:
		return "xterm-256color"
	}
}

func localRuntimeTerminalEnv() []string {
	env := make([]string, 0, len(localRuntimeTerminalEnvKeys)+2)
	hasTerm := false
	hasColorTerm := false
	for _, key := range localRuntimeTerminalEnvKeys {
		value, ok := os.LookupEnv(key)
		if !ok || strings.TrimSpace(value) == "" {
			continue
		}
		if key == "TERM" {
			value = normalizeLocalRuntimeTERM(value)
		}
		env = append(env, key+"="+value)
		if key == "TERM" {
			hasTerm = true
		}
		if key == "COLORTERM" {
			hasColorTerm = true
		}
	}
	if !hasTerm {
		env = append(env, "TERM=xterm-256color")
	}
	if !hasColorTerm {
		env = append(env, "COLORTERM=truecolor")
	}
	return env
}

func appendLocalRuntimeEnvArgs(args []string, flag string) []string {
	for _, entry := range localRuntimeTerminalEnv() {
		args = append(args, flag, entry)
	}
	return args
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
		args = appendLocalRuntimeEnvArgs(args, "-e")
		args = append(args, instance.RuntimeName)
		args = append(args, command...)
		cmd = osExec.Command("docker", args...)
	case "incus":
		args := []string{"exec"}
		if strings.TrimSpace(workDir) != "" {
			args = append(args, "--cwd", workDir)
		}
		args = appendLocalRuntimeEnvArgs(args, "--env")
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

		// limactl shell <vm> sudo docker exec -i [-t] -w <wd> cw-workspace bash -lc 'exec "$@"' bash <command...>
		// The `bash -lc 'exec "$@"' bash <args>` wrapper makes the docker exec
		// run through a login shell, so /etc/profile.d/* gets sourced. That's
		// how cw-claude-token-shadow.sh (PR #8) actually fires for direct
		// `cw exec -- claude` invocations — without this, profile.d only
		// sources for shells started by the user, not for binaries we exec
		// directly. The `exec "$@"` form passes args verbatim so quoting is
		// correct even with embedded spaces; the dummy `bash` after the script
		// is $0 so $1..$N stay in order.
		dockerArgs := []string{"sudo", "docker", "exec", "-i"}
		if wantTTY {
			dockerArgs = append(dockerArgs, "-t")
		}
		if strings.TrimSpace(wd) != "" {
			dockerArgs = append(dockerArgs, "-w", wd)
		}
		dockerArgs = appendLocalRuntimeEnvArgs(dockerArgs, "-e")
		dockerArgs = append(dockerArgs, limaContainerName, "bash", "-lc", `exec "$@"`, "bash")
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
		jsonOutput  bool
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
					if jsonOutput {
						res, err := execInLocalRuntimeBuffered(instance, workDir, cmdArgs)
						if err != nil {
							return err
						}
						return emitJSON(res)
					}
					return execInLocalRuntimeTarget(instance, workDir, cmdArgs, interactive && tty)
				}
				if workDir == "" {
					workDir, _ = os.Getwd()
				}
				if jsonOutput {
					res, err := execLocallyBuffered(workDir, cmdArgs)
					if err != nil {
						return err
					}
					return emitJSON(res)
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
				if jsonOutput {
					return emitJSON(&execBufferedResult{
						ExitCode: result.ExitCode,
						Stdout:   result.Stdout,
						Stderr:   result.Stderr,
					})
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
	cmd.Flags().BoolVar(&jsonOutput, "json", false, "Capture stdout/stderr and emit {exit_code,stdout,stderr} JSON on completion")
	return cmd
}

// execLocallyBuffered runs command in workDir on the host and captures stdout
// and stderr instead of streaming them. Used by `cw exec --json` when the
// target is the host itself (local, no VM).
func execLocallyBuffered(workDir string, command []string) (*execBufferedResult, error) {
	if len(command) == 0 {
		return nil, fmt.Errorf("no command specified")
	}
	cmd := osExec.Command(command[0], command[1:]...)
	cmd.Dir = workDir
	var stdoutBuf, stderrBuf bytes.Buffer
	cmd.Stdin = os.Stdin
	cmd.Stdout = &stdoutBuf
	cmd.Stderr = &stderrBuf
	runErr := cmd.Run()
	exitCode := 0
	if runErr != nil {
		if exitErr, ok := runErr.(*osExec.ExitError); ok {
			exitCode = exitErr.ExitCode()
		} else {
			return nil, runErr
		}
	}
	return &execBufferedResult{
		ExitCode: exitCode,
		Stdout:   stdoutBuf.String(),
		Stderr:   stderrBuf.String(),
	}, nil
}

