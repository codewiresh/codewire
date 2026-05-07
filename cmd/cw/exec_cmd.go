package main

import (
	"bytes"
	"fmt"
	"os"
	osExec "os/exec"
	"strings"

	"github.com/spf13/cobra"

	cwconfig "github.com/codewiresh/codewire/internal/config"
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
// incus, lima.
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

		// limactl shell <vm> sudo docker exec -i [-t] -w <wd> cw-workspace <command...>
		dockerArgs := []string{"sudo", "docker", "exec", "-i"}
		if wantTTY {
			dockerArgs = append(dockerArgs, "-t")
		}
		if strings.TrimSpace(wd) != "" {
			dockerArgs = append(dockerArgs, "-w", wd)
		}
		dockerArgs = appendLocalRuntimeEnvArgs(dockerArgs, "-e")
		dockerArgs = append(dockerArgs, limaContainerName)
		dockerArgs = append(dockerArgs, command...)

		args := []string{"shell", "--workdir", "/", name}
		args = append(args, dockerArgs...)
		cmd = osExec.Command("limactl", args...)
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
		interactive bool
		tty         bool
		jsonOutput  bool
		sessionDir  string
		tags        []string
		name        string
		group       string
		envVars     []string
		autoApprove bool
		promptFile  string
	)

	cmd := &cobra.Command{
		Use:   "exec [target] -- <command> [args...]",
		Short: "Execute a command on a target",
		Long:  "Run a command on a target. If target is omitted, uses the current target. Session flags such as --name, --tag, or --group launch a Codewire session via the target runtime.",
		Args:  cobra.ArbitraryArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			targetRef := ""
			cmdArgs := args
			if dash := cmd.ArgsLenAtDash(); dash >= 0 {
				if dash > 1 {
					return fmt.Errorf("expected at most one target before --")
				}
				if dash == 1 {
					targetRef = args[0]
				}
				cmdArgs = args[dash:]
			}
			if len(cmdArgs) == 0 {
				return fmt.Errorf("no command specified. Usage: cw exec [target] -- <command>")
			}
			if cmd.Flags().Changed("dir") {
				if cmd.Flags().Changed("workdir") {
					return fmt.Errorf("use either --dir or --workdir, not both")
				}
				workDir = sessionDir
			}

			sessionMode := name != "" || group != "" || len(tags) > 0 || len(envVars) > 0 || autoApprove || promptFile != "" || cmd.Flags().Changed("dir")
			if sessionMode {
				if jsonOutput {
					return fmt.Errorf("--json cannot be used with session flags")
				}
				if autoApprove && len(cmdArgs) > 0 {
					cmdArgs = append([]string{cmdArgs[0], "--dangerously-skip-permissions"}, cmdArgs[1:]...)
				}

				var stdinData []byte
				if promptFile != "" {
					var readErr error
					stdinData, readErr = os.ReadFile(promptFile)
					if readErr != nil {
						return fmt.Errorf("reading prompt file: %w", readErr)
					}
				}
				return execSession(targetRef, workDir, name, group, envVars, stdinData, tags, cmdArgs)
			}

			target, err := selectedExecutionTarget(targetRef)
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

	cmd.Flags().StringVarP(&workDir, "workdir", "w", "", "Working directory (default: cwd for local, /workspace for env)")
	cmd.Flags().IntVar(&timeout, "timeout", 0, "Timeout in seconds for environment exec (0 = server default, currently 10m)")
	cmd.Flags().BoolVarP(&interactive, "interactive", "i", false, "Keep stdin open")
	cmd.Flags().BoolVarP(&tty, "tty", "t", false, "Allocate a pseudo-TTY")
	cmd.Flags().BoolVar(&jsonOutput, "json", false, "Capture stdout/stderr and emit {exit_code,stdout,stderr} JSON on completion")
	cmd.Flags().StringVarP(&sessionDir, "dir", "d", "", "Working directory for the session")
	cmd.Flags().StringSliceVar(&tags, "tag", nil, "Tags for the session (can be repeated)")
	cmd.Flags().StringVar(&name, "name", "", "Unique name for the session (alphanumeric + hyphens, 1-32 chars)")
	cmd.Flags().StringVar(&group, "group", "", "Attach the named session to a relay group")
	cmd.Flags().StringArrayVarP(&envVars, "env", "e", nil, "Environment variable overrides for session launches (KEY=VALUE, can be repeated)")
	cmd.Flags().BoolVar(&autoApprove, "auto-approve", false, "Inject --dangerously-skip-permissions after the command binary")
	cmd.Flags().StringVar(&promptFile, "prompt-file", "", "File whose contents are injected as stdin after launch")
	_ = cmd.RegisterFlagCompletionFunc("tag", tagCompletionFunc)
	return cmd
}

func execSession(targetRef, workDir, name, group string, envVars []string, stdinData []byte, tags []string, command []string) error {
	group = strings.TrimSpace(group)
	if group != "" {
		if strings.TrimSpace(name) == "" {
			return fmt.Errorf("--group requires --name")
		}
		if serverFlag != "" {
			return fmt.Errorf("--group cannot be used with --server")
		}
		tags = appendGroupTag(tags, group)
	}

	if serverFlag != "" {
		if strings.TrimSpace(targetRef) != "" {
			return fmt.Errorf("target cannot be used with --server")
		}
		target, err := resolveTargetForRun()
		if err != nil {
			return err
		}
		if target.IsLocal() {
			if err := ensureNodeForRun(); err != nil {
				return err
			}
		}
		if workDir == "" {
			workDir, _ = os.Getwd()
		}
		return runOnTarget(target, command, workDir, name, envVars, stdinData, tags...)
	}

	execTarget, err := selectedExecutionTarget(targetRef)
	if err != nil {
		return err
	}
	switch execTarget.Kind {
	case "local":
		target, err := resolveTargetForRun()
		if err != nil {
			return err
		}
		if err := ensureNodeForRun(); err != nil {
			return err
		}
		runCommand := command
		runWorkDir := workDir
		if execTarget.Ref != "" && execTarget.Ref != "local" {
			instance := lookupLocalInstanceForTarget(execTarget)
			if instance == nil {
				return fmt.Errorf("local instance not found: %s", execTarget.Ref)
			}
			runCommand, runWorkDir, err = wrapLocalRuntimeRunCommand(instance, workDir, command)
			if err != nil {
				return err
			}
		}
		if group != "" {
			if err := validateLocalGroupedRun(group); err != nil {
				return err
			}
		}
		if strings.TrimSpace(runWorkDir) == "" {
			runWorkDir, _ = os.Getwd()
		}
		return runOnTarget(target, runCommand, runWorkDir, name, envVars, stdinData, tags...)
	case "env":
		if len(stdinData) > 0 {
			return fmt.Errorf("--prompt-file is not supported for environment targets yet")
		}
		if workDir == "" {
			workDir = "/workspace"
		}
		printEnvironmentRunPreamble(execTarget)
		result, err := runInEnvironmentTarget(execTarget.Ref, workDir, name, group, envVars, tags, command)
		if err != nil {
			return fmt.Errorf("exec: %w", err)
		}
		if err := printEnvironmentRunResult(result); err != nil {
			return err
		}
		sessionRef := name
		if sessionRef == "" {
			sessionRef = "1"
		}
		fmt.Fprintf(os.Stderr, "  follow: cw exec %s -- cw logs %s --follow\n", shortEnvID(execTarget.Ref), sessionRef)
		return nil
	default:
		return fmt.Errorf("unsupported target kind %q", execTarget.Kind)
	}
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
