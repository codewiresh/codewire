package main

import (
	"fmt"
	"os"
	"strings"

	cwconfig "github.com/codewiresh/codewire/internal/config"
	"github.com/codewiresh/codewire/internal/platform"
)

// 0 = server-side default (currently 10 minutes). The server already clamps
// non-positive values; sending 0 lets the platform pick the timeout instead
// of the CLI capping it at a fast-path-only number.
const environmentRunExecTimeoutSeconds = 0

var runInEnvironmentTarget = func(envID, workDir, name, group string, envVars []string, tags []string, command []string) (*platform.ExecResult, error) {
	orgID, client, err := getDefaultOrg()
	if err != nil {
		return nil, err
	}
	return client.ExecInEnvironment(orgID, envID, &platform.ExecRequest{
		Command:    buildEnvironmentRunCommand(workDir, name, group, envVars, tags, command),
		WorkingDir: "/workspace",
		Timeout:    environmentRunExecTimeoutSeconds,
	})
}

func buildEnvironmentRunCommand(workDir, name, group string, envVars []string, tags []string, command []string) []string {
	runCommand := []string{"cw", "exec"}
	if workDir != "" {
		runCommand = append(runCommand, "--dir", workDir)
	}
	if name != "" {
		runCommand = append(runCommand, "--name", name)
	}
	if group != "" {
		runCommand = append(runCommand, "--group", group)
	}
	for _, envVar := range envVars {
		runCommand = append(runCommand, "--env", envVar)
	}
	for _, tag := range tags {
		runCommand = append(runCommand, "--tag", tag)
	}
	runCommand = append(runCommand, "--")
	runCommand = append(runCommand, command...)
	return runCommand
}

func printEnvironmentRunResult(result *platform.ExecResult) error {
	if result == nil {
		return nil
	}
	if result.Stdout != "" {
		fmt.Print(result.Stdout)
	}
	if result.Stderr != "" {
		fmt.Fprint(os.Stderr, result.Stderr)
	}
	if result.ExitCode == 0 {
		return nil
	}

	combined := strings.ToLower(result.Stdout + "\n" + result.Stderr)
	if strings.Contains(combined, "cw: not found") || strings.Contains(combined, "exec: cw: not found") {
		return fmt.Errorf("environment image does not include the codewire CLI; use a Codewire base image for session support or run a direct 'cw exec'")
	}
	return fmt.Errorf("environment run exited with code %d", result.ExitCode)
}

func printEnvironmentRunPreamble(target *cwconfig.CurrentTargetConfig) {
	if target == nil || target.Kind != "env" {
		return
	}
	fmt.Fprintf(os.Stderr, "  target: %s [%s] via env runtime\n", target.Name, shortEnvID(target.Ref))
}
