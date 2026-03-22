package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/codewiresh/codewire/internal/platform"
)

const environmentRunExecTimeoutSeconds = 30

var runInEnvironmentTarget = func(envID, workDir, name string, envVars []string, tags []string, command []string) (*platform.ExecResult, error) {
	orgID, client, err := getDefaultOrg()
	if err != nil {
		return nil, err
	}
	return client.ExecInEnvironment(orgID, envID, &platform.ExecRequest{
		Command:    buildEnvironmentRunCommand(workDir, name, envVars, tags, command),
		WorkingDir: "/workspace",
		Timeout:    environmentRunExecTimeoutSeconds,
	})
}

func buildEnvironmentRunCommand(workDir, name string, envVars []string, tags []string, command []string) []string {
	runCommand := []string{"cw", "run"}
	if workDir != "" {
		runCommand = append(runCommand, "--dir", workDir)
	}
	if name != "" {
		runCommand = append(runCommand, "--name", name)
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
		return fmt.Errorf("environment image does not include the codewire CLI; use a Codewire base image for 'cw run' support or fall back to 'cw exec'")
	}
	return fmt.Errorf("environment run exited with code %d", result.ExitCode)
}
