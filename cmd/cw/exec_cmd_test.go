package main

import (
	"strings"
	"testing"

	cwconfig "github.com/codewiresh/codewire/internal/config"
	"github.com/codewiresh/codewire/internal/platform"
)

func TestSelectedExecutionTargetDefaultsToLocal(t *testing.T) {
	origLoad := loadCLIConfigForTarget
	defer func() { loadCLIConfigForTarget = origLoad }()

	loadCLIConfigForTarget = func() (*cwconfig.Config, error) {
		return &cwconfig.Config{}, nil
	}

	target, err := selectedExecutionTarget("")
	if err != nil {
		t.Fatalf("selectedExecutionTarget: %v", err)
	}
	if target.Kind != "local" {
		t.Fatalf("target.Kind = %q, want local", target.Kind)
	}
}

func TestRequireEnvironmentTargetRejectsLocal(t *testing.T) {
	origLoad := loadCLIConfigForTarget
	defer func() { loadCLIConfigForTarget = origLoad }()

	loadCLIConfigForTarget = func() (*cwconfig.Config, error) {
		return &cwconfig.Config{}, nil
	}

	_, err := requireEnvironmentTarget("")
	if err == nil {
		t.Fatal("expected local target to be rejected")
	}
}

func TestExecCmdUsesCurrentEnvironmentTarget(t *testing.T) {
	origLoad := loadCLIConfigForTarget
	origExecEnv := execInEnvironmentTarget
	defer func() {
		loadCLIConfigForTarget = origLoad
		execInEnvironmentTarget = origExecEnv
	}()

	loadCLIConfigForTarget = func() (*cwconfig.Config, error) {
		return &cwconfig.Config{
			CurrentTarget: &cwconfig.CurrentTargetConfig{
				Kind: "env",
				Ref:  "f062947a-60e2-405c-b89d-5f48b493d8fb",
				Name: "env-fb08",
			},
		}, nil
	}

	var gotEnvID, gotWorkDir string
	var gotTimeout int
	var gotCommand []string
	execInEnvironmentTarget = func(envID, workDir string, timeout int, command []string) (*platform.ExecResult, error) {
		gotEnvID = envID
		gotWorkDir = workDir
		gotTimeout = timeout
		gotCommand = append([]string(nil), command...)
		return &platform.ExecResult{}, nil
	}

	cmd := execCmd()
	cmd.SetArgs([]string{"--", "pwd"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("exec command failed: %v", err)
	}
	if gotEnvID != "f062947a-60e2-405c-b89d-5f48b493d8fb" {
		t.Fatalf("envID = %q", gotEnvID)
	}
	if gotWorkDir != "/workspace" {
		t.Fatalf("workdir = %q, want /workspace", gotWorkDir)
	}
	if gotTimeout != 0 {
		t.Fatalf("timeout = %d, want 0 (server default)", gotTimeout)
	}
	if len(gotCommand) != 1 || gotCommand[0] != "pwd" {
		t.Fatalf("command = %#v", gotCommand)
	}
}

func TestExecCmdUsesCurrentLocalTarget(t *testing.T) {
	origLoad := loadCLIConfigForTarget
	origExecLocal := execLocally
	defer func() {
		loadCLIConfigForTarget = origLoad
		execLocally = origExecLocal
	}()

	loadCLIConfigForTarget = func() (*cwconfig.Config, error) {
		return &cwconfig.Config{}, nil
	}

	var gotWorkDir string
	var gotCommand []string
	execLocally = func(workDir string, command []string) error {
		gotWorkDir = workDir
		gotCommand = append([]string(nil), command...)
		return nil
	}

	cmd := execCmd()
	cmd.SetArgs([]string{"--workdir", "/tmp", "--", "pwd"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("exec command failed: %v", err)
	}
	if gotWorkDir != "/tmp" {
		t.Fatalf("workdir = %q", gotWorkDir)
	}
	if len(gotCommand) != 1 || gotCommand[0] != "pwd" {
		t.Fatalf("command = %#v", gotCommand)
	}
}

func TestExecCmdUsesCurrentLocalInstanceTarget(t *testing.T) {
	origLoad := loadCLIConfigForTarget
	origLoadLocal := loadLocalInstancesForCLI
	origExecLocalRuntime := execInLocalRuntimeTarget
	defer func() {
		loadCLIConfigForTarget = origLoad
		loadLocalInstancesForCLI = origLoadLocal
		execInLocalRuntimeTarget = origExecLocalRuntime
	}()

	loadCLIConfigForTarget = func() (*cwconfig.Config, error) {
		return &cwconfig.Config{
			CurrentTarget: &cwconfig.CurrentTargetConfig{
				Kind: "local",
				Ref:  "repo",
				Name: "repo",
			},
		}, nil
	}
	loadLocalInstancesForCLI = func() (*cwconfig.LocalInstancesConfig, error) {
		return &cwconfig.LocalInstancesConfig{
			Instances: map[string]cwconfig.LocalInstance{
				"repo": {
					Name:        "repo",
					Backend:     "docker",
					RuntimeName: "cw-repo",
				},
			},
		}, nil
	}

	var gotInstance *cwconfig.LocalInstance
	var gotWorkDir string
	var gotCommand []string
	execInLocalRuntimeTarget = func(instance *cwconfig.LocalInstance, workDir string, command []string, allocTTY ...bool) error {
		gotInstance = instance
		gotWorkDir = workDir
		gotCommand = append([]string(nil), command...)
		return nil
	}

	cmd := execCmd()
	cmd.SetArgs([]string{"--", "pwd"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("exec command failed: %v", err)
	}
	if gotInstance == nil || gotInstance.Name != "repo" {
		t.Fatalf("instance = %#v", gotInstance)
	}
	if gotWorkDir != "/workspace" {
		t.Fatalf("workdir = %q, want /workspace", gotWorkDir)
	}
	if len(gotCommand) != 1 || gotCommand[0] != "pwd" {
		t.Fatalf("command = %#v", gotCommand)
	}
}

func TestLocalRuntimeTerminalEnvNormalizesUnsupportedHostTerminals(t *testing.T) {
	t.Setenv("TERM", "xterm-kitty")
	t.Setenv("COLORTERM", "truecolor")
	t.Setenv("TERM_PROGRAM", "WarpTerminal")
	env := localRuntimeTerminalEnv()
	joined := strings.Join(env, "\n")
	for _, want := range []string{"TERM=xterm-256color", "COLORTERM=truecolor", "TERM_PROGRAM=WarpTerminal"} {
		if !strings.Contains(joined, want) {
			t.Fatalf("localRuntimeTerminalEnv() missing %q in %#v", want, env)
		}
	}
	if strings.Contains(joined, "TERM=xterm-kitty") {
		t.Fatalf("localRuntimeTerminalEnv() leaked unsupported TERM in %#v", env)
	}
}

func TestLocalRuntimeTerminalEnvFallsBackToSafeDefaults(t *testing.T) {
	t.Setenv("TERM", "")
	t.Setenv("COLORTERM", "")
	env := localRuntimeTerminalEnv()
	joined := strings.Join(env, "\n")
	for _, want := range []string{"TERM=xterm-256color", "COLORTERM=truecolor"} {
		if !strings.Contains(joined, want) {
			t.Fatalf("localRuntimeTerminalEnv() missing %q in %#v", want, env)
		}
	}
}

func TestShellCmdAllowsCurrentTargetWhenNoArg(t *testing.T) {
	cmd := shellCmd()
	if err := cmd.Args(cmd, nil); err != nil {
		t.Fatalf("ssh args rejected zero args: %v", err)
	}
}

func TestExecCmdDoesNotExposeOnFlag(t *testing.T) {
	cmd := execCmd()
	if cmd.Flags().Lookup("on") != nil {
		t.Fatal("expected exec command not to expose legacy target override flag")
	}
}
