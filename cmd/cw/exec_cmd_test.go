package main

import (
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
	if gotTimeout != 30 {
		t.Fatalf("timeout = %d, want 30", gotTimeout)
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

func TestSSHCmdAllowsCurrentTargetWhenNoArg(t *testing.T) {
	cmd := sshCmd()
	if err := cmd.Args(cmd, nil); err != nil {
		t.Fatalf("ssh args rejected zero args: %v", err)
	}
}

func TestExecCmdExposesOnFlag(t *testing.T) {
	cmd := execCmd()
	if cmd.Flags().Lookup("on") == nil {
		t.Fatal("expected exec command to expose --on")
	}
}
