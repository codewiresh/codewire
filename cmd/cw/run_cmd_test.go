package main

import (
	"os"
	"strings"
	"testing"

	"github.com/codewiresh/codewire/internal/client"
	cwconfig "github.com/codewiresh/codewire/internal/config"
	"github.com/codewiresh/codewire/internal/platform"
)

func TestBuildEnvironmentRunCommandIncludesFlags(t *testing.T) {
	got := buildEnvironmentRunCommand(
		"/workspace/app",
		"planner",
		"mesh",
		[]string{"FOO=bar", "A=B"},
		[]string{"alpha", "beta"},
		[]string{"claude", "--version"},
	)

	want := []string{
		"cw", "exec",
		"--dir", "/workspace/app",
		"--name", "planner",
		"--group", "mesh",
		"--env", "FOO=bar",
		"--env", "A=B",
		"--tag", "alpha",
		"--tag", "beta",
		"--",
		"claude", "--version",
	}

	if strings.Join(got, "\x00") != strings.Join(want, "\x00") {
		t.Fatalf("command = %#v, want %#v", got, want)
	}
}

func TestRunCmdUsesCurrentEnvironmentTarget(t *testing.T) {
	origLoad := loadCLIConfigForTarget
	origRunEnv := runInEnvironmentTarget
	origServerFlag := serverFlag
	defer func() {
		loadCLIConfigForTarget = origLoad
		runInEnvironmentTarget = origRunEnv
		serverFlag = origServerFlag
	}()

	serverFlag = ""
	loadCLIConfigForTarget = func() (*cwconfig.Config, error) {
		return &cwconfig.Config{
			CurrentTarget: &cwconfig.CurrentTargetConfig{
				Kind: "env",
				Ref:  "f062947a-60e2-405c-b89d-5f48b493d8fb",
				Name: "env-fb08",
			},
		}, nil
	}

	var gotEnvID, gotWorkDir, gotName, gotGroup string
	var gotEnvVars, gotTags, gotCommand []string
	runInEnvironmentTarget = func(envID, workDir, name, group string, envVars []string, tags []string, command []string) (*platform.ExecResult, error) {
		gotEnvID = envID
		gotWorkDir = workDir
		gotName = name
		gotGroup = group
		gotEnvVars = append([]string(nil), envVars...)
		gotTags = append([]string(nil), tags...)
		gotCommand = append([]string(nil), command...)
		return &platform.ExecResult{}, nil
	}

	cmd := execCmd()
	cmd.SetArgs([]string{"--name", "planner", "--group", "mesh", "--tag", "alpha", "--env", "FOO=bar", "--", "claude", "--version"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("run command failed: %v", err)
	}

	if gotEnvID != "f062947a-60e2-405c-b89d-5f48b493d8fb" {
		t.Fatalf("envID = %q", gotEnvID)
	}
	if gotWorkDir != "/workspace" {
		t.Fatalf("workdir = %q, want /workspace", gotWorkDir)
	}
	if gotName != "planner" {
		t.Fatalf("name = %q, want planner", gotName)
	}
	if gotGroup != "mesh" {
		t.Fatalf("group = %q, want mesh", gotGroup)
	}
	if len(gotEnvVars) != 1 || gotEnvVars[0] != "FOO=bar" {
		t.Fatalf("env vars = %#v", gotEnvVars)
	}
	if len(gotTags) != 2 || gotTags[0] != "alpha" || gotTags[1] != "group:mesh" {
		t.Fatalf("tags = %#v", gotTags)
	}
	if strings.Join(gotCommand, "\x00") != strings.Join([]string{"claude", "--version"}, "\x00") {
		t.Fatalf("command = %#v", gotCommand)
	}
}

func TestRunCmdRequiresNameForGroup(t *testing.T) {
	cmd := execCmd()
	cmd.SetArgs([]string{"--group", "mesh", "--", "claude"})
	err := cmd.Execute()
	if err == nil {
		t.Fatal("expected grouped run without name to fail")
	}
	if !strings.Contains(err.Error(), "--group requires --name") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestAppendGroupTagDeduplicates(t *testing.T) {
	got := appendGroupTag([]string{"alpha", "group:mesh"}, "mesh")
	if strings.Join(got, "\x00") != strings.Join([]string{"alpha", "group:mesh"}, "\x00") {
		t.Fatalf("tags = %#v", got)
	}
}

func TestRunCmdRejectsPromptFileForEnvironmentTarget(t *testing.T) {
	origLoad := loadCLIConfigForTarget
	origServerFlag := serverFlag
	defer func() {
		loadCLIConfigForTarget = origLoad
		serverFlag = origServerFlag
	}()

	serverFlag = ""
	loadCLIConfigForTarget = func() (*cwconfig.Config, error) {
		return &cwconfig.Config{
			CurrentTarget: &cwconfig.CurrentTargetConfig{
				Kind: "env",
				Ref:  "f062947a-60e2-405c-b89d-5f48b493d8fb",
				Name: "env-fb08",
			},
		}, nil
	}

	promptFile := t.TempDir() + "/prompt.txt"
	if err := os.WriteFile(promptFile, []byte("hello"), 0o644); err != nil {
		t.Fatalf("write prompt file: %v", err)
	}

	cmd := execCmd()
	cmd.SetArgs([]string{"--prompt-file", promptFile, "--", "claude", "--version"})
	err := cmd.Execute()
	if err == nil {
		t.Fatal("expected prompt-file to be rejected for env targets")
	}
	if !strings.Contains(err.Error(), "--prompt-file is not supported for environment targets yet") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestWrapLocalRuntimeRunCommand(t *testing.T) {
	origExe := currentExecutablePath
	defer func() { currentExecutablePath = origExe }()

	currentExecutablePath = func() (string, error) {
		return "/usr/local/bin/cw", nil
	}

	command, hostWorkDir, err := wrapLocalRuntimeRunCommand(&cwconfig.LocalInstance{
		Name:     "repo",
		RepoPath: "/tmp/repo",
		Workdir:  "/workspace",
	}, "", []string{"claude", "--version"})
	if err != nil {
		t.Fatalf("wrapLocalRuntimeRunCommand() error = %v", err)
	}
	if hostWorkDir != "/tmp/repo" {
		t.Fatalf("hostWorkDir = %q, want /tmp/repo", hostWorkDir)
	}
	want := []string{"/usr/local/bin/cw", "exec", "-it", "--workdir", "/workspace", "repo", "--", "claude", "--version"}
	if strings.Join(command, "\x00") != strings.Join(want, "\x00") {
		t.Fatalf("command = %#v, want %#v", command, want)
	}
}

func TestRunCmdUsesNamedLocalRuntimeTarget(t *testing.T) {
	origLoad := loadCLIConfigForTarget
	origRun := runOnTarget
	origServerFlag := serverFlag
	origEnsureNode := ensureNodeForRun
	origResolveTarget := resolveTargetForRun
	origExe := currentExecutablePath
	defer func() {
		loadCLIConfigForTarget = origLoad
		runOnTarget = origRun
		serverFlag = origServerFlag
		ensureNodeForRun = origEnsureNode
		resolveTargetForRun = origResolveTarget
		currentExecutablePath = origExe
	}()

	serverFlag = ""
	loadCLIConfigForTarget = func() (*cwconfig.Config, error) {
		return &cwconfig.Config{
			CurrentTarget: &cwconfig.CurrentTargetConfig{
				Kind: "local",
				Ref:  "repo",
				Name: "repo",
			},
		}, nil
	}
	ensureNodeForRun = func() error { return nil }
	resolveTargetForRun = func() (*client.Target, error) {
		return &client.Target{Local: "/tmp/data"}, nil
	}
	currentExecutablePath = func() (string, error) {
		return "/usr/local/bin/cw", nil
	}

	var gotTarget *client.Target
	var gotCommand []string
	var gotWorkDir string
	runOnTarget = func(target *client.Target, command []string, workingDir string, name string, env []string, stdinData []byte, tags ...string) error {
		gotTarget = target
		gotCommand = append([]string(nil), command...)
		gotWorkDir = workingDir
		return nil
	}
	origLoadLocal := loadLocalInstancesForCLI
	defer func() {
		loadLocalInstancesForCLI = origLoadLocal
	}()
	loadLocalInstancesForCLI = func() (*cwconfig.LocalInstancesConfig, error) {
		return &cwconfig.LocalInstancesConfig{
			Instances: map[string]cwconfig.LocalInstance{
				"repo": {
					Name:     "repo",
					Backend:  "lima",
					RepoPath: "/tmp/repo",
					Workdir:  "/workspace",
				},
			},
		}, nil
	}

	cmd := execCmd()
	cmd.SetArgs([]string{"--name", "planner", "--", "claude"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("run command failed: %v", err)
	}
	if gotTarget == nil || gotTarget.Local != "/tmp/data" {
		t.Fatalf("target = %#v", gotTarget)
	}
	wantCommand := []string{"/usr/local/bin/cw", "exec", "-it", "--workdir", "/workspace", "repo", "--", "claude"}
	if strings.Join(gotCommand, "\x00") != strings.Join(wantCommand, "\x00") {
		t.Fatalf("command = %#v, want %#v", gotCommand, wantCommand)
	}
	if gotWorkDir != "/tmp/repo" {
		t.Fatalf("workDir = %q, want /tmp/repo", gotWorkDir)
	}
}

func TestPrintEnvironmentRunResultExplainsMissingCodewireCLI(t *testing.T) {
	err := printEnvironmentRunResult(&platform.ExecResult{
		ExitCode: 127,
		Stderr:   "sh: 1: exec: cw: not found",
	})
	if err == nil {
		t.Fatal("expected missing cw error")
	}
	if !strings.Contains(err.Error(), "environment image does not include the codewire CLI") || !strings.Contains(err.Error(), "session support") {
		t.Fatalf("unexpected error: %v", err)
	}
}
