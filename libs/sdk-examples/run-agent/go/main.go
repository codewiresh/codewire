// Runs a coding agent in an environment on a small project, without a
// terminal, and prints the change it made. Reads CODEWIRE_API_KEY,
// CODEWIRE_ORG_ID and, for a server other than the hosted one,
// CODEWIRE_API_URL.
//
//	go run .
//
// RUN_AGENT_COMMAND replaces the agent command, which by default is Claude
// Code without a terminal. Claude Code needs a Claude credential in the
// environment; a program signed in with an API key can't bind a profile
// yet (#5687).
package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"

	codewire "codewire.sh/sdk-go"
)

const (
	project = "/workspace/project"
	task    = "The test in test_greeting.py fails. Fix greeting.py so that it passes, without changing the test."
)

var files = map[string]string{
	"greeting.py": "def greet(name):\n    return \"Hello \" + name\n",
	"test_greeting.py": "import unittest\n\nfrom greeting import greet\n\n\n" +
		"class GreetingTest(unittest.TestCase):\n" +
		"    def test_greets_by_name(self):\n" +
		"        self.assertEqual(greet(\"Codewire\"), \"Hello, Codewire!\")\n\n\n" +
		"if __name__ == \"__main__\":\n    unittest.main()\n",
}

func main() {
	if err := runAgent(context.Background()); err != nil {
		fmt.Fprintln(os.Stderr, "run-agent failed:", err)
		os.Exit(1)
	}
}

func runAgent(ctx context.Context) error {
	client := codewire.New("")
	name := "go-sdk-run-agent"
	spec := codewire.ProjectSpec{SchemaVersion: 1, Image: "workspace", WorkingDirectory: "/workspace"}
	env, err := client.Environments.Create(ctx, codewire.CreateEnvironmentBody{Name: &name, ProjectSpec: spec})
	if err != nil {
		return fmt.Errorf("create: %w", err)
	}
	fmt.Println("created", env.Id)

	// From here on, delete the environment whether or not anything fails.
	steps := useEnvironment(ctx, env)
	deleted := env.Remove(ctx)
	if deleted == nil {
		fmt.Println("deleted", env.Id)
	} else {
		deleted = fmt.Errorf("delete: %w", deleted)
	}
	return errors.Join(steps, deleted)
}

func run(ctx context.Context, env *codewire.Environment, command string, timeout int64) (*codewire.ExecResult, error) {
	dir := project
	return env.Exec(ctx, codewire.ExecBody{Command: &[]string{"sh", "-c", command}, WorkingDir: &dir, Timeout: &timeout})
}

// succeeded reports a failed command, or a command that exited non-zero, as
// an error naming what it was for.
func succeeded(what string, result *codewire.ExecResult, err error) error {
	if err != nil {
		return fmt.Errorf("%s: %w", what, err)
	}
	if result.ExitCode != 0 {
		return fmt.Errorf("%s exited %d: %s", what, result.ExitCode, result.Stderr)
	}
	return nil
}

func useEnvironment(ctx context.Context, env *codewire.Environment) error {
	if err := env.WaitReady(ctx); err != nil {
		return fmt.Errorf("wait: %w", err)
	}
	result, err := env.Exec(ctx, codewire.ExecBody{Command: &[]string{"mkdir", "-p", project}})
	if err := succeeded("mkdir", result, err); err != nil {
		return err
	}
	for name, contents := range files {
		if err := env.Files.Upload(ctx, strings.NewReader(contents), project+"/"+name); err != nil {
			return fmt.Errorf("upload %s: %w", name, err)
		}
	}
	result, err = run(ctx, env,
		"git init -q && git add -A && git -c user.name=example -c user.email=example@example.com commit -qm baseline", 300)
	if err := succeeded("git baseline", result, err); err != nil {
		return err
	}
	result, err = run(ctx, env, "python3 -m unittest -q test_greeting", 300)
	if err != nil {
		return fmt.Errorf("test: %w", err)
	}
	if result.ExitCode == 0 {
		return errors.New("the test should fail before the agent runs")
	}
	fmt.Println("uploaded the project; its test fails")

	agent := strings.TrimSpace(os.Getenv("RUN_AGENT_COMMAND"))
	if agent == "" {
		agent = "claude -p " + strconv.Quote(task) + " --permission-mode acceptEdits"
	}
	result, err = run(ctx, env, agent, 900)
	if err := succeeded("the agent", result, err); err != nil {
		return err
	}
	fmt.Println("the agent finished")

	result, err = run(ctx, env, "git diff", 300)
	if err := succeeded("git diff", result, err); err != nil {
		return err
	}
	fmt.Print(result.Stdout)
	result, err = run(ctx, env, "python3 -m unittest -q test_greeting", 300)
	if err := succeeded("the test", result, err); err != nil {
		return err
	}
	fmt.Println("the test passes")
	return nil
}
