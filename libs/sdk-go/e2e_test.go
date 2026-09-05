//go:build e2e

package codewire_test

import (
	"context"
	"io"
	"strings"
	"testing"

	codewire "codewire.sh/sdk-go"
)

func ptr[T any](v T) *T { return &v }

func TestE2E_FirstPartyEnv(t *testing.T) {
	client := codewire.New("")
	ctx := context.Background()

	env, err := client.Environments.Create(ctx, codewire.CreateEnvironmentBody{
		ProjectSpec: codewire.ProjectSpec{SchemaVersion: 1, Preset: "python", WorkingDirectory: "/workspace"},
	}, codewire.CreateOptions{Wait: true})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	defer env.Remove(ctx)

	result, err := env.Exec(ctx, codewire.ExecBody{
		Command: &[]string{"python3", "--version"},
	})
	if err != nil {
		t.Fatalf("exec: %v", err)
	}
	if result.ExitCode != 0 {
		t.Fatalf("exit_code=%d stderr=%s", result.ExitCode, result.Stderr)
	}
	if !strings.Contains(result.Stdout, "Python") {
		t.Fatalf("stdout=%q, want Python", result.Stdout)
	}

	if err := env.Files.Upload(ctx, strings.NewReader("hello"), "/workspace/test.txt"); err != nil {
		t.Fatalf("upload: %v", err)
	}
	files, err := env.Files.List(ctx, ptr("/workspace"))
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	found := false
	for _, f := range files {
		if f.Name == "test.txt" {
			found = true
		}
	}
	if !found {
		t.Fatal("test.txt not found")
	}
	body, err := env.Files.Download(ctx, "/workspace/test.txt")
	if err != nil {
		t.Fatalf("download: %v", err)
	}
	defer body.Close()
	data, _ := io.ReadAll(body)
	if string(data) != "hello" {
		t.Fatalf("content=%q, want hello", data)
	}
}

func TestE2E_ArbitraryImage(t *testing.T) {
	client := codewire.New("")
	ctx := context.Background()

	env, err := client.Environments.Create(ctx, codewire.CreateEnvironmentBody{
		ProjectSpec: codewire.ProjectSpec{SchemaVersion: 1, Image: "python:3.12-slim", WorkingDirectory: "/workspace"},
	}, codewire.CreateOptions{Wait: true})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	defer env.Remove(ctx)

	result, err := env.Exec(ctx, codewire.ExecBody{
		Command: &[]string{"python3", "-c", "print(1+1)"},
	})
	if err != nil {
		t.Fatalf("exec: %v", err)
	}
	if result.ExitCode != 0 {
		t.Fatalf("exit_code=%d stderr=%s", result.ExitCode, result.Stderr)
	}
	if strings.TrimSpace(result.Stdout) != "2" {
		t.Fatalf("stdout=%q, want 2", result.Stdout)
	}
}
