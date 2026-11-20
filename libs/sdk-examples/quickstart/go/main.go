// Creates an environment, runs a command in it, writes and reads back a
// file, and deletes it. Reads CODEWIRE_API_KEY, CODEWIRE_ORG_ID and, for a
// server other than the hosted one, CODEWIRE_API_URL.
//
//	go run .
package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	codewire "codewire.sh/sdk-go"
)

func main() {
	if err := quickstart(context.Background()); err != nil {
		fmt.Fprintln(os.Stderr, "quickstart failed:", err)
		os.Exit(1)
	}
}

func quickstart(ctx context.Context) error {
	client := codewire.New("")
	name := "go-sdk-quickstart"
	env, err := client.Environments.Create(ctx, codewire.CreateEnvironmentBody{
		Name: &name,
		ProjectSpec: codewire.ProjectSpec{
			SchemaVersion:    1,
			Image:            "python:3.12-slim",
			WorkingDirectory: "/workspace",
		},
	}, codewire.CreateOptions{Wait: true})
	if err != nil {
		return fmt.Errorf("create: %w", err)
	}
	fmt.Println("created", env.Id)
	fmt.Println("ready")

	// Delete the environment whether or not the steps succeeded.
	steps := useEnvironment(ctx, env)
	deleted := env.Remove(ctx)
	if deleted == nil {
		fmt.Println("deleted", env.Id)
	} else {
		deleted = fmt.Errorf("delete: %w", deleted)
	}
	return errors.Join(steps, deleted)
}

func useEnvironment(ctx context.Context, env *codewire.Environment) error {
	output, err := env.Exec(ctx, codewire.ExecBody{
		Command: &[]string{"python3", "--version"},
	})
	if err != nil {
		return fmt.Errorf("exec: %w", err)
	}
	fmt.Print(output.Stdout)
	if output.ExitCode != 0 {
		return fmt.Errorf("python3 exited %d", output.ExitCode)
	}

	if err := env.Files.Upload(ctx, strings.NewReader("hello from Go"), "/workspace/hello.txt"); err != nil {
		return fmt.Errorf("upload: %w", err)
	}
	workspace := "/workspace"
	files, err := env.Files.List(ctx, &workspace)
	if err != nil {
		return fmt.Errorf("list: %w", err)
	}
	found := false
	for _, file := range files {
		found = found || file.Name == "hello.txt"
	}
	if !found {
		return errors.New("hello.txt is missing from /workspace")
	}
	body, err := env.Files.Download(ctx, "/workspace/hello.txt")
	if err != nil {
		return fmt.Errorf("download: %w", err)
	}
	defer body.Close()
	contents, err := io.ReadAll(body)
	if err != nil {
		return fmt.Errorf("download: %w", err)
	}
	if string(contents) != "hello from Go" {
		return errors.New("hello.txt came back different")
	}
	fmt.Println("wrote and read back /workspace/hello.txt")
	return nil
}
