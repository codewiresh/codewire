//go:build e2e

package codewire_test

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io"
	"strings"
	"testing"
	"time"

	codewire "codewire.sh/sdk-go"
)

func ptr[T any](v T) *T { return &v }

// removeAndWait deletes env and waits until it is destroyed: delete returns
// before then, and a preset an environment still uses cannot be deleted.
func removeAndWait(t *testing.T, ctx context.Context, client *codewire.Client, env *codewire.Environment) {
	t.Helper()
	if err := env.Remove(ctx); err != nil {
		t.Errorf("remove %s: %v", env.Id, err)
		return
	}
	for deadline := time.Now().Add(5 * time.Minute); time.Now().Before(deadline); time.Sleep(2 * time.Second) {
		current, err := client.Environments.Get(ctx, env.Id)
		var apiErr *codewire.Error
		if errors.As(err, &apiErr) && apiErr.StatusCode == 404 {
			return
		}
		if err != nil {
			t.Errorf("get %s: %v", env.Id, err)
			return
		}
		if current.State == "destroyed" {
			return
		}
	}
	t.Errorf("environment %s was not destroyed within 5 minutes", env.Id)
}

// Presets belong to an organization, so the test makes its own and deletes it
// after: the account it runs as has none to begin with.
func TestE2E_PresetEnv(t *testing.T) {
	client := codewire.New("")
	ctx := context.Background()

	suffix := make([]byte, 4)
	if _, err := rand.Read(suffix); err != nil {
		t.Fatalf("slug: %v", err)
	}
	slug := "sdk-e2e-" + hex.EncodeToString(suffix)
	preset, err := client.Presets.Create(ctx, codewire.CreatePresetBody{
		Name:        slug,
		Slug:        &slug,
		ProjectSpec: codewire.ProjectSpec{SchemaVersion: 1, Image: "python:3.12-slim", WorkingDirectory: "/workspace"},
	})
	if err != nil {
		t.Fatalf("create preset: %v", err)
	}
	t.Cleanup(func() {
		if err := client.Presets.Delete(ctx, preset.Id); err != nil {
			t.Errorf("delete preset %s: %v", preset.Id, err)
		}
	})

	env, err := client.Environments.Create(ctx, codewire.CreateEnvironmentBody{
		ProjectSpec: codewire.ProjectSpec{SchemaVersion: 1, Preset: slug, WorkingDirectory: "/workspace"},
	}, codewire.CreateOptions{Wait: true})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	// Runs before the preset's delete: cleanups run last first.
	t.Cleanup(func() { removeAndWait(t, ctx, client, env) })

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
