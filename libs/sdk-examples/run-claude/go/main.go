// Runnable proof that the Go SDK can drive a local VM end-to-end:
//   1. Create a Docker-backed local environment.
//   2. Exec `claude -p <prompt>` inside.
//   3. Print the model's response.
//   4. Tear down.
//
// Run with:
//
//	go run ./examples/run-claude/go
//
// Requires: docker running, CW_BIN pointing at a built cw binary (or cw on
// PATH), and a valid CLAUDE_CODE_OAUTH_TOKEN in ~/.claude/.credentials.json
// (which the CLI forwards automatically into the container).
package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"time"

	codewire "codewire.sh/sdk-go"
)

// Image override: set CW_EXAMPLE_IMAGE to use a preset with `claude` in PATH
// (e.g. `ghcr.io/codewiresh/workspace@sha256:03571275319488cd317d7f405fc22057214906fba0c6727160090286a17f7467`). The default image is alpine so the
// example boots without extra dependencies — swap it once you have a
// claude-ready base image.
const (
	defaultImage = "docker.io/library/alpine:3.20"
	defaultCmd   = "echo hello from codewire"
)

func main() {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	image := envOr("CW_EXAMPLE_IMAGE", defaultImage)
	cmdline := envOr("CW_EXAMPLE_CMD", defaultCmd)

	cw := codewire.New("")

	workdir, err := os.MkdirTemp("", "cw-example-go-")
	if err != nil {
		log.Fatalf("mktemp: %v", err)
	}
	defer os.RemoveAll(workdir)

	fmt.Println("==> Creating docker local instance…")
	inst, err := cw.Local.Create(ctx,
		codewire.LocalSpec{Image: image},
		codewire.LocalCreateOptions{
			Backend: "docker",
			Path:    workdir,
			Wait:    true,
		},
	)
	if err != nil {
		log.Fatalf("create: %v", err)
	}
	defer func() {
		fmt.Println("==> Removing instance…")
		if err := inst.Remove(context.Background()); err != nil {
			log.Printf("remove: %v", err)
		}
	}()

	fmt.Printf("    created %s (backend=%s status=%s)\n",
		inst.Name, inst.Backend, inst.Status)

	fmt.Printf("==> Running: %s\n", cmdline)
	res, err := inst.Exec(ctx, codewire.LocalExecRequest{
		Command: []string{"sh", "-c", cmdline},
	})
	if err != nil {
		log.Fatalf("exec: %v", err)
	}

	fmt.Printf("\n--- exit %d ---\n%s--- end ---\n", res.ExitCode, res.Stdout)
	if res.ExitCode != 0 {
		fmt.Fprintf(os.Stderr, "stderr:\n%s\n", res.Stderr)
		os.Exit(res.ExitCode)
	}
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
