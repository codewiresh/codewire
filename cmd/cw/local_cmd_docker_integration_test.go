package main

import (
	"fmt"
	"os"
	"os/exec"
	"testing"
	"time"

	cwconfig "github.com/codewiresh/codewire/internal/config"
)

func TestLocalDockerLifecycleIntegration(t *testing.T) {
	if os.Getenv("CODEWIRE_TEST_DOCKER") != "1" {
		t.Skip("set CODEWIRE_TEST_DOCKER=1 to run real Docker integration tests")
	}
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("docker not installed")
	}

	image := os.Getenv("CODEWIRE_TEST_DOCKER_IMAGE")
	if image == "" {
		image = "docker.io/library/alpine:3.20"
	}

	suffix := time.Now().UnixNano()
	tmpDir := t.TempDir()
	instance := &cwconfig.LocalInstance{
		Name:        fmt.Sprintf("itest-%d", suffix),
		Backend:     "docker",
		RuntimeName: fmt.Sprintf("cw-itest-%d", suffix),
		RepoPath:    tmpDir,
		Image:       image,
	}
	t.Cleanup(func() {
		_ = deleteLocalRuntime(instance)
	})

	if err := createLocalDockerInstance(instance); err != nil {
		t.Fatalf("createLocalDockerInstance() error = %v", err)
	}

	status, err := dockerContainerStatus(instance.RuntimeName)
	if err != nil {
		t.Fatalf("dockerContainerStatus() error = %v", err)
	}
	if status != "running" {
		t.Fatalf("status after create = %q, want %q", status, "running")
	}

	if err := stopLocalRuntime(instance); err != nil {
		t.Fatalf("stopLocalRuntime() error = %v", err)
	}

	status, err = dockerContainerStatus(instance.RuntimeName)
	if err != nil {
		t.Fatalf("dockerContainerStatus() after stop error = %v", err)
	}
	if status != "exited" {
		t.Fatalf("status after stop = %q, want %q", status, "exited")
	}

	if err := startLocalRuntime(instance); err != nil {
		t.Fatalf("startLocalRuntime() error = %v", err)
	}

	status, err = dockerContainerStatus(instance.RuntimeName)
	if err != nil {
		t.Fatalf("dockerContainerStatus() after start error = %v", err)
	}
	if status != "running" {
		t.Fatalf("status after start = %q, want %q", status, "running")
	}

	if err := deleteLocalRuntime(instance); err != nil {
		t.Fatalf("deleteLocalRuntime() error = %v", err)
	}

	status, err = dockerContainerStatus(instance.RuntimeName)
	if err != nil {
		t.Fatalf("dockerContainerStatus() after delete error = %v", err)
	}
	if status != "missing" {
		t.Fatalf("status after delete = %q, want %q", status, "missing")
	}
}
