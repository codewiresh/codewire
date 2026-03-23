package main

import (
	"fmt"
	"os"
	"os/exec"
	"testing"
	"time"

	cwconfig "github.com/codewiresh/codewire/internal/config"
)

func TestLocalIncusLifecycleIntegration(t *testing.T) {
	if os.Getenv("CODEWIRE_TEST_INCUS") != "1" {
		t.Skip("set CODEWIRE_TEST_INCUS=1 to run real Incus integration tests")
	}
	if _, err := exec.LookPath("incus"); err != nil {
		t.Skip("incus not installed")
	}
	if _, err := exec.LookPath("skopeo"); err != nil {
		t.Skip("skopeo not installed")
	}

	image := os.Getenv("CODEWIRE_TEST_INCUS_IMAGE")
	if image == "" {
		image = "docker.io/library/nginx:stable-alpine"
	}

	tmpDir := t.TempDir()
	instance := &cwconfig.LocalInstance{
		Name:        fmt.Sprintf("itest-%d", time.Now().UnixNano()),
		Backend:     "incus",
		RuntimeName: fmt.Sprintf("cw-itest-%d", time.Now().UnixNano()),
		RepoPath:    tmpDir,
		Image:       image,
	}
	t.Cleanup(func() {
		_ = deleteLocalRuntime(instance)
	})

	if err := createLocalIncusInstance(instance); err != nil {
		t.Fatalf("createLocalIncusInstance() error = %v", err)
	}

	status, err := incusInstanceStatus(instance.RuntimeName)
	if err != nil {
		t.Fatalf("incusInstanceStatus() error = %v", err)
	}
	if status == "missing" {
		t.Fatal("instance should exist after create")
	}

	if err := stopLocalRuntime(instance); err != nil {
		t.Fatalf("stopLocalRuntime() error = %v", err)
	}

	if err := startLocalRuntime(instance); err != nil {
		t.Fatalf("startLocalRuntime() error = %v", err)
	}

	if err := deleteLocalRuntime(instance); err != nil {
		t.Fatalf("deleteLocalRuntime() error = %v", err)
	}

	status, err = incusInstanceStatus(instance.RuntimeName)
	if err != nil {
		t.Fatalf("incusInstanceStatus() after delete error = %v", err)
	}
	if status != "missing" {
		t.Fatalf("status after delete = %q, want %q", status, "missing")
	}
}
