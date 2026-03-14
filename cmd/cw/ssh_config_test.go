package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestReplaceManagedSSHSectionAppend(t *testing.T) {
	got, err := replaceManagedSSHSection("", sshConfigBlock(sshConfigOptions{}))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(got, "ProxyCommand cw ssh --stdio %n") {
		t.Fatalf("expected ProxyCommand in config, got %q", got)
	}
	if !strings.Contains(got, "StrictHostKeyChecking accept-new") {
		t.Fatalf("expected managed host key policy, got %q", got)
	}
	if !strings.Contains(got, "UserKnownHostsFile ") {
		t.Fatalf("expected managed known_hosts file, got %q", got)
	}
	if !strings.Contains(got, sshConfigMarkerStart) || !strings.Contains(got, sshConfigMarkerEnd) {
		t.Fatalf("expected managed markers, got %q", got)
	}
}

func TestReplaceManagedSSHSectionReplace(t *testing.T) {
	existing := strings.Join([]string{
		"Host github.com",
		"    User git",
		"",
		sshConfigMarkerStart,
		"Host cw-*",
		"    ProxyCommand old",
		sshConfigMarkerEnd,
		"",
		"Host other",
		"    User someone",
		"",
	}, "\n")

	got, err := replaceManagedSSHSection(existing, sshConfigBlock(sshConfigOptions{
		SSHOptions: []string{"ForwardAgent yes"},
	}))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(got, "ProxyCommand old") {
		t.Fatalf("expected old managed block to be replaced, got %q", got)
	}
	if !strings.Contains(got, "ForwardAgent yes") {
		t.Fatalf("expected ssh option in managed block, got %q", got)
	}
	if !strings.Contains(got, "Host github.com") || !strings.Contains(got, "Host other") {
		t.Fatalf("expected surrounding config to be preserved, got %q", got)
	}
}

func TestRenderManagedSSHConfigNoChange(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config")
	content := sshConfigBlock(sshConfigOptions{
		SSHOptions: []string{"ForwardAgent yes"},
	}) + "\n"
	if err := os.WriteFile(configPath, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}

	rendered, changed, err := renderManagedSSHConfig(configPath, sshConfigOptions{
		SSHOptions: []string{"ForwardAgent yes"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if changed {
		t.Fatal("expected no change")
	}
	if string(rendered) != content {
		t.Fatalf("rendered = %q, want %q", string(rendered), content)
	}
}
