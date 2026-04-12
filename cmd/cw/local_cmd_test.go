package main

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	cwconfig "github.com/codewiresh/codewire/internal/config"
)

func TestSanitizeLocalName(t *testing.T) {
	if got := sanitizeLocalName("My Repo_name"); got != "my-repo-name" {
		t.Fatalf("sanitizeLocalName() = %q, want %q", got, "my-repo-name")
	}
}

func stubLocalCLIDataDir(t *testing.T) string {
	t.Helper()
	orig := localCLIDataDir
	dir := t.TempDir()
	localCLIDataDir = func() string { return dir }
	t.Cleanup(func() { localCLIDataDir = orig })
	return dir
}

func TestIncusOCIImageRef(t *testing.T) {
	remoteName, remoteURL, remoteImage, err := incusOCIImageRef("ghcr.io/codewiresh/full:latest")
	if err != nil {
		t.Fatalf("incusOCIImageRef() error = %v", err)
	}
	if remoteName != "cw-ghcr-io" {
		t.Fatalf("remoteName = %q, want %q", remoteName, "cw-ghcr-io")
	}
	if remoteURL != "https://ghcr.io" {
		t.Fatalf("remoteURL = %q, want %q", remoteURL, "https://ghcr.io")
	}
	if remoteImage != "cw-ghcr-io:codewiresh/full:latest" {
		t.Fatalf("remoteImage = %q, want %q", remoteImage, "cw-ghcr-io:codewiresh/full:latest")
	}
}

func TestResolveLocalInstanceUsesRepoMatch(t *testing.T) {
	origGetwd := localGetwd
	t.Cleanup(func() { localGetwd = origGetwd })
	localGetwd = func() (string, error) {
		return "/tmp/work/repo", nil
	}

	state := &cwconfig.LocalInstancesConfig{
		Instances: map[string]cwconfig.LocalInstance{
			"repo": {
				Name:        "repo",
				RuntimeName: "cw-repo",
				RepoPath:    "/tmp/work/repo",
			},
		},
	}

	key, instance, err := resolveLocalInstance(state, "")
	if err != nil {
		t.Fatalf("resolveLocalInstance() error = %v", err)
	}
	if key != "repo" {
		t.Fatalf("key = %q, want %q", key, "repo")
	}
	if instance.Name != "repo" {
		t.Fatalf("instance.Name = %q, want %q", instance.Name, "repo")
	}
}

func TestPrepareLocalInstanceUsesCodewireYAMLAndOverrides(t *testing.T) {
	tmpDir := t.TempDir()
	cfgPath := filepath.Join(tmpDir, "codewire.yaml")
	err := cwconfig.WriteCodewireConfig(cfgPath, &cwconfig.CodewireConfig{
		Preset:  "full",
		Image:   "ghcr.io/codewiresh/full:latest",
		Install: "pnpm install",
		Startup: "pnpm dev",
		CPU:     1000,
	})
	if err != nil {
		t.Fatalf("WriteCodewireConfig() error = %v", err)
	}

	instance, err := prepareLocalInstance(localCreateOptions{
		Backend: "incus",
		Path:    tmpDir,
		File:    "codewire.yaml",
		Image:   "ghcr.io/codewiresh/base:latest",
		Memory:  4096,
	})
	if err != nil {
		t.Fatalf("prepareLocalInstance() error = %v", err)
	}
	if instance.Image != "ghcr.io/codewiresh/base:latest" {
		t.Fatalf("instance.Image = %q, want override image", instance.Image)
	}
	if instance.Install != "pnpm install" {
		t.Fatalf("instance.Install = %q, want %q", instance.Install, "pnpm install")
	}
	if instance.Memory != 4096 {
		t.Fatalf("instance.Memory = %d, want 4096", instance.Memory)
	}
}

func TestPrepareLocalInstanceUsesRepoPathWorkdirForLima(t *testing.T) {
	tmpDir := t.TempDir()
	cfgPath := filepath.Join(tmpDir, "codewire.yaml")
	if err := cwconfig.WriteCodewireConfig(cfgPath, &cwconfig.CodewireConfig{Image: "ghcr.io/codewiresh/full:latest"}); err != nil {
		t.Fatalf("WriteCodewireConfig() error = %v", err)
	}

	instance, err := prepareLocalInstance(localCreateOptions{Backend: "lima", Path: tmpDir, File: "codewire.yaml"})
	if err != nil {
		t.Fatalf("prepareLocalInstance() error = %v", err)
	}
	if instance.Workdir != tmpDir {
		t.Fatalf("instance.Workdir = %q, want %q", instance.Workdir, tmpDir)
	}
}

func TestCreateLocalIncusInstanceInvokesExpectedCommands(t *testing.T) {
	origLookPath := localLookPath
	origRunCommand := localRunCommand
	origUserHomeDir := localUserHomeDir
	origOsStat := localOsStat
	t.Cleanup(func() {
		localLookPath = origLookPath
		localRunCommand = origRunCommand
		localUserHomeDir = origUserHomeDir
		localOsStat = origOsStat
	})

	localUserHomeDir = func() (string, error) { return "/home/testuser", nil }
	localOsStat = func(name string) (os.FileInfo, error) { return nil, nil }

	localLookPath = func(file string) (string, error) {
		if file != "incus" && file != "skopeo" {
			t.Fatalf("LookPath(%q) unexpected", file)
		}
		return "/usr/bin/" + file, nil
	}

	var calls [][]string
	localRunCommand = func(name string, args ...string) ([]byte, error) {
		call := append([]string{name}, args...)
		calls = append(calls, call)
		return nil, nil
	}

	instance := &cwconfig.LocalInstance{
		Name:        "repo",
		Backend:     "incus",
		RuntimeName: "cw-repo",
		RepoPath:    "/tmp/repo",
		Image:       "ghcr.io/codewiresh/full:latest",
		CPU:         1500,
		Memory:      4096,
		Disk:        20,
	}
	if err := createLocalIncusInstance(instance); err != nil {
		t.Fatalf("createLocalIncusInstance() error = %v", err)
	}

	want := [][]string{
		{"incus", "remote", "add", "cw-ghcr-io", "https://ghcr.io", "--protocol=oci"},
		{"incus", "init", "cw-ghcr-io:codewiresh/full:latest", "cw-repo"},
		{"incus", "config", "set", "cw-repo", "limits.cpu", "2"},
		{"incus", "config", "set", "cw-repo", "limits.memory", "4096MiB"},
		{"incus", "config", "device", "set", "cw-repo", "root", "size", "20GiB"},
		{"incus", "config", "device", "add", "cw-repo", "workspace", "disk", "source=/tmp/repo", "path=/workspace"},
		{"incus", "config", "device", "add", "cw-repo", "claude-config", "disk", "source=/home/testuser/.claude", "path=/home/codewire/.claude"},
		{"incus", "config", "device", "add", "cw-repo", "claude-json", "disk", "source=/home/testuser/.claude.json", "path=/home/codewire/.claude.json"},
		{"incus", "config", "device", "add", "cw-repo", "gh-config", "disk", "source=/home/testuser/.config/gh", "path=/home/codewire/.config/gh", "readonly=true"},
		{"incus", "config", "device", "add", "cw-repo", "ssh-config", "disk", "source=/home/testuser/.ssh", "path=/home/codewire/.ssh", "readonly=true"},
		{"incus", "config", "device", "add", "cw-repo", "codex-config", "disk", "source=/home/testuser/.codex", "path=/home/codewire/.codex"},
		{"incus", "start", "cw-repo"},
	}
	if !reflect.DeepEqual(calls, want) {
		t.Fatalf("incus calls = %#v, want %#v", calls, want)
	}
}

func TestCreateLocalIncusInstanceCleansUpOnFailure(t *testing.T) {
	origLookPath := localLookPath
	origRunCommand := localRunCommand
	origUserHomeDir := localUserHomeDir
	origOsStat := localOsStat
	t.Cleanup(func() {
		localLookPath = origLookPath
		localRunCommand = origRunCommand
		localUserHomeDir = origUserHomeDir
		localOsStat = origOsStat
	})

	localUserHomeDir = func() (string, error) { return "/home/testuser", nil }
	localOsStat = func(name string) (os.FileInfo, error) { return nil, os.ErrNotExist }

	localLookPath = func(file string) (string, error) {
		if file != "incus" && file != "skopeo" {
			t.Fatalf("LookPath(%q) unexpected", file)
		}
		return "/usr/bin/" + file, nil
	}

	var calls [][]string
	localRunCommand = func(name string, args ...string) ([]byte, error) {
		call := append([]string{name}, args...)
		calls = append(calls, call)
		if reflect.DeepEqual(call, []string{"incus", "start", "cw-repo"}) {
			return []byte("start failed"), errors.New("boom")
		}
		return nil, nil
	}

	instance := &cwconfig.LocalInstance{
		Name:        "repo",
		Backend:     "incus",
		RuntimeName: "cw-repo",
		RepoPath:    "/tmp/repo",
		Image:       "ghcr.io/codewiresh/full:latest",
	}
	err := createLocalIncusInstance(instance)
	if err == nil {
		t.Fatal("expected createLocalIncusInstance() to fail")
	}

	if len(calls) == 0 {
		t.Fatal("expected incus calls")
	}
	gotLast := calls[len(calls)-1]
	wantLast := []string{"incus", "delete", "cw-repo", "--force"}
	if !reflect.DeepEqual(gotLast, wantLast) {
		t.Fatalf("last call = %#v, want %#v", gotLast, wantLast)
	}
}

func TestCreateLocalIncusInstanceRequiresSkopeo(t *testing.T) {
	origLookPath := localLookPath
	t.Cleanup(func() { localLookPath = origLookPath })

	localLookPath = func(file string) (string, error) {
		switch file {
		case "incus":
			return "/usr/bin/incus", nil
		case "skopeo":
			return "", errors.New("not found")
		default:
			t.Fatalf("LookPath(%q) unexpected", file)
			return "", nil
		}
	}

	instance := &cwconfig.LocalInstance{
		Name:        "repo",
		Backend:     "incus",
		RuntimeName: "cw-repo",
		RepoPath:    "/tmp/repo",
		Image:       "ghcr.io/codewiresh/full:latest",
	}
	err := createLocalIncusInstance(instance)
	if err == nil {
		t.Fatal("expected createLocalIncusInstance() to fail")
	}
	if got := err.Error(); got != "skopeo is required for the incus backend when using OCI images: not found" {
		t.Fatalf("error = %q, want skopeo prerequisite error", got)
	}
}

func TestEnsureIncusOCIRemoteIgnoresExistingRemote(t *testing.T) {
	origRunCommand := localRunCommand
	t.Cleanup(func() { localRunCommand = origRunCommand })

	localRunCommand = func(name string, args ...string) ([]byte, error) {
		return []byte("Remote already exists"), errors.New("exists")
	}

	if err := ensureIncusOCIRemote("cw-ghcr-io", "https://ghcr.io"); err != nil {
		t.Fatalf("ensureIncusOCIRemote() error = %v", err)
	}
}

func TestIncusInstanceStatusParsesJSON(t *testing.T) {
	origRunCommand := localRunCommand
	t.Cleanup(func() { localRunCommand = origRunCommand })

	localRunCommand = func(name string, args ...string) ([]byte, error) {
		return []byte(`[{"status":"Running"}]`), nil
	}

	got, err := incusInstanceStatus("cw-repo")
	if err != nil {
		t.Fatalf("incusInstanceStatus() error = %v", err)
	}
	if got != "running" {
		t.Fatalf("status = %q, want %q", got, "running")
	}
}

func TestIncusInstanceStatusMissingOnNotFound(t *testing.T) {
	origRunCommand := localRunCommand
	t.Cleanup(func() { localRunCommand = origRunCommand })

	localRunCommand = func(name string, args ...string) ([]byte, error) {
		return []byte("Instance not found"), errors.New("missing")
	}

	got, err := incusInstanceStatus("cw-repo")
	if err != nil {
		t.Fatalf("incusInstanceStatus() error = %v", err)
	}
	if got != "missing" {
		t.Fatalf("status = %q, want %q", got, "missing")
	}
}

func TestFormatDockerCPUs(t *testing.T) {
	if got := formatDockerCPUs(1500); got != "1.500" {
		t.Fatalf("formatDockerCPUs(1500) = %q, want %q", got, "1.500")
	}
	if got := formatDockerCPUs(2000); got != "2" {
		t.Fatalf("formatDockerCPUs(2000) = %q, want %q", got, "2")
	}
}

func TestCreateLocalDockerInstanceInvokesExpectedCommands(t *testing.T) {
	origLookPath := localLookPath
	origRunCommand := localRunCommand
	origUserHomeDir := localUserHomeDir
	origOsStat := localOsStat
	t.Cleanup(func() {
		localLookPath = origLookPath
		localRunCommand = origRunCommand
		localUserHomeDir = origUserHomeDir
		localOsStat = origOsStat
	})

	localLookPath = func(file string) (string, error) {
		if file != "docker" {
			t.Fatalf("LookPath(%q) unexpected", file)
		}
		return "/usr/bin/docker", nil
	}

	// ~/.claude exists
	localUserHomeDir = func() (string, error) { return "/home/testuser", nil }
	localOsStat = func(name string) (os.FileInfo, error) { return nil, nil }

	var calls [][]string
	localRunCommand = func(name string, args ...string) ([]byte, error) {
		call := append([]string{name}, args...)
		calls = append(calls, call)
		return nil, nil
	}

	instance := &cwconfig.LocalInstance{
		Name:        "repo",
		Backend:     "docker",
		RuntimeName: "cw-repo",
		RepoPath:    "/tmp/repo",
		Image:       "ghcr.io/codewiresh/full:latest",
		CPU:         1500,
		Memory:      4096,
		Env: map[string]string{
			"B": "2",
			"A": "1",
		},
	}
	if err := createLocalDockerInstance(instance); err != nil {
		t.Fatalf("createLocalDockerInstance() error = %v", err)
	}

	want := [][]string{
		{"docker", "create", "--name", "cw-repo", "--hostname", "cw-repo", "--workdir", "/workspace", "--volume", "/tmp/repo:/workspace", "--volume", "/home/testuser/.claude:/home/codewire/.claude", "--volume", "/home/testuser/.claude.json:/home/codewire/.claude.json", "--volume", "/home/testuser/.config/gh:/home/codewire/.config/gh:ro", "--volume", "/home/testuser/.ssh:/home/codewire/.ssh:ro", "--volume", "/home/testuser/.codex:/home/codewire/.codex", "--cpus", "1.500", "--memory", "4096m", "--env", "A=1", "--env", "B=2", "ghcr.io/codewiresh/full:latest", "/bin/sh", "-lc", "trap 'exit 0' TERM INT; while true; do sleep 3600; done"},
		{"docker", "start", "cw-repo"},
	}
	if !reflect.DeepEqual(calls, want) {
		t.Fatalf("docker calls = %#v, want %#v", calls, want)
	}
}

func TestCreateLocalDockerInstanceSkipsClaudeMountWhenMissing(t *testing.T) {
	origLookPath := localLookPath
	origRunCommand := localRunCommand
	origUserHomeDir := localUserHomeDir
	origOsStat := localOsStat
	t.Cleanup(func() {
		localLookPath = origLookPath
		localRunCommand = origRunCommand
		localUserHomeDir = origUserHomeDir
		localOsStat = origOsStat
	})

	localLookPath = func(file string) (string, error) {
		return "/usr/bin/docker", nil
	}

	// ~/.claude does not exist
	localUserHomeDir = func() (string, error) { return "/home/testuser", nil }
	localOsStat = func(name string) (os.FileInfo, error) {
		return nil, os.ErrNotExist
	}

	var calls [][]string
	localRunCommand = func(name string, args ...string) ([]byte, error) {
		call := append([]string{name}, args...)
		calls = append(calls, call)
		return nil, nil
	}

	instance := &cwconfig.LocalInstance{
		Name:        "repo",
		Backend:     "docker",
		RuntimeName: "cw-repo",
		RepoPath:    "/tmp/repo",
		Image:       "ghcr.io/codewiresh/full:latest",
	}
	if err := createLocalDockerInstance(instance); err != nil {
		t.Fatalf("createLocalDockerInstance() error = %v", err)
	}

	createArgs := calls[0]
	for i, arg := range createArgs {
		if arg == "--volume" && i+1 < len(createArgs) && strings.Contains(createArgs[i+1], ".claude") {
			t.Fatalf("unexpected .claude volume mount when ~/.claude does not exist: %v", createArgs)
		}
	}
}

func TestCreateLocalDockerInstanceCleansUpOnFailure(t *testing.T) {
	origLookPath := localLookPath
	origRunCommand := localRunCommand
	origUserHomeDir := localUserHomeDir
	origOsStat := localOsStat
	t.Cleanup(func() {
		localLookPath = origLookPath
		localRunCommand = origRunCommand
		localUserHomeDir = origUserHomeDir
		localOsStat = origOsStat
	})

	localLookPath = func(file string) (string, error) {
		return "/usr/bin/docker", nil
	}

	// No ~/.claude for this test
	localUserHomeDir = func() (string, error) { return "/home/testuser", nil }
	localOsStat = func(name string) (os.FileInfo, error) { return nil, os.ErrNotExist }

	var calls [][]string
	localRunCommand = func(name string, args ...string) ([]byte, error) {
		call := append([]string{name}, args...)
		calls = append(calls, call)
		if reflect.DeepEqual(call, []string{"docker", "start", "cw-repo"}) {
			return []byte("start failed"), errors.New("boom")
		}
		return nil, nil
	}

	instance := &cwconfig.LocalInstance{
		Name:        "repo",
		Backend:     "docker",
		RuntimeName: "cw-repo",
		RepoPath:    "/tmp/repo",
		Image:       "ghcr.io/codewiresh/full:latest",
	}
	err := createLocalDockerInstance(instance)
	if err == nil {
		t.Fatal("expected createLocalDockerInstance() to fail")
	}

	gotLast := calls[len(calls)-1]
	wantLast := []string{"docker", "rm", "-f", "cw-repo"}
	if !reflect.DeepEqual(gotLast, wantLast) {
		t.Fatalf("last call = %#v, want %#v", gotLast, wantLast)
	}
}

func TestLimaCreateCommandArgs(t *testing.T) {
	origGOOS := localGOOS
	origUserHomeDir := localUserHomeDir
	origOsStat := localOsStat
	dataDir := stubLocalCLIDataDir(t)
	t.Cleanup(func() {
		localGOOS = origGOOS
		localUserHomeDir = origUserHomeDir
		localOsStat = origOsStat
	})
	localGOOS = "linux"
	localUserHomeDir = func() (string, error) { return "/home/testuser", nil }
	localOsStat = func(name string) (os.FileInfo, error) { return nil, nil }

	instance := &cwconfig.LocalInstance{
		Name:        "repo",
		RuntimeName: "cw-repo",
		RepoPath:    "/tmp/repo",
		CPU:         1500,
		Memory:      4096,
		Disk:        20,
		Ports: []cwconfig.PortConfig{
			{Port: 3000, Label: "web"},
			{HostPort: 18080, GuestPort: 8080, Label: "api"},
		},
		Mounts: []cwconfig.MountConfig{
			{Source: "/tmp/shared", Target: "/mnt/shared", Readonly: boolPtr(true)},
		},
	}

	got := limaCreateCommandArgs(instance)
	wantClaudeDir := filepath.Join(dataDir, "lima", "cw-repo", "claude")
	wantMountSet := `.mounts=[{"location":"/tmp/repo","mountPoint":"/tmp/repo","writable":true},{"location":"` + wantClaudeDir + `","mountPoint":"/home/{{.User}}.guest/.claude","writable":true},{"location":"/home/testuser/.config/gh","mountPoint":"/home/{{.User}}.guest/.config/gh","writable":false},{"location":"/home/testuser/.ssh","mountPoint":"/mnt/host-ssh","writable":false},{"location":"/home/testuser/.codex","mountPoint":"/home/{{.User}}.guest/.codex","writable":true},{"location":"/tmp/shared","mountPoint":"/mnt/shared","writable":false}]`

	want := []string{
		"start",
		"--tty=false",
		"--name", "cw-repo",
		"--vm-type", "qemu",
		"--mount-type", "9p",
		"--mount-none",
		"--set", wantMountSet,
		"--cpus", "2",
		"--memory", "4",
		"--disk", "20",
		"--port-forward", "3000:3000,static=true",
		"--port-forward", "18080:8080,static=true",
		"template:docker",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("lima args = %#v, want %#v", got, want)
	}
}

func TestCreateLocalLimaInstanceInvokesExpectedCommands(t *testing.T) {
	origLookPath := localLookPath
	origRunStream := localRunCommandStream
	origRunCommand := localRunCommand
	origGOOS := localGOOS
	origUserHomeDir := localUserHomeDir
	origOsStat := localOsStat
	stubLocalCLIDataDir(t)
	t.Cleanup(func() {
		localLookPath = origLookPath
		localRunCommandStream = origRunStream
		localRunCommand = origRunCommand
		localGOOS = origGOOS
		localUserHomeDir = origUserHomeDir
		localOsStat = origOsStat
	})

	localGOOS = "linux"
	localUserHomeDir = func() (string, error) { return "/home/testuser", nil }
	localOsStat = func(name string) (os.FileInfo, error) { return nil, nil }
	localLookPath = func(file string) (string, error) {
		if file == "limactl" {
			return "/usr/bin/limactl", nil
		}
		if file == "gh" {
			return "/usr/bin/gh", nil
		}
		return "", errors.New("not found")
	}

	var streamCalls [][]string
	localRunCommandStream = func(name string, args ...string) error {
		streamCalls = append(streamCalls, append([]string{name}, args...))
		return nil
	}
	localRunCommand = func(name string, args ...string) ([]byte, error) {
		if name == "/usr/bin/gh" {
			return []byte("fake-token\n"), nil
		}
		if name == "limactl" && len(args) >= 10 && args[0] == "shell" && args[4] == "sudo" && args[5] == "docker" && args[6] == "inspect" {
			return []byte("Error: No such container"), errors.New("missing")
		}
		if name == "limactl" && len(args) >= 9 && args[0] == "shell" && args[4] == "sudo" && args[5] == "stat" && args[6] == "-c" && args[7] == "%g" {
			return []byte("988\n"), nil
		}
		return nil, nil
	}

	vmUser := os.Getenv("USER")
	instance := &cwconfig.LocalInstance{
		Name:        "repo",
		Backend:     "lima",
		RuntimeName: "cw-repo",
		RepoPath:    "/tmp/repo",
		Image:       "ghcr.io/codewiresh/full:latest",
		CPU:         1500,
		Memory:      4096,
		Disk:        20,
		Ports:       []cwconfig.PortConfig{{Port: 3000, Label: "web"}},
		Mounts:      []cwconfig.MountConfig{{Source: "/tmp/shared", Target: "/mnt/shared", Readonly: boolPtr(true)}},
	}
	if err := createLocalLimaInstance(instance); err != nil {
		t.Fatalf("createLocalLimaInstance() error = %v", err)
	}

	want := [][]string{
		append([]string{"limactl"}, limaCreateCommandArgs(instance)...),
		{"limactl", "shell", "--workdir", "/", "cw-repo", "sudo", "docker", "info"},
		{"limactl", "shell", "--workdir", "/", "cw-repo", "sudo", "docker", "pull", "ghcr.io/codewiresh/full:latest"},
		{"limactl", "shell", "--workdir", "/", "cw-repo", "sudo", "docker", "run", "-d",
			"--name", "cw-workspace",
			"--network", "host",
			"--group-add", "988",
			"-e", "DOCKER_HOST=" + limaDockerHostValue,
			"-v", limaDockerSockPath + ":" + limaDockerSockPath,
			"-v", "/tmp/repo:/tmp/repo",
			"-v", "/home/" + vmUser + ".guest/.claude:/home/codewire/.claude",
			"-v", "/home/" + vmUser + ".guest/.config/gh:/home/codewire/.config/gh:ro",
			"-v", "/mnt/host-ssh:/home/codewire/.ssh:ro",
			"-v", "/home/" + vmUser + ".guest/.codex:/home/codewire/.codex",
			"-v", "/tmp/shared:/mnt/shared:ro",
			"--workdir", "/tmp/repo",
			"ghcr.io/codewiresh/full:latest",
			"sleep", "infinity"},
	}
	if !reflect.DeepEqual(streamCalls, want) {
		t.Fatalf("lima stream calls:\n  got:  %#v\n  want: %#v", streamCalls, want)
	}
	if instance.LimaInstanceName != "cw-repo" {
		t.Fatalf("LimaInstanceName = %q, want %q", instance.LimaInstanceName, "cw-repo")
	}
	if instance.LimaVMType != "qemu" {
		t.Fatalf("LimaVMType = %q, want qemu", instance.LimaVMType)
	}
	if instance.LimaMountType != "9p" {
		t.Fatalf("LimaMountType = %q, want 9p", instance.LimaMountType)
	}
}

func TestResolveLocalMountsNormalizesSourceAndTarget(t *testing.T) {
	projectDir := t.TempDir()
	sharedDir := filepath.Join(t.TempDir(), "shared")
	if err := os.MkdirAll(sharedDir, 0o755); err != nil {
		t.Fatalf("MkdirAll(sharedDir): %v", err)
	}
	assetsDir := filepath.Join(projectDir, "assets")
	if err := os.MkdirAll(assetsDir, 0o755); err != nil {
		t.Fatalf("MkdirAll(assetsDir): %v", err)
	}

	got, err := resolveLocalMounts(projectDir, []cwconfig.MountConfig{
		{Source: assetsDir},
		{Source: sharedDir, Target: "/mnt/shared", Readonly: boolPtr(false)},
	})
	if err != nil {
		t.Fatalf("resolveLocalMounts() error = %v", err)
	}
	want := []cwconfig.MountConfig{
		{Source: assetsDir, Target: assetsDir},
		{Source: sharedDir, Target: "/mnt/shared", Readonly: boolPtr(false)},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("resolveLocalMounts() = %#v, want %#v", got, want)
	}
}

func TestEnsureLimaClaudeStateSeedsPortableEntries(t *testing.T) {
	origUserHomeDir := localUserHomeDir
	stubDir := stubLocalCLIDataDir(t)
	t.Cleanup(func() { localUserHomeDir = origUserHomeDir })

	root := t.TempDir()
	homeDir := filepath.Join(root, "home")
	agenticDir := filepath.Join(root, "agentic")
	if err := os.MkdirAll(filepath.Join(homeDir, ".claude", "commands"), 0o755); err != nil {
		t.Fatalf("MkdirAll(home .claude commands): %v", err)
	}
	if err := os.MkdirAll(filepath.Join(homeDir, ".claude", "skills", "tasks"), 0o755); err != nil {
		t.Fatalf("MkdirAll(home .claude skills): %v", err)
	}
	if err := os.MkdirAll(filepath.Join(agenticDir, ".claude"), 0o755); err != nil {
		t.Fatalf("MkdirAll(agentic .claude): %v", err)
	}
	if err := os.WriteFile(filepath.Join(agenticDir, "MEMORY.md"), []byte("memory"), 0o644); err != nil {
		t.Fatalf("WriteFile(MEMORY.md): %v", err)
	}
	if err := os.WriteFile(filepath.Join(agenticDir, ".claude", "settings.json"), []byte("{\"permissions\":{}}"), 0o644); err != nil {
		t.Fatalf("WriteFile(settings.json): %v", err)
	}
	if err := os.WriteFile(filepath.Join(homeDir, ".claude", "settings.local.json"), []byte("{}"), 0o644); err != nil {
		t.Fatalf("WriteFile(settings.local.json): %v", err)
	}
	if err := os.WriteFile(filepath.Join(homeDir, ".claude", "commands", "test.md"), []byte("command"), 0o644); err != nil {
		t.Fatalf("WriteFile(command): %v", err)
	}
	if err := os.WriteFile(filepath.Join(homeDir, ".claude", "skills", "tasks", "SKILL.md"), []byte("skill"), 0o644); err != nil {
		t.Fatalf("WriteFile(skill): %v", err)
	}
	if err := os.Symlink(filepath.Join(agenticDir, "MEMORY.md"), filepath.Join(homeDir, ".claude", "CLAUDE.md")); err != nil {
		t.Fatalf("Symlink(CLAUDE.md): %v", err)
	}
	if err := os.Symlink(filepath.Join(agenticDir, ".claude", "settings.json"), filepath.Join(homeDir, ".claude", "settings.json")); err != nil {
		t.Fatalf("Symlink(settings.json): %v", err)
	}

	localUserHomeDir = func() (string, error) { return homeDir, nil }
	instance := &cwconfig.LocalInstance{Name: "repo", RuntimeName: "cw-repo"}
	if err := ensureLimaClaudeState(instance); err != nil {
		t.Fatalf("ensureLimaClaudeState() error = %v", err)
	}

	targetDir := filepath.Join(stubDir, "lima", "cw-repo", "claude")
	checks := map[string]string{
		"CLAUDE.md":                                  "memory",
		"settings.json":                              "{\"permissions\":{}}",
		"settings.local.json":                        "{}",
		filepath.Join("commands", "test.md"):         "command",
		filepath.Join("skills", "tasks", "SKILL.md"): "skill",
	}
	for rel, want := range checks {
		data, err := os.ReadFile(filepath.Join(targetDir, rel))
		if err != nil {
			t.Fatalf("ReadFile(%s): %v", rel, err)
		}
		if string(data) != want {
			t.Fatalf("%s = %q, want %q", rel, string(data), want)
		}
	}
	if info, err := os.Lstat(filepath.Join(targetDir, "settings.json")); err != nil {
		t.Fatalf("Lstat(settings.json): %v", err)
	} else if info.Mode()&os.ModeSymlink != 0 {
		t.Fatal("expected settings.json to be copied, not symlinked")
	}
}

func TestLimaAdditionalMountsFollowsExternalCodexSymlinkTargets(t *testing.T) {
	origUserHomeDir := localUserHomeDir
	origOsStat := localOsStat
	t.Cleanup(func() {
		localUserHomeDir = origUserHomeDir
		localOsStat = origOsStat
	})

	root := t.TempDir()
	homeDir := filepath.Join(root, "home")
	externalDir := filepath.Join(root, "external")
	if err := os.MkdirAll(filepath.Join(homeDir, ".codex"), 0o755); err != nil {
		t.Fatalf("MkdirAll(home .codex): %v", err)
	}
	if err := os.MkdirAll(externalDir, 0o755); err != nil {
		t.Fatalf("MkdirAll(external): %v", err)
	}
	if err := os.WriteFile(filepath.Join(externalDir, "config.toml"), []byte("model = \"gpt-5\""), 0o644); err != nil {
		t.Fatalf("WriteFile(config.toml): %v", err)
	}
	if err := os.Symlink(filepath.Join(externalDir, "config.toml"), filepath.Join(homeDir, ".codex", "config.toml")); err != nil {
		t.Fatalf("Symlink(config.toml): %v", err)
	}

	localUserHomeDir = func() (string, error) { return homeDir, nil }
	localOsStat = os.Stat

	got := limaAdditionalMounts(&cwconfig.LocalInstance{})
	want := []cwconfig.MountConfig{{Source: externalDir, Target: externalDir, Readonly: boolPtr(false)}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("limaAdditionalMounts() = %#v, want %#v", got, want)
	}
}

func TestCreateLocalLimaInstanceReusesExistingVMAndContainer(t *testing.T) {
	origLookPath := localLookPath
	origRunStream := localRunCommandStream
	origRunCommand := localRunCommand
	origGOOS := localGOOS
	origUserHomeDir := localUserHomeDir
	origOsStat := localOsStat
	stubLocalCLIDataDir(t)
	t.Cleanup(func() {
		localLookPath = origLookPath
		localRunCommandStream = origRunStream
		localRunCommand = origRunCommand
		localGOOS = origGOOS
		localUserHomeDir = origUserHomeDir
		localOsStat = origOsStat
	})

	localGOOS = "linux"
	localUserHomeDir = func() (string, error) { return "/home/testuser", nil }
	localOsStat = func(name string) (os.FileInfo, error) { return nil, nil }
	localLookPath = func(file string) (string, error) {
		if file == "limactl" {
			return "/usr/bin/limactl", nil
		}
		if file == "gh" {
			return "/usr/bin/gh", nil
		}
		return "", errors.New("not found")
	}

	var streamCalls [][]string
	localRunCommandStream = func(name string, args ...string) error {
		streamCalls = append(streamCalls, append([]string{name}, args...))
		return nil
	}
	localRunCommand = func(name string, args ...string) ([]byte, error) {
		if name == "/usr/bin/gh" {
			return []byte("fake-token\n"), nil
		}
		if name == "limactl" && len(args) >= 3 && args[0] == "list" && args[1] == "--format" && args[2] == "json" {
			return []byte(`[{"name":"cw-repo","status":"Running"}]`), nil
		}
		if name == "limactl" && len(args) >= 10 && args[0] == "shell" && args[4] == "sudo" && args[5] == "docker" && args[6] == "inspect" {
			return []byte("running\n"), nil
		}
		if name == "limactl" && len(args) >= 9 && args[0] == "shell" && args[4] == "sudo" && args[5] == "stat" && args[6] == "-c" && args[7] == "%g" {
			return []byte("988\n"), nil
		}
		return nil, nil
	}

	instance := &cwconfig.LocalInstance{
		Name:        "repo",
		Backend:     "lima",
		RuntimeName: "cw-repo",
		RepoPath:    "/tmp/repo",
		Image:       "ghcr.io/codewiresh/full:latest",
	}
	if err := createLocalLimaInstance(instance); err != nil {
		t.Fatalf("createLocalLimaInstance() error = %v", err)
	}

	want := [][]string{
		{"limactl", "shell", "--workdir", "/", "cw-repo", "sudo", "docker", "info"},
		{"limactl", "shell", "--workdir", "/", "cw-repo", "sudo", "docker", "pull", "ghcr.io/codewiresh/full:latest"},
	}
	if !reflect.DeepEqual(streamCalls, want) {
		t.Fatalf("reused lima stream calls:\n  got:  %#v\n  want: %#v", streamCalls, want)
	}
}

func TestLimaLifecycleCommands(t *testing.T) {
	origLookPath := localLookPath
	origRunCommand := localRunCommand
	origRunStream := localRunCommandStream
	origUserHomeDir := localUserHomeDir
	dataDir := stubLocalCLIDataDir(t)
	homeDir := filepath.Join(t.TempDir(), "home")
	t.Cleanup(func() {
		localLookPath = origLookPath
		localRunCommand = origRunCommand
		localRunCommandStream = origRunStream
		localUserHomeDir = origUserHomeDir
	})

	localUserHomeDir = func() (string, error) { return homeDir, nil }
	localLookPath = func(file string) (string, error) {
		if file != "limactl" {
			t.Fatalf("LookPath(%q) unexpected", file)
		}
		return "/usr/bin/limactl", nil
	}

	var calls [][]string
	localRunCommand = func(name string, args ...string) ([]byte, error) {
		calls = append(calls, append([]string{name}, args...))
		return nil, nil
	}
	localRunCommandStream = func(name string, args ...string) error {
		calls = append(calls, append([]string{name}, args...))
		return nil
	}

	stateDir := filepath.Join(dataDir, "lima", "cw-repo", "claude")
	if err := os.MkdirAll(stateDir, 0o755); err != nil {
		t.Fatalf("MkdirAll(stateDir): %v", err)
	}

	instance := &cwconfig.LocalInstance{Name: "repo", Backend: "lima", LimaInstanceName: "cw-repo"}
	if err := startLocalLimaInstance(instance); err != nil {
		t.Fatalf("startLocalLimaInstance() error = %v", err)
	}
	if err := stopLocalLimaInstance(instance); err != nil {
		t.Fatalf("stopLocalLimaInstance() error = %v", err)
	}
	if err := deleteLocalLimaInstance(instance); err != nil {
		t.Fatalf("deleteLocalLimaInstance() error = %v", err)
	}

	want := [][]string{
		{"limactl", "start", "--tty=false", "cw-repo"},
		{"limactl", "shell", "--workdir", "/", "cw-repo", "sudo", "systemctl", "start", "docker"},
		{"limactl", "shell", "--workdir", "/", "cw-repo", "sudo", "docker", "start", "cw-workspace"},
		{"limactl", "shell", "--workdir", "/", "cw-repo", "sudo", "docker", "stop", "cw-workspace"},
		{"limactl", "stop", "cw-repo"},
		{"limactl", "delete", "--force", "cw-repo"},
	}
	if !reflect.DeepEqual(calls, want) {
		t.Fatalf("lima calls:\n  got:  %#v\n  want: %#v", calls, want)
	}
	if _, err := os.Stat(filepath.Join(dataDir, "lima", "cw-repo")); !os.IsNotExist(err) {
		t.Fatalf("expected Lima state dir to be removed, got err=%v", err)
	}
}

func TestLimaInstanceStatusParsesListOutput(t *testing.T) {
	origLookPath := localLookPath
	origRunCommand := localRunCommand
	t.Cleanup(func() {
		localLookPath = origLookPath
		localRunCommand = origRunCommand
	})

	localLookPath = func(file string) (string, error) {
		if file != "limactl" {
			t.Fatalf("LookPath(%q) unexpected", file)
		}
		return "/usr/bin/limactl", nil
	}
	localRunCommand = func(name string, args ...string) ([]byte, error) {
		return []byte(`[{"name":"cw-repo","status":"Running"}]`), nil
	}

	got, err := limaInstanceStatus(&cwconfig.LocalInstance{LimaInstanceName: "cw-repo"})
	if err != nil {
		t.Fatalf("limaInstanceStatus() error = %v", err)
	}
	if got != "running" {
		t.Fatalf("status = %q, want %q", got, "running")
	}
}

func TestLocalPortSummaryFormatsLimaPorts(t *testing.T) {
	got := localPortSummary(&cwconfig.LocalInstance{
		Backend: "lima",
		Ports: []cwconfig.PortConfig{
			{Port: 3000, Label: "web"},
			{HostPort: 18080, GuestPort: 8080, Label: "api"},
		},
	})
	want := "3000 -> 3000 (web), 18080 -> 8080 (api)"
	if got != want {
		t.Fatalf("localPortSummary() = %q, want %q", got, want)
	}
}

func TestLocalPortsCmdAddsLimaPortsAndPersistsState(t *testing.T) {
	origLoadLocal := loadLocalInstancesForCLI
	origSaveLocal := saveLocalInstancesForCLI
	origRunCommand := localRunCommand
	t.Cleanup(func() {
		loadLocalInstancesForCLI = origLoadLocal
		saveLocalInstancesForCLI = origSaveLocal
		localRunCommand = origRunCommand
	})

	state := &cwconfig.LocalInstancesConfig{
		Instances: map[string]cwconfig.LocalInstance{
			"repo": {
				Name:             "repo",
				Backend:          "lima",
				RuntimeName:      "cw-repo",
				LimaInstanceName: "cw-repo",
				Ports: []cwconfig.PortConfig{
					{Port: 3000, Label: "web"},
				},
			},
		},
	}
	loadLocalInstancesForCLI = func() (*cwconfig.LocalInstancesConfig, error) {
		return state, nil
	}

	var saved *cwconfig.LocalInstancesConfig
	saveLocalInstancesForCLI = func(cfg *cwconfig.LocalInstancesConfig) error {
		saved = cfg
		return nil
	}

	var calls [][]string
	localRunCommand = func(name string, args ...string) ([]byte, error) {
		calls = append(calls, append([]string{name}, args...))
		return nil, nil
	}

	oldStdout := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	os.Stdout = w
	defer func() { os.Stdout = oldStdout }()

	cmd := localPortsCmd()
	cmd.SetArgs([]string{"repo", "--publish", "18080:8080"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("local ports command failed: %v", err)
	}

	_ = w.Close()
	_, _ = io.ReadAll(r)

	wantCalls := [][]string{{
		"limactl",
		"edit",
		"--tty=false",
		"cw-repo",
		"--set",
		`.portForwards = (.portForwards // []) + [{"guestPort":8080,"hostPort":18080,"proto":"tcp"}]`,
	}}
	if !reflect.DeepEqual(calls, wantCalls) {
		t.Fatalf("localRunCommand calls = %#v, want %#v", calls, wantCalls)
	}
	if saved == nil {
		t.Fatal("expected local instance state to be saved")
	}
	wantPorts := []cwconfig.PortConfig{
		{Port: 3000, Label: "web"},
		{HostPort: 18080, GuestPort: 8080},
	}
	gotPorts := saved.Instances["repo"].Ports
	if !reflect.DeepEqual(gotPorts, wantPorts) {
		t.Fatalf("saved ports = %#v, want %#v", gotPorts, wantPorts)
	}
}

func TestLocalPortsCmdRejectsConflictingLimaHostPort(t *testing.T) {
	origLoadLocal := loadLocalInstancesForCLI
	origSaveLocal := saveLocalInstancesForCLI
	origRunCommand := localRunCommand
	t.Cleanup(func() {
		loadLocalInstancesForCLI = origLoadLocal
		saveLocalInstancesForCLI = origSaveLocal
		localRunCommand = origRunCommand
	})

	loadLocalInstancesForCLI = func() (*cwconfig.LocalInstancesConfig, error) {
		return &cwconfig.LocalInstancesConfig{
			Instances: map[string]cwconfig.LocalInstance{
				"repo": {
					Name:             "repo",
					Backend:          "lima",
					RuntimeName:      "cw-repo",
					LimaInstanceName: "cw-repo",
					Ports: []cwconfig.PortConfig{
						{HostPort: 18080, GuestPort: 8080},
					},
				},
			},
		}, nil
	}

	saved := false
	saveLocalInstancesForCLI = func(cfg *cwconfig.LocalInstancesConfig) error {
		saved = true
		return nil
	}

	called := false
	localRunCommand = func(name string, args ...string) ([]byte, error) {
		called = true
		return nil, nil
	}

	cmd := localPortsCmd()
	cmd.SetArgs([]string{"repo", "--publish", "18080:3000"})
	err := cmd.Execute()
	if err == nil {
		t.Fatal("expected local ports command to fail")
	}
	if !strings.Contains(err.Error(), "host port 18080 is already forwarded to guest port 8080") {
		t.Fatalf("error = %q, want host port conflict", err)
	}
	if called {
		t.Fatal("expected limactl edit not to be called")
	}
	if saved {
		t.Fatal("expected local instance state not to be saved")
	}
}

func TestLocalInfoCmdPrintsLimaPortSummary(t *testing.T) {
	origLoadLocal := loadLocalInstancesForCLI
	origLookPath := localLookPath
	origRunCommand := localRunCommand
	t.Cleanup(func() {
		loadLocalInstancesForCLI = origLoadLocal
		localLookPath = origLookPath
		localRunCommand = origRunCommand
	})

	loadLocalInstancesForCLI = func() (*cwconfig.LocalInstancesConfig, error) {
		return &cwconfig.LocalInstancesConfig{
			Instances: map[string]cwconfig.LocalInstance{
				"repo": {
					Name:             "repo",
					Backend:          "lima",
					RuntimeName:      "cw-repo",
					RepoPath:         "/tmp/repo",
					Workdir:          "/workspace",
					Image:            "ghcr.io/codewiresh/full:latest",
					LimaInstanceName: "cw-repo",
					LimaVMType:       "qemu",
					LimaMountType:    "9p",
					Ports: []cwconfig.PortConfig{
						{Port: 3000, Label: "web"},
					},
				},
			},
		}, nil
	}
	localLookPath = func(file string) (string, error) {
		if file != "limactl" {
			t.Fatalf("LookPath(%q) unexpected", file)
		}
		return "/usr/bin/limactl", nil
	}
	localRunCommand = func(name string, args ...string) ([]byte, error) {
		return []byte(`[{"name":"cw-repo","status":"Running"}]`), nil
	}

	oldStdout := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	os.Stdout = w
	defer func() { os.Stdout = oldStdout }()

	cmd := localInfoCmd()
	cmd.SetArgs([]string{"repo"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("local info command failed: %v", err)
	}

	_ = w.Close()
	output, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("read output: %v", err)
	}
	got := string(output)
	if !strings.Contains(got, "Ports:") {
		t.Fatalf("expected Ports line, got %q", got)
	}
	if !strings.Contains(got, "3000 -> 3000 (web)") {
		t.Fatalf("expected lima port mapping, got %q", got)
	}
}

func TestLocalListCmdPrintsPortColumn(t *testing.T) {
	origLoadLocal := loadLocalInstancesForCLI
	origLookPath := localLookPath
	origRunCommand := localRunCommand
	t.Cleanup(func() {
		loadLocalInstancesForCLI = origLoadLocal
		localLookPath = origLookPath
		localRunCommand = origRunCommand
	})

	loadLocalInstancesForCLI = func() (*cwconfig.LocalInstancesConfig, error) {
		return &cwconfig.LocalInstancesConfig{
			Instances: map[string]cwconfig.LocalInstance{
				"repo": {
					Name:             "repo",
					Backend:          "lima",
					RuntimeName:      "cw-repo",
					RepoPath:         "/tmp/repo",
					Image:            "ghcr.io/codewiresh/full:latest",
					LimaInstanceName: "cw-repo",
					Ports: []cwconfig.PortConfig{
						{Port: 3000, Label: "web"},
					},
				},
			},
		}, nil
	}
	localLookPath = func(file string) (string, error) {
		if file != "limactl" {
			t.Fatalf("LookPath(%q) unexpected", file)
		}
		return "/usr/bin/limactl", nil
	}
	localRunCommand = func(name string, args ...string) ([]byte, error) {
		return []byte(`[{"name":"cw-repo","status":"Running"}]`), nil
	}

	oldStdout := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	os.Stdout = w
	defer func() { os.Stdout = oldStdout }()

	cmd := localListCmd()
	cmd.SetArgs(nil)
	if err := cmd.Execute(); err != nil {
		t.Fatalf("local list command failed: %v", err)
	}

	_ = w.Close()
	output, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("read output: %v", err)
	}
	got := string(output)
	if !strings.Contains(got, "PORTS") {
		t.Fatalf("expected PORTS header, got %q", got)
	}
	if !strings.Contains(got, "3000 -> 3000 (web)") {
		t.Fatalf("expected lima port mapping, got %q", got)
	}
}

func TestDockerContainerStatusParsesInspectOutput(t *testing.T) {
	origRunCommand := localRunCommand
	t.Cleanup(func() { localRunCommand = origRunCommand })

	localRunCommand = func(name string, args ...string) ([]byte, error) {
		return []byte("running\n"), nil
	}

	got, err := dockerContainerStatus("cw-repo")
	if err != nil {
		t.Fatalf("dockerContainerStatus() error = %v", err)
	}
	if got != "running" {
		t.Fatalf("status = %q, want %q", got, "running")
	}
}

func TestDockerContainerStatusMissingOnNotFound(t *testing.T) {
	origRunCommand := localRunCommand
	t.Cleanup(func() { localRunCommand = origRunCommand })

	localRunCommand = func(name string, args ...string) ([]byte, error) {
		return []byte("Error: No such container"), errors.New("missing")
	}

	got, err := dockerContainerStatus("cw-repo")
	if err != nil {
		t.Fatalf("dockerContainerStatus() error = %v", err)
	}
	if got != "missing" {
		t.Fatalf("status = %q, want %q", got, "missing")
	}
}

func TestOfferLimaInstallDeclined(t *testing.T) {
	origPrompt := localPromptConfirm
	t.Cleanup(func() { localPromptConfirm = origPrompt })

	localPromptConfirm = func(label string) (bool, error) {
		return false, nil
	}

	err := offerLimaInstall()
	if err == nil {
		t.Fatal("expected error when user declines install")
	}
	if !strings.Contains(err.Error(), "limactl not found in PATH") {
		t.Fatalf("error = %q, want limactl not found message", err.Error())
	}
}

func TestOfferLimaInstallPromptError(t *testing.T) {
	origPrompt := localPromptConfirm
	t.Cleanup(func() { localPromptConfirm = origPrompt })

	localPromptConfirm = func(label string) (bool, error) {
		return false, errors.New("not a terminal")
	}

	err := offerLimaInstall()
	if err == nil {
		t.Fatal("expected error when prompt fails")
	}
	if !strings.Contains(err.Error(), "limactl not found in PATH") {
		t.Fatalf("error = %q, want limactl not found message", err.Error())
	}
}

func TestOfferLimaInstallBrewOnDarwin(t *testing.T) {
	origPrompt := localPromptConfirm
	origLookPath := localLookPath
	origRunCommand := localRunCommand
	origGOOS := localGOOS
	t.Cleanup(func() {
		localPromptConfirm = origPrompt
		localLookPath = origLookPath
		localRunCommand = origRunCommand
		localGOOS = origGOOS
	})

	localGOOS = "darwin"
	localPromptConfirm = func(label string) (bool, error) {
		return true, nil
	}

	localLookPath = func(file string) (string, error) {
		if file == "brew" {
			return "/opt/homebrew/bin/brew", nil
		}
		if file == "limactl" {
			return "/opt/homebrew/bin/limactl", nil
		}
		return "", errors.New("not found")
	}

	var ranBrew bool
	localRunCommand = func(name string, args ...string) ([]byte, error) {
		if name == "brew" && len(args) == 2 && args[0] == "install" && args[1] == "lima" {
			ranBrew = true
			return nil, nil
		}
		return nil, errors.New("unexpected command: " + name)
	}

	err := offerLimaInstall()
	if err != nil {
		t.Fatalf("offerLimaInstall() error = %v", err)
	}
	if !ranBrew {
		t.Fatal("expected brew install lima to be called")
	}
}

func TestOfferLimaInstallGitHubReleaseOnLinux(t *testing.T) {
	origPrompt := localPromptConfirm
	origLookPath := localLookPath
	origRunCommand := localRunCommand
	origGOOS := localGOOS
	t.Cleanup(func() {
		localPromptConfirm = origPrompt
		localLookPath = origLookPath
		localRunCommand = origRunCommand
		localGOOS = origGOOS
	})

	localGOOS = "linux"
	localPromptConfirm = func(label string) (bool, error) {
		return true, nil
	}

	// Create a temp dir with the expected binary layout
	tmpDir := t.TempDir()
	binDir := filepath.Join(tmpDir, "bin")
	os.MkdirAll(binDir, 0o755)
	os.WriteFile(filepath.Join(binDir, "limactl"), []byte("#!/bin/sh\n"), 0o755)

	lookPathCalls := 0
	localLookPath = func(file string) (string, error) {
		lookPathCalls++
		if file == "limactl" && lookPathCalls > 1 {
			// After install, limactl is found
			return "/usr/local/bin/limactl", nil
		}
		return "", errors.New("not found")
	}

	var commands []string
	localRunCommand = func(name string, args ...string) ([]byte, error) {
		cmd := name + " " + strings.Join(args, " ")
		commands = append(commands, cmd)
		if name == "curl" {
			return []byte("{\n  \"tag_name\": \"v1.0.0\"\n}"), nil
		}
		if name == "sh" {
			// Simulate tarball extraction by creating expected file
			return nil, nil
		}
		if name == "sudo" {
			return nil, nil
		}
		return nil, errors.New("unexpected: " + cmd)
	}

	// We need os.Stat to find the binary -- use a real temp dir.
	// The function creates its own tmpDir, so we need to pre-create the binary there.
	// Instead, just test that it calls the right commands in sequence.
	// The os.Stat check will fail because the real curl/tar didn't run,
	// so we verify the error message mentions the expected path.
	err := offerLimaInstall()

	// Verify curl was called to fetch the release
	if len(commands) == 0 {
		t.Fatal("expected commands to be run")
	}
	if !strings.Contains(commands[0], "api.github.com/repos/lima-vm/lima") {
		t.Fatalf("first command should fetch lima release, got: %s", commands[0])
	}
	// The tar extraction won't actually create the file, so we expect
	// an error about the binary not being found at the expected path
	if err != nil && !strings.Contains(err.Error(), "limactl not found at expected path") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestLimaCreateFailureReturnsError(t *testing.T) {
	origLookPath := localLookPath
	origRunStream := localRunCommandStream
	origGOOS := localGOOS
	origUserHomeDir := localUserHomeDir
	stubLocalCLIDataDir(t)
	homeDir := filepath.Join(t.TempDir(), "home")
	t.Cleanup(func() {
		localLookPath = origLookPath
		localRunCommandStream = origRunStream
		localGOOS = origGOOS
		localUserHomeDir = origUserHomeDir
	})

	localGOOS = "linux"
	localUserHomeDir = func() (string, error) { return homeDir, nil }
	localLookPath = func(file string) (string, error) {
		return "/usr/bin/" + file, nil
	}
	localRunCommandStream = func(name string, args ...string) error {
		return errors.New("exit status 1")
	}

	instance := &cwconfig.LocalInstance{Name: "repo", Backend: "lima", RuntimeName: "cw-repo", RepoPath: "/tmp/repo"}
	err := createLocalLimaInstance(instance)
	if err == nil {
		t.Fatal("expected error when limactl start fails")
	}
	if !strings.Contains(err.Error(), "limactl") {
		t.Fatalf("error should mention limactl, got: %v", err)
	}
}

func TestLimaStartFailureReturnsError(t *testing.T) {
	origLookPath := localLookPath
	origRunStream := localRunCommandStream
	origUserHomeDir := localUserHomeDir
	stubLocalCLIDataDir(t)
	homeDir := filepath.Join(t.TempDir(), "home")
	t.Cleanup(func() {
		localLookPath = origLookPath
		localRunCommandStream = origRunStream
		localUserHomeDir = origUserHomeDir
	})

	localUserHomeDir = func() (string, error) { return homeDir, nil }
	localLookPath = func(file string) (string, error) {
		return "/usr/bin/" + file, nil
	}
	localRunCommandStream = func(name string, args ...string) error {
		return errors.New("exit status 1")
	}

	instance := &cwconfig.LocalInstance{LimaInstanceName: "cw-repo"}
	err := startLocalLimaInstance(instance)
	if err == nil {
		t.Fatal("expected error when limactl start fails")
	}
	if !strings.Contains(err.Error(), "cw-repo") {
		t.Fatalf("error should mention instance name, got: %v", err)
	}
}

func TestLimaStopFailureReturnsError(t *testing.T) {
	origLookPath := localLookPath
	origRunCommand := localRunCommand
	t.Cleanup(func() {
		localLookPath = origLookPath
		localRunCommand = origRunCommand
	})

	localLookPath = func(file string) (string, error) {
		return "/usr/bin/" + file, nil
	}
	localRunCommand = func(name string, args ...string) ([]byte, error) {
		return []byte("stop failed"), errors.New("exit status 1")
	}

	instance := &cwconfig.LocalInstance{LimaInstanceName: "cw-repo"}
	err := stopLocalLimaInstance(instance)
	if err == nil {
		t.Fatal("expected error when limactl stop fails")
	}
	if !strings.Contains(err.Error(), "cw-repo") {
		t.Fatalf("error should mention instance name, got: %v", err)
	}
}

func TestLimaDeleteNotFoundReturnsNil(t *testing.T) {
	origLookPath := localLookPath
	origRunCommand := localRunCommand
	dataDir := stubLocalCLIDataDir(t)
	t.Cleanup(func() {
		localLookPath = origLookPath
		localRunCommand = origRunCommand
	})

	localLookPath = func(file string) (string, error) {
		return "/usr/bin/" + file, nil
	}
	localRunCommand = func(name string, args ...string) ([]byte, error) {
		return []byte("instance not found"), errors.New("exit status 1")
	}

	instance := &cwconfig.LocalInstance{LimaInstanceName: "cw-repo"}
	if err := os.MkdirAll(filepath.Join(dataDir, "lima", "cw-repo", "claude"), 0o755); err != nil {
		t.Fatalf("MkdirAll(stateDir): %v", err)
	}
	err := deleteLocalLimaInstance(instance)
	if err != nil {
		t.Fatalf("expected nil error for not-found delete, got: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dataDir, "lima", "cw-repo")); !os.IsNotExist(err) {
		t.Fatalf("expected Lima state dir to be removed, got err=%v", err)
	}
}

func TestLimaDeleteFailureReturnsError(t *testing.T) {
	origLookPath := localLookPath
	origRunCommand := localRunCommand
	stubLocalCLIDataDir(t)
	t.Cleanup(func() {
		localLookPath = origLookPath
		localRunCommand = origRunCommand
	})

	localLookPath = func(file string) (string, error) {
		return "/usr/bin/" + file, nil
	}
	localRunCommand = func(name string, args ...string) ([]byte, error) {
		return []byte("permission denied"), errors.New("exit status 1")
	}

	instance := &cwconfig.LocalInstance{LimaInstanceName: "cw-repo"}
	err := deleteLocalLimaInstance(instance)
	if err == nil {
		t.Fatal("expected error for non-not-found delete failure")
	}
}

func TestLimaInstanceStatusMissingOnNDJSONListOutput(t *testing.T) {
	origLookPath := localLookPath
	origRunCommand := localRunCommand
	t.Cleanup(func() {
		localLookPath = origLookPath
		localRunCommand = origRunCommand
	})

	localLookPath = func(file string) (string, error) {
		return "/usr/bin/" + file, nil
	}
	localRunCommand = func(name string, args ...string) ([]byte, error) {
		return []byte(`{"name":"cw-other","status":"Running"}
{"name":"cw-something","status":"Stopped"}
`), nil
	}

	instance := &cwconfig.LocalInstance{LimaInstanceName: "cw-repo"}
	status, err := limaInstanceStatus(instance)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if status != "missing" {
		t.Fatalf("status = %q, want %q", status, "missing")
	}
}

func TestLimaInstanceStatusMissingOnNotFound(t *testing.T) {
	origLookPath := localLookPath
	origRunCommand := localRunCommand
	t.Cleanup(func() {
		localLookPath = origLookPath
		localRunCommand = origRunCommand
	})

	localLookPath = func(file string) (string, error) {
		return "/usr/bin/" + file, nil
	}
	localRunCommand = func(name string, args ...string) ([]byte, error) {
		return []byte("instance not found"), errors.New("exit status 1")
	}

	instance := &cwconfig.LocalInstance{LimaInstanceName: "cw-repo"}
	status, err := limaInstanceStatus(instance)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if status != "missing" {
		t.Fatalf("status = %q, want %q", status, "missing")
	}
}

func TestLimaInstanceStatusIgnoresWarningOnlyOutput(t *testing.T) {
	origLookPath := localLookPath
	origRunCommand := localRunCommand
	t.Cleanup(func() {
		localLookPath = origLookPath
		localRunCommand = origRunCommand
	})

	localLookPath = func(file string) (string, error) {
		return "/usr/bin/" + file, nil
	}
	localRunCommand = func(name string, args ...string) ([]byte, error) {
		return []byte(`time="2026-04-11T17:00:49+02:00" level=warning msg="No instance found. Run ` + "`limactl create`" + ` to create an instance."
`), nil
	}

	instance := &cwconfig.LocalInstance{LimaInstanceName: "cw-repo"}
	status, err := limaInstanceStatus(instance)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if status != "missing" {
		t.Fatalf("status = %q, want %q", status, "missing")
	}
}

func TestLimaInstanceStatusEmptyOutput(t *testing.T) {
	origLookPath := localLookPath
	origRunCommand := localRunCommand
	t.Cleanup(func() {
		localLookPath = origLookPath
		localRunCommand = origRunCommand
	})

	localLookPath = func(file string) (string, error) {
		return "/usr/bin/" + file, nil
	}
	localRunCommand = func(name string, args ...string) ([]byte, error) {
		return []byte(""), nil
	}

	instance := &cwconfig.LocalInstance{LimaInstanceName: "cw-repo"}
	status, err := limaInstanceStatus(instance)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if status != "missing" {
		t.Fatalf("status = %q, want %q", status, "missing")
	}
}

func TestLimaInstanceStatusSingleObject(t *testing.T) {
	origLookPath := localLookPath
	origRunCommand := localRunCommand
	t.Cleanup(func() {
		localLookPath = origLookPath
		localRunCommand = origRunCommand
	})

	localLookPath = func(file string) (string, error) {
		return "/usr/bin/" + file, nil
	}
	localRunCommand = func(name string, args ...string) ([]byte, error) {
		return []byte(`{"name":"cw-repo","status":"Stopped"}`), nil
	}

	instance := &cwconfig.LocalInstance{LimaInstanceName: "cw-repo"}
	status, err := limaInstanceStatus(instance)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if status != "stopped" {
		t.Fatalf("status = %q, want %q", status, "stopped")
	}
}

func TestLimaInstanceStatusNameMismatch(t *testing.T) {
	origLookPath := localLookPath
	origRunCommand := localRunCommand
	t.Cleanup(func() {
		localLookPath = origLookPath
		localRunCommand = origRunCommand
	})

	localLookPath = func(file string) (string, error) {
		return "/usr/bin/" + file, nil
	}
	localRunCommand = func(name string, args ...string) ([]byte, error) {
		return []byte(`[{"name":"other-instance","status":"Running"}]`), nil
	}

	instance := &cwconfig.LocalInstance{LimaInstanceName: "cw-repo"}
	status, err := limaInstanceStatus(instance)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if status != "missing" {
		t.Fatalf("status = %q, want %q", status, "missing")
	}
}

func TestLimaInstanceNamePriority(t *testing.T) {
	// LimaInstanceName takes priority
	inst := &cwconfig.LocalInstance{LimaInstanceName: "custom", RuntimeName: "rt", Name: "n"}
	if got := limaInstanceName(inst); got != "custom" {
		t.Fatalf("got %q, want %q", got, "custom")
	}
	// Falls back to RuntimeName
	inst = &cwconfig.LocalInstance{RuntimeName: "rt", Name: "n"}
	if got := limaInstanceName(inst); got != "rt" {
		t.Fatalf("got %q, want %q", got, "rt")
	}
	// Falls back to Name
	inst = &cwconfig.LocalInstance{Name: "n"}
	if got := limaInstanceName(inst); got != "n" {
		t.Fatalf("got %q, want %q", got, "n")
	}
	// Nil returns empty
	if got := limaInstanceName(nil); got != "" {
		t.Fatalf("got %q, want empty", got)
	}
}

func TestDefaultLimaVMAndMountType(t *testing.T) {
	origGOOS := localGOOS
	t.Cleanup(func() { localGOOS = origGOOS })

	localGOOS = "darwin"
	if got := defaultLimaVMType(); got != "vz" {
		t.Fatalf("darwin VM type = %q, want vz", got)
	}
	if got := defaultLimaMountType("vz"); got != "virtiofs" {
		t.Fatalf("vz mount type = %q, want virtiofs", got)
	}

	localGOOS = "linux"
	if got := defaultLimaVMType(); got != "qemu" {
		t.Fatalf("linux VM type = %q, want qemu", got)
	}
	if got := defaultLimaMountType("qemu"); got != "9p" {
		t.Fatalf("qemu mount type = %q, want 9p", got)
	}
}

func TestOfferLimaInstallCalledWhenLimactlMissing(t *testing.T) {
	origLookPath := localLookPath
	origPrompt := localPromptConfirm
	t.Cleanup(func() {
		localLookPath = origLookPath
		localPromptConfirm = origPrompt
	})

	localLookPath = func(file string) (string, error) {
		return "", errors.New("not found")
	}

	var installOffered bool
	localPromptConfirm = func(label string) (bool, error) {
		installOffered = true
		return false, nil // decline
	}

	instance := &cwconfig.LocalInstance{
		Name:        "repo",
		Backend:     "lima",
		RuntimeName: "cw-repo",
		RepoPath:    "/tmp/repo",
	}

	err := createLocalLimaInstance(instance)
	if err == nil {
		t.Fatal("expected error when limactl is missing and install declined")
	}
	if !installOffered {
		t.Fatal("expected install prompt to be offered")
	}
}
