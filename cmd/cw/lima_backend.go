package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"

	cwconfig "github.com/codewiresh/codewire/internal/config"
)

var localGOOS = runtime.GOOS

// offerLimaInstall prompts the user to install Lima automatically.
func offerLimaInstall() error {
	fmt.Fprintln(os.Stderr, "Lima is not installed.")
	ok, err := localPromptConfirm("Install Lima now?")
	if err != nil {
		return fmt.Errorf("limactl not found in PATH")
	}
	if !ok {
		return fmt.Errorf("limactl not found in PATH")
	}

	// macOS: prefer Homebrew if available
	if localGOOS == "darwin" {
		if _, brewErr := localLookPath("brew"); brewErr == nil {
			fmt.Fprintf(os.Stderr, "\n  Installing Lima via Homebrew...\n")
			out, err := localRunCommand("brew", "install", "lima")
			if err != nil {
				return fmt.Errorf("brew install lima failed: %v\n%s", err, strings.TrimSpace(string(out)))
			}
			if _, err := localLookPath("limactl"); err != nil {
				return fmt.Errorf("lima installed but limactl not found in PATH")
			}
			fmt.Fprintf(os.Stderr, "  Lima installed.\n\n")
			return nil
		}
	}

	// Linux (or macOS without Homebrew): install from GitHub release
	fmt.Fprintf(os.Stderr, "\n  Fetching latest Lima release...\n")

	arch := "x86_64"
	if runtime.GOARCH == "arm64" {
		arch = "aarch64"
	}
	osName := "Linux"
	if localGOOS == "darwin" {
		osName = "Darwin"
	}

	// Get latest version tag
	out, err := localRunCommand("curl", "-fsSL",
		"https://api.github.com/repos/lima-vm/lima/releases/latest")
	if err != nil {
		return fmt.Errorf("failed to fetch latest release: %w", err)
	}
	version := ""
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "\"tag_name\"") {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 {
				version = strings.Trim(strings.TrimSpace(parts[1]), "\",")
			}
			break
		}
	}
	if version == "" {
		return fmt.Errorf("could not determine latest lima version")
	}

	fmt.Fprintf(os.Stderr, "  Installing Lima %s (%s/%s)...\n", version, osName, arch)

	// Download and extract -- tag has "v" prefix but asset filenames do not
	bareVersion := strings.TrimPrefix(version, "v")
	url := fmt.Sprintf("https://github.com/lima-vm/lima/releases/download/%s/lima-%s-%s-%s.tar.gz",
		version, bareVersion, osName, arch)
	tmpDir := filepath.Join(os.TempDir(), "cw-lima-install")
	os.MkdirAll(tmpDir, 0o755)
	defer os.RemoveAll(tmpDir)

	out, err = localRunCommand("sh", "-c",
		fmt.Sprintf("curl -fsSL %q | tar xz -C %q", url, tmpDir))
	if err != nil {
		return fmt.Errorf("download failed: %v\n%s", err, strings.TrimSpace(string(out)))
	}

	// Lima tarballs contain bin/, libexec/, share/ (templates, guest agent)
	binaryPath := filepath.Join(tmpDir, "bin", "limactl")
	if _, statErr := os.Stat(binaryPath); statErr != nil {
		return fmt.Errorf("limactl not found at expected path: %s", binaryPath)
	}

	// Install full tree to /usr/local/ so templates and guest agent are available
	fmt.Fprintf(os.Stderr, "  Installing to /usr/local/ (requires sudo)...\n")
	out, err = localRunCommand("sudo", "sh", "-c",
		fmt.Sprintf("cp -r %s/bin/* /usr/local/bin/ && cp -r %s/share/* /usr/local/share/ && "+
			"test -d %s/libexec && cp -r %s/libexec/* /usr/local/libexec/ || true",
			tmpDir, tmpDir, tmpDir, tmpDir))
	if err != nil {
		return fmt.Errorf("install failed: %v\n%s\n\n  You can install manually:\n    sudo tar xzf <lima-tarball> -C /usr/local/",
			err, strings.TrimSpace(string(out)))
	}

	// Verify
	if _, err := localLookPath("limactl"); err != nil {
		return fmt.Errorf("lima installed but limactl not found in PATH")
	}

	fmt.Fprintf(os.Stderr, "  Lima %s installed.\n\n", version)
	return nil
}

type limaListEntry struct {
	Name   string `json:"name"`
	Status string `json:"status"`
}

func limaInstanceName(instance *cwconfig.LocalInstance) string {
	if instance == nil {
		return ""
	}
	if strings.TrimSpace(instance.LimaInstanceName) != "" {
		return strings.TrimSpace(instance.LimaInstanceName)
	}
	if strings.TrimSpace(instance.RuntimeName) != "" {
		return strings.TrimSpace(instance.RuntimeName)
	}
	return strings.TrimSpace(instance.Name)
}

func defaultLimaVMType() string {
	if localGOOS == "darwin" {
		return "vz"
	}
	return "qemu"
}

func defaultLimaMountType(vmType string) string {
	if vmType == "vz" {
		return "virtiofs"
	}
	return "9p"
}

type limaVMMount struct {
	Location   string `json:"location"`
	MountPoint string `json:"mountPoint"`
	Writable   bool   `json:"writable"`
}

type limaContainerMount struct {
	Source   string
	Target   string
	ReadOnly bool
}

func pathWithinRoot(root, candidate string) bool {
	root = filepath.Clean(root)
	candidate = filepath.Clean(candidate)
	if root == candidate {
		return true
	}
	rel, err := filepath.Rel(root, candidate)
	if err != nil {
		return false
	}
	return rel == "." || (rel != ".." && !strings.HasPrefix(rel, ".."+string(os.PathSeparator)))
}

func discoverExternalSymlinkMounts(root string, readOnly bool) []cwconfig.MountConfig {
	root = filepath.Clean(strings.TrimSpace(root))
	if root == "" {
		return nil
	}
	if _, err := localOsStat(root); err != nil {
		return nil
	}

	candidates := map[string]struct{}{}
	var walk func(string)
	walk = func(dir string) {
		entries, err := os.ReadDir(dir)
		if err != nil {
			return
		}
		for _, entry := range entries {
			path := filepath.Join(dir, entry.Name())
			if entry.Type()&os.ModeSymlink != 0 {
				target, err := os.Readlink(path)
				if err != nil {
					continue
				}
				if !filepath.IsAbs(target) {
					target = filepath.Join(filepath.Dir(path), target)
				}
				target = filepath.Clean(target)
				if pathWithinRoot(root, target) {
					continue
				}
				info, err := localOsStat(target)
				if err != nil {
					continue
				}
				if !info.IsDir() && !info.Mode().IsRegular() {
					continue
				}
				mountPath := target
				if !info.IsDir() {
					mountPath = filepath.Dir(target)
				}
				if mountPath == "/" || mountPath == "." {
					continue
				}
				candidates[mountPath] = struct{}{}
				continue
			}
			if entry.IsDir() {
				walk(path)
			}
		}
	}
	walk(root)

	paths := make([]string, 0, len(candidates))
	for candidate := range candidates {
		paths = append(paths, candidate)
	}
	sort.Slice(paths, func(i, j int) bool {
		if len(paths[i]) == len(paths[j]) {
			return paths[i] < paths[j]
		}
		return len(paths[i]) < len(paths[j])
	})

	collapsed := make([]string, 0, len(paths))
	for _, candidate := range paths {
		skip := false
		for _, existing := range collapsed {
			if pathWithinRoot(existing, candidate) {
				skip = true
				break
			}
		}
		if !skip {
			collapsed = append(collapsed, candidate)
		}
	}

	mounts := make([]cwconfig.MountConfig, 0, len(collapsed))
	for _, candidate := range collapsed {
		mounts = append(mounts, cwconfig.MountConfig{
			Source:   candidate,
			Target:   candidate,
			Readonly: boolPtr(readOnly),
		})
	}
	return mounts
}

// Keep per-instance Claude runtime state isolated. In particular, do not seed
// plugins or marketplaces from host ~/.claude because those registries store
// absolute install and project paths that break across host/Lima boundaries.
var limaClaudePortableEntries = []string{
	"settings.json",
	"settings.local.json",
	"CLAUDE.md",
	"commands",
	"skills",
}

func limaRepoMountPath(instance *cwconfig.LocalInstance) string {
	if instance == nil {
		return localWorkspacePath
	}
	if workdir := strings.TrimSpace(instance.Workdir); workdir != "" {
		return filepath.Clean(workdir)
	}
	if repoPath := strings.TrimSpace(instance.RepoPath); repoPath != "" {
		return filepath.Clean(repoPath)
	}
	return localWorkspacePath
}

func limaStateDir(instance *cwconfig.LocalInstance) string {
	return filepath.Join(localCLIDataDir(), "lima", limaInstanceName(instance))
}

func limaClaudeStateHostDir(instance *cwconfig.LocalInstance) string {
	return filepath.Join(limaStateDir(instance), "claude")
}

func limaGitStateHostDir(instance *cwconfig.LocalInstance) string {
	return filepath.Join(limaStateDir(instance), "git")
}

func ensureLimaGitConfig(instance *cwconfig.LocalInstance) error {
	source := strings.TrimSpace(localGitConfigPath())
	if source == "" {
		return nil
	}
	targetDir := limaGitStateHostDir(instance)
	if err := os.MkdirAll(targetDir, 0o755); err != nil {
		return fmt.Errorf("create Lima git state dir: %w", err)
	}
	if err := copyPathIfMissing(source, filepath.Join(targetDir, ".gitconfig")); err != nil {
		return fmt.Errorf("seed Lima git config: %w", err)
	}
	return nil
}

func limaSSHAgentForwardSetExpr() (string, bool, error) {
	hostSocket := strings.TrimSpace(localSSHAuthSock())
	if hostSocket == "" {
		return "", false, nil
	}
	payload, err := json.Marshal([]map[string]string{{"guestSocket": localSSHAuthSockPath, "hostSocket": hostSocket}})
	if err != nil {
		return "", false, fmt.Errorf("marshal Lima SSH agent forward: %w", err)
	}
	return fmt.Sprintf(`.portForwards = ((.portForwards // []) | map(select(.guestSocket != %q)) + %s)`, localSSHAuthSockPath, string(payload)), true, nil
}

func ensureLimaSSHAgentForward(instance *cwconfig.LocalInstance) error {
	setExpr, ok, err := limaSSHAgentForwardSetExpr()
	if err != nil || !ok {
		return err
	}
	out, err := localRunCommand("limactl", "edit", "--tty=false", limaInstanceName(instance), "--set", setExpr)
	if err != nil {
		trimmed := strings.TrimSpace(string(out))
		if trimmed != "" {
			return fmt.Errorf("limactl edit %s: %v\n%s", limaInstanceName(instance), err, trimmed)
		}
		return fmt.Errorf("limactl edit %s: %w", limaInstanceName(instance), err)
	}
	return nil
}

func ensureLimaClaudeState(instance *cwconfig.LocalInstance) error {
	targetDir := limaClaudeStateHostDir(instance)
	if err := os.MkdirAll(targetDir, 0o755); err != nil {
		return fmt.Errorf("create Lima Claude state dir: %w", err)
	}

	homeDir, err := localUserHomeDir()
	if err != nil {
		return nil
	}
	hostClaudeDir := filepath.Join(homeDir, ".claude")
	if _, err := os.Stat(hostClaudeDir); err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("read host Claude dir: %w", err)
	}

	for _, entry := range limaClaudePortableEntries {
		if err := copyPathIfMissing(filepath.Join(hostClaudeDir, entry), filepath.Join(targetDir, entry)); err != nil {
			return fmt.Errorf("seed Lima Claude state %s: %w", entry, err)
		}
	}
	return nil
}

func copyPathIfMissing(source, target string) error {
	info, err := os.Lstat(source)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}

	if info.Mode()&os.ModeSymlink != 0 {
		resolved, err := filepath.EvalSymlinks(source)
		if err != nil {
			if os.IsNotExist(err) {
				return nil
			}
			return err
		}
		return copyPathIfMissing(resolved, target)
	}

	if info.IsDir() {
		if err := os.MkdirAll(target, info.Mode().Perm()); err != nil {
			return err
		}
		entries, err := os.ReadDir(source)
		if err != nil {
			return err
		}
		for _, entry := range entries {
			if err := copyPathIfMissing(filepath.Join(source, entry.Name()), filepath.Join(target, entry.Name())); err != nil {
				return err
			}
		}
		return nil
	}

	if !info.Mode().IsRegular() {
		return nil
	}
	if _, err := os.Lstat(target); err == nil {
		return nil
	} else if !os.IsNotExist(err) {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
		return err
	}
	return copyRegularFile(source, target, info.Mode().Perm())
}

func copyRegularFile(source, target string, mode os.FileMode) error {
	in, err := os.Open(source)
	if err != nil {
		return err
	}
	defer in.Close()

	out, err := os.OpenFile(target, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, mode)
	if err != nil {
		return err
	}
	defer func() { _ = out.Close() }()

	if _, err := io.Copy(out, in); err != nil {
		return err
	}
	return out.Close()
}

func limaAdditionalMounts(instance *cwconfig.LocalInstance) []cwconfig.MountConfig {
	mounts := make([]cwconfig.MountConfig, 0)
	if homeDir, err := localUserHomeDir(); err == nil {
		mounts = append(mounts, discoverExternalSymlinkMounts(filepath.Join(homeDir, ".codex"), false)...)
		mounts = append(mounts, discoverExternalSymlinkMounts(filepath.Join(homeDir, ".config", "gh"), false)...)
		mounts = append(mounts, discoverExternalSymlinkMounts(filepath.Join(homeDir, ".ssh"), true)...)
	}
	mounts = append(mounts, instance.Mounts...)

	indexByKey := map[string]int{}
	normalized := make([]cwconfig.MountConfig, 0, len(mounts))
	for _, mount := range mounts {
		source := filepath.Clean(strings.TrimSpace(mount.Source))
		target := mount.EffectiveTarget()
		if source == "" || target == "" {
			continue
		}
		normalizedMount := cwconfig.MountConfig{
			Source:   source,
			Target:   target,
			Readonly: boolPtr(mount.IsReadOnly()),
		}
		key := source + "\x00" + target
		if idx, ok := indexByKey[key]; ok {
			normalized[idx] = normalizedMount
			continue
		}
		indexByKey[key] = len(normalized)
		normalized = append(normalized, normalizedMount)
	}
	sort.Slice(normalized, func(i, j int) bool {
		left := normalized[i].EffectiveTarget()
		right := normalized[j].EffectiveTarget()
		if left == right {
			return normalized[i].Source < normalized[j].Source
		}
		return left < right
	})
	return normalized
}

func limaVMMounts(instance *cwconfig.LocalInstance) []limaVMMount {
	homeDir, _ := localUserHomeDir()
	ghConfigDir := filepath.Join(homeDir, ".config", "gh")
	sshDir := filepath.Join(homeDir, ".ssh")
	mounts := []limaVMMount{
		{Location: limaRepoMountPath(instance), MountPoint: limaRepoMountPath(instance), Writable: true},
		{Location: limaClaudeStateHostDir(instance), MountPoint: "/home/{{.User}}.guest/.claude", Writable: true},
		{Location: ghConfigDir, MountPoint: "/home/{{.User}}.guest/.config/gh", Writable: true},
	}
	if _, err := os.Stat(filepath.Join(limaGitStateHostDir(instance), ".gitconfig")); err == nil {
		mounts = append(mounts, limaVMMount{Location: limaGitStateHostDir(instance), MountPoint: "/home/{{.User}}.guest/.codewire-git", Writable: false})
	}
	mounts = append(mounts, limaVMMount{Location: sshDir, MountPoint: "/mnt/host-ssh", Writable: false})

	codexDir := filepath.Join(homeDir, ".codex")
	if _, err := localOsStat(codexDir); err == nil {
		mounts = append(mounts, limaVMMount{Location: codexDir, MountPoint: "/home/{{.User}}.guest/.codex", Writable: true})
	}
	for _, mount := range limaAdditionalMounts(instance) {
		mounts = append(mounts, limaVMMount{
			Location:   mount.Source,
			MountPoint: mount.EffectiveTarget(),
			Writable:   !mount.IsReadOnly(),
		})
	}
	return mounts
}

func limaContainerMounts(instance *cwconfig.LocalInstance) []limaContainerMount {
	vmUser := os.Getenv("USER")
	vmHome := filepath.Join("/home", vmUser+".guest")
	mounts := []limaContainerMount{
		{Source: filepath.Join(vmHome, ".claude"), Target: "/home/codewire/.claude", ReadOnly: false},
		{Source: filepath.Join(vmHome, ".config", "gh"), Target: "/home/codewire/.config/gh", ReadOnly: false},
		{Source: "/mnt/host-ssh", Target: "/home/codewire/.ssh", ReadOnly: true},
		{Source: filepath.Join(vmHome, ".codex"), Target: "/home/codewire/.codex", ReadOnly: false},
	}
	if sshAuthSock := strings.TrimSpace(localSSHAuthSock()); sshAuthSock != "" {
		mounts = append([]limaContainerMount{{Source: localSSHAuthSockPath, Target: localSSHAuthSockPath, ReadOnly: false}}, mounts...)
	}
	if _, err := os.Stat(filepath.Join(limaGitStateHostDir(instance), ".gitconfig")); err == nil {
		mounts = append([]limaContainerMount{{Source: filepath.Join(vmHome, ".codewire-git", ".gitconfig"), Target: "/home/codewire/.gitconfig", ReadOnly: true}}, mounts...)
	}
	for _, mount := range limaAdditionalMounts(instance) {
		mounts = append(mounts, limaContainerMount{
			Source:   mount.Source,
			Target:   mount.EffectiveTarget(),
			ReadOnly: mount.IsReadOnly(),
		})
	}
	return mounts
}

func limaContainerMountArgs(instance *cwconfig.LocalInstance) []string {
	mounts := limaContainerMounts(instance)
	args := make([]string, 0, len(mounts)*2)
	for _, mount := range mounts {
		spec := mount.Source + ":" + mount.Target
		if mount.ReadOnly {
			spec += ":ro"
		}
		args = append(args, "-v", spec)
	}
	return args
}

func limaCreateCommandArgs(instance *cwconfig.LocalInstance) []string {
	vmType := strings.TrimSpace(instance.LimaVMType)
	if vmType == "" {
		vmType = defaultLimaVMType()
	}
	mountType := strings.TrimSpace(instance.LimaMountType)
	if mountType == "" {
		mountType = defaultLimaMountType(vmType)
	}

	mountBytes, _ := json.Marshal(limaVMMounts(instance))
	mountSet := ".mounts=" + string(mountBytes)

	args := []string{
		"start",
		"--tty=false",
		"--name", limaInstanceName(instance),
		"--vm-type", vmType,
		"--mount-type", mountType,
		"--mount-none",
		"--set", mountSet,
	}
	if sshAgentSetExpr, ok, err := limaSSHAgentForwardSetExpr(); err == nil && ok {
		args = append(args, "--set", sshAgentSetExpr)
	} else if err != nil {
		fmt.Fprintf(os.Stderr, "  Warning: skipping SSH agent forward: %v\n", err)
	}

	if instance.CPU > 0 {
		cpus := (instance.CPU + 999) / 1000
		if cpus < 1 {
			cpus = 1
		}
		args = append(args, "--cpus", strconv.Itoa(cpus))
	}
	if instance.Memory > 0 {
		memGiB := (instance.Memory + 1023) / 1024
		if memGiB < 1 {
			memGiB = 1
		}
		args = append(args, "--memory", strconv.Itoa(memGiB))
	}
	if instance.Disk > 0 {
		args = append(args, "--disk", strconv.Itoa(instance.Disk))
	}
	for _, port := range instance.Ports {
		hostPort := port.EffectiveHostPort()
		guestPort := port.EffectiveGuestPort()
		if hostPort <= 0 || guestPort <= 0 {
			continue
		}
		args = append(args, "--port-forward", fmt.Sprintf("%d:%d,static=true", hostPort, guestPort))
	}

	return append(args, "template:docker")
}

const (
	limaContainerName   = "cw-workspace"
	limaDockerSockPath  = "/var/run/docker.sock"
	limaDockerHostValue = "unix:///var/run/docker.sock"
)

func createLocalLimaInstance(instance *cwconfig.LocalInstance) error {
	if _, err := localLookPath("limactl"); err != nil {
		if installErr := offerLimaInstall(); installErr != nil {
			return installErr
		}
	}

	instance.LimaInstanceName = limaInstanceName(instance)
	instance.LimaVMType = defaultLimaVMType()
	instance.LimaMountType = defaultLimaMountType(instance.LimaVMType)

	name := limaInstanceName(instance)
	if err := ensureLimaClaudeState(instance); err != nil {
		return err
	}
	if err := ensureLimaGitConfig(instance); err != nil {
		return err
	}
	cleanup, err := ensureLimaVMForCreate(instance)
	if err != nil {
		return err
	}
	defer func() {
		if cleanup {
			_, _ = localRunCommand("limactl", "delete", "--force", name)
		}
	}()

	// Switch to rootful Docker so bind-mounted files preserve host UIDs.
	// The Lima template installs both rootful and rootless; rootless remaps
	// UIDs which makes 600-permission credential files unreadable.
	_, _ = localRunCommand("limactl", "shell", "--workdir", "/", name,
		"sudo", "systemctl", "start", "docker")

	// Wait for Docker readiness inside the VM
	fmt.Fprintf(os.Stderr, "  Waiting for Docker inside VM...\n")
	if err := localRunCommandStream("limactl", "shell", "--workdir", "/", name, "sudo", "docker", "info"); err != nil {
		return fmt.Errorf("docker not ready inside Lima VM: %v", err)
	}

	// Login to GHCR using host's gh auth token (best-effort)
	if tok := strings.TrimSpace(localGitHubToken()); tok != "" {
		_, _ = localRunCommand("limactl", "shell", "--workdir", "/", name, "sh", "-c",
			"sudo docker login ghcr.io -u oauth2 --password-stdin <<< "+strconv.Quote(tok))
	}

	// Pull the image
	image := instance.Image
	if image == "" {
		image = "ubuntu:latest"
	}
	fmt.Fprintf(os.Stderr, "  Pulling %s...\n", image)
	if err := localRunCommandStream("limactl", "shell", "--workdir", "/", name, "sudo", "docker", "pull", image); err != nil {
		return fmt.Errorf("docker pull %s: %v", image, err)
	}

	status, err := limaWorkspaceContainerStatus(instance)
	if err != nil {
		return err
	}
	dockerSockGID, err := limaDockerSocketGID(instance)
	if err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "  Starting workspace container...\n")
	switch status {
	case "missing":
		repoMountPath := limaRepoMountPath(instance)
		dockerArgs := []string{
			"sudo", "docker", "run", "-d",
			"--name", limaContainerName,
			"--network", "host",
			"--group-add", dockerSockGID,
			// Override the image's ENTRYPOINT so the sleep CMD runs directly.
			// Matches the docker backend: dev images often have an entrypoint
			// that writes SSH host keys into ~/.ssh (which we mount read-only).
			"--entrypoint", "/bin/sh",
			"-e", "DOCKER_HOST=" + limaDockerHostValue,
			"-v", limaDockerSockPath + ":" + limaDockerSockPath,
			"-v", repoMountPath + ":" + repoMountPath,
		}
		if token := strings.TrimSpace(localGitHubToken()); token != "" {
			dockerArgs = append(dockerArgs, "-e", "GH_TOKEN="+token)
		}
		if sshAuthSock := strings.TrimSpace(localSSHAuthSock()); sshAuthSock != "" {
			dockerArgs = append(dockerArgs, "-e", "SSH_AUTH_SOCK="+localSSHAuthSockPath)
		}
		dockerArgs = append(dockerArgs, limaContainerMountArgs(instance)...)
		dockerArgs = append(dockerArgs,
			"--workdir", repoMountPath,
			image,
			// Entrypoint was overridden to /bin/sh above, so "sleep infinity"
			// must be wrapped in `-c` for the shell to exec it.
			"-c", "sleep infinity",
		)
		if err := localRunCommandStream("limactl", append([]string{"shell", "--workdir", "/", name}, dockerArgs...)...); err != nil {
			return fmt.Errorf("docker run: %v", err)
		}
	case "running":
		// Container already exists and is running; adopt it.
	default:
		out, err := localRunCommand("limactl", "shell", "--workdir", "/", name, "sudo", "docker", "start", limaContainerName)
		if err != nil {
			return fmt.Errorf("docker start %s: %v\n%s", limaContainerName, err, strings.TrimSpace(string(out)))
		}
	}
	if err := ensureLimaDockerSocketGroup(instance, dockerSockGID); err != nil {
		return err
	}

	cleanup = false
	return nil
}

func ensureLimaVMForCreate(instance *cwconfig.LocalInstance) (bool, error) {
	name := limaInstanceName(instance)
	status, err := limaInstanceStatus(instance)
	if err != nil {
		return false, err
	}
	if status == "missing" {
		args := limaCreateCommandArgs(instance)
		fmt.Fprintf(os.Stderr, "  Creating Lima VM %q (this may download a VM image on first run)...\n", name)
		if err := localRunCommandStream("limactl", args...); err != nil {
			// Clean up zombie VM on boot failure.
			_, _ = localRunCommand("limactl", "delete", "--force", name)
			return false, fmt.Errorf("limactl %s: %v", strings.Join(args, " "), err)
		}
		return true, nil
	}

	fmt.Fprintf(os.Stderr, "  Reusing existing Lima VM %q...\n", name)
	if status != "running" {
		if err := ensureLimaSSHAgentForward(instance); err != nil {
			return false, err
		}
		if err := localRunCommandStream("limactl", "start", "--tty=false", name); err != nil {
			return false, fmt.Errorf("limactl start %s: %v", name, err)
		}
	}
	return false, nil
}

func limaDockerSocketGID(instance *cwconfig.LocalInstance) (string, error) {
	name := limaInstanceName(instance)
	out, err := localRunCommand("limactl", "shell", "--workdir", "/", name,
		"sudo", "stat", "-c", "%g", limaDockerSockPath)
	if err != nil {
		return "", fmt.Errorf("stat docker socket gid: %v\n%s", err, strings.TrimSpace(string(out)))
	}
	gid := strings.TrimSpace(string(out))
	if gid == "" {
		return "", fmt.Errorf("stat docker socket gid: empty output")
	}
	return gid, nil
}
func ensureLimaDockerSocketGroup(instance *cwconfig.LocalInstance, gid string) error {
	gid = strings.TrimSpace(gid)
	if gid == "" {
		return nil
	}

	name := limaInstanceName(instance)
	script := fmt.Sprintf(
		`gid=%q; if getent group "$gid" >/dev/null 2>&1; then exit 0; fi; groupadd -g "$gid" codewire-docker >/dev/null 2>&1 || groupadd -g "$gid" docker >/dev/null 2>&1 || true`,
		gid,
	)
	out, err := localRunCommand("limactl", "shell", "--workdir", "/", name,
		"sudo", "docker", "exec", "-u", "0", limaContainerName,
		"sh", "-lc", script)
	if err != nil {
		return fmt.Errorf("ensure docker socket group in %s: %v\n%s", limaContainerName, err, strings.TrimSpace(string(out)))
	}
	return nil
}

func limaWorkspaceContainerStatus(instance *cwconfig.LocalInstance) (string, error) {
	name := limaInstanceName(instance)
	out, err := localRunCommand("limactl", "shell", "--workdir", "/", name,
		"sudo", "docker", "inspect", "--format", "{{.State.Status}}", limaContainerName)
	if err != nil {
		lower := strings.ToLower(string(out))
		if strings.Contains(lower, "no such object") || strings.Contains(lower, "no such container") || strings.Contains(lower, "not found") {
			return "missing", nil
		}
		return "", fmt.Errorf("docker inspect %s: %v\n%s", limaContainerName, err, strings.TrimSpace(string(out)))
	}
	status := strings.ToLower(strings.TrimSpace(string(out)))
	if status == "" {
		return "unknown", nil
	}
	return status, nil
}

func startLocalLimaInstance(instance *cwconfig.LocalInstance) error {
	if _, err := localLookPath("limactl"); err != nil {
		if installErr := offerLimaInstall(); installErr != nil {
			return installErr
		}
	}
	name := limaInstanceName(instance)
	if err := ensureLimaClaudeState(instance); err != nil {
		return err
	}
	if err := ensureLimaGitConfig(instance); err != nil {
		return err
	}
	if err := ensureLimaSSHAgentForward(instance); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "  Starting Lima VM %q...\n", name)
	if err := localRunCommandStream("limactl", "start", "--tty=false", name); err != nil {
		return fmt.Errorf("limactl start %s: %v", name, err)
	}
	// Start rootful Docker and the workspace container
	_, _ = localRunCommand("limactl", "shell", "--workdir", "/", name, "sudo", "systemctl", "start", "docker")
	fmt.Fprintf(os.Stderr, "  Starting workspace container...\n")
	out, err := localRunCommand("limactl", "shell", "--workdir", "/", name, "sudo", "docker", "start", limaContainerName)
	if err != nil {
		return fmt.Errorf("docker start %s: %v\n%s", limaContainerName, err, strings.TrimSpace(string(out)))
	}
	dockerSockGID, err := limaDockerSocketGID(instance)
	if err != nil {
		return err
	}
	if err := ensureLimaDockerSocketGroup(instance, dockerSockGID); err != nil {
		return err
	}
	return nil
}

func stopLocalLimaInstance(instance *cwconfig.LocalInstance) error {
	if _, err := localLookPath("limactl"); err != nil {
		if installErr := offerLimaInstall(); installErr != nil {
			return installErr
		}
	}
	name := limaInstanceName(instance)
	// Stop the workspace container first
	_, _ = localRunCommand("limactl", "shell", "--workdir", "/", name, "sudo", "docker", "stop", limaContainerName)
	// Stop the VM
	out, err := localRunCommand("limactl", "stop", name)
	if err != nil {
		return fmt.Errorf("limactl stop %s: %v\n%s", name, err, strings.TrimSpace(string(out)))
	}
	return nil
}

func deleteLocalLimaInstance(instance *cwconfig.LocalInstance) error {
	if _, err := localLookPath("limactl"); err != nil {
		if installErr := offerLimaInstall(); installErr != nil {
			return installErr
		}
	}
	name := limaInstanceName(instance)
	out, err := localRunCommand("limactl", "delete", "--force", name)
	if err != nil {
		lower := strings.ToLower(string(out))
		if strings.Contains(lower, "not found") || strings.Contains(lower, "no such") {
			_ = os.RemoveAll(limaStateDir(instance))
			return nil
		}
		return fmt.Errorf("limactl delete --force %s: %v\n%s", name, err, strings.TrimSpace(string(out)))
	}
	if err := os.RemoveAll(limaStateDir(instance)); err != nil {
		return fmt.Errorf("remove Lima state dir: %w", err)
	}
	return nil
}

func limaInstanceStatus(instance *cwconfig.LocalInstance) (string, error) {
	if _, err := localLookPath("limactl"); err != nil {
		if installErr := offerLimaInstall(); installErr != nil {
			return "", installErr
		}
	}
	name := limaInstanceName(instance)
	out, err := localRunCommand("limactl", "list", "--format", "json")
	if err != nil {
		lower := strings.ToLower(string(out))
		if strings.Contains(lower, "not found") || strings.Contains(lower, "no such") || strings.Contains(lower, "no instance matching") || strings.Contains(lower, "unmatched instances") {
			return "missing", nil
		}
		return "", fmt.Errorf("limactl list --format json: %v\n%s", err, strings.TrimSpace(string(out)))
	}

	data := bytes.TrimSpace(out)
	if len(data) == 0 {
		return "missing", nil
	}

	var entries []limaListEntry
	if data[0] == '[' {
		if err := json.Unmarshal(data, &entries); err != nil {
			return "", fmt.Errorf("parse limactl list output: %w", err)
		}
	} else {
		for _, line := range bytes.Split(data, []byte{'\n'}) {
			line = bytes.TrimSpace(line)
			if len(line) == 0 {
				continue
			}
			if line[0] != '{' {
				continue
			}
			var entry limaListEntry
			if err := json.Unmarshal(line, &entry); err != nil {
				return "", fmt.Errorf("parse limactl list output: %w", err)
			}
			entries = append(entries, entry)
		}
	}

	for _, entry := range entries {
		if strings.TrimSpace(entry.Name) == name {
			status := strings.ToLower(strings.TrimSpace(entry.Status))
			if status == "" {
				return "unknown", nil
			}
			return status, nil
		}
	}

	return "missing", nil
}
