package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
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

func limaCreateCommandArgs(instance *cwconfig.LocalInstance) []string {
	vmType := strings.TrimSpace(instance.LimaVMType)
	if vmType == "" {
		vmType = defaultLimaVMType()
	}
	mountType := strings.TrimSpace(instance.LimaMountType)
	if mountType == "" {
		mountType = defaultLimaMountType(vmType)
	}

	homeDir, _ := localUserHomeDir()
	ghConfigDir := filepath.Join(homeDir, ".config", "gh")
	sshDir := filepath.Join(homeDir, ".ssh")

	mounts := fmt.Sprintf(
		`{"location":%s,"mountPoint":"/workspace","writable":true},{"location":%s,"mountPoint":"/home/{{.User}}.guest/.config/gh","writable":false},{"location":%s,"mountPoint":"/mnt/host-ssh","writable":false}`,
		strconv.Quote(instance.RepoPath),
		strconv.Quote(ghConfigDir),
		strconv.Quote(sshDir),
	)

	claudeDir := filepath.Join(homeDir, ".claude")
	if _, err := localOsStat(claudeDir); err == nil {
		mounts += fmt.Sprintf(
			`,{"location":%s,"mountPoint":"/home/{{.User}}.guest/.claude","writable":true}`,
			strconv.Quote(claudeDir),
		)
	}
	codexDir := filepath.Join(homeDir, ".codex")
	if _, err := localOsStat(codexDir); err == nil {
		mounts += fmt.Sprintf(
			`,{"location":%s,"mountPoint":"/home/{{.User}}.guest/.codex","writable":true}`,
			strconv.Quote(codexDir),
		)
	}

	mountSet := ".mounts=[" + mounts + "]"

	args := []string{
		"start",
		"--tty=false",
		"--name", limaInstanceName(instance),
		"--vm-type", vmType,
		"--mount-type", mountType,
		"--mount-none",
		"--set", mountSet,
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
		if port.Port <= 0 {
			continue
		}
		args = append(args, "--port-forward", fmt.Sprintf("%d:%d,static=true", port.Port, port.Port))
	}

	return append(args, "template:docker")
}

const limaContainerName = "cw-workspace"

func createLocalLimaInstance(instance *cwconfig.LocalInstance) error {
	if _, err := localLookPath("limactl"); err != nil {
		if installErr := offerLimaInstall(); installErr != nil {
			return installErr
		}
	}

	instance.LimaInstanceName = limaInstanceName(instance)
	instance.LimaVMType = defaultLimaVMType()
	instance.LimaMountType = defaultLimaMountType(instance.LimaVMType)

	// Boot the VM with Docker template
	args := limaCreateCommandArgs(instance)
	fmt.Fprintf(os.Stderr, "  Creating Lima VM %q (this may download a VM image on first run)...\n", limaInstanceName(instance))
	if err := localRunCommandStream("limactl", args...); err != nil {
		// Clean up zombie VM on boot failure
		_, _ = localRunCommand("limactl", "delete", "--force", limaInstanceName(instance))
		return fmt.Errorf("limactl %s: %v", strings.Join(args, " "), err)
	}

	name := limaInstanceName(instance)

	cleanup := true
	defer func() {
		if cleanup {
			_, _ = localRunCommand("limactl", "delete", "--force", name)
		}
	}()

	// Wait for Docker readiness inside the VM
	fmt.Fprintf(os.Stderr, "  Waiting for Docker inside VM...\n")
	if err := localRunCommandStream("limactl", "shell", "--workdir", "/", name, "docker", "info"); err != nil {
		return fmt.Errorf("docker not ready inside Lima VM: %v", err)
	}

	// Login to GHCR using host's gh auth token (best-effort)
	if ghPath, ghErr := localLookPath("gh"); ghErr == nil {
		if token, tokenErr := localRunCommand(ghPath, "auth", "token"); tokenErr == nil {
			tok := strings.TrimSpace(string(token))
			if tok != "" {
				_, _ = localRunCommand("limactl", "shell", "--workdir", "/", name, "sh", "-c",
					"docker login ghcr.io -u oauth2 --password-stdin <<< "+strconv.Quote(tok))
			}
		}
	}

	// Pull the image
	image := instance.Image
	if image == "" {
		image = "ubuntu:latest"
	}
	fmt.Fprintf(os.Stderr, "  Pulling %s...\n", image)
	if err := localRunCommandStream("limactl", "shell", "--workdir", "/", name, "docker", "pull", image); err != nil {
		return fmt.Errorf("docker pull %s: %v", image, err)
	}

	// Run the container with the workspace mounted
	fmt.Fprintf(os.Stderr, "  Starting workspace container...\n")
	dockerArgs := []string{
		"docker", "run", "-d",
		"--name", limaContainerName,
		"-v", "/workspace:/workspace",
	}
	vmUser := os.Getenv("USER")
	vmHome := filepath.Join("/home", vmUser+".guest")
	claudeDir := filepath.Join(vmHome, ".claude")
	if homeDir, err := localUserHomeDir(); err == nil {
		hostClaude := filepath.Join(homeDir, ".claude")
		if _, statErr := localOsStat(hostClaude); statErr == nil {
			dockerArgs = append(dockerArgs, "-v", claudeDir+":/home/codewire/.claude")
		}
	}
	dockerArgs = append(dockerArgs,
		"-v", filepath.Join(vmHome, ".config", "gh")+":/home/codewire/.config/gh:ro",
		"-v", "/mnt/host-ssh:/home/codewire/.ssh:ro",
		"-v", filepath.Join(vmHome, ".codex")+":/home/codewire/.codex",
	)
	dockerArgs = append(dockerArgs,
		"--workdir", "/workspace",
		image,
		"sleep", "infinity",
	)
	if err := localRunCommandStream("limactl", append([]string{"shell", "--workdir", "/", name}, dockerArgs...)...); err != nil {
		return fmt.Errorf("docker run: %v", err)
	}

	// Copy ~/.claude.json into the container (Lima mounts only support directories).
	if homeDir, err := localUserHomeDir(); err == nil {
		claudeJSON := filepath.Join(homeDir, ".claude.json")
		if _, statErr := localOsStat(claudeJSON); statErr == nil {
			vmTmp := "/tmp/claude.json"
			if _, cpErr := localRunCommand("limactl", "copy", claudeJSON, name+":"+vmTmp); cpErr == nil {
				_, _ = localRunCommand("limactl", "shell", "--workdir", "/", name,
					"docker", "cp", vmTmp, limaContainerName+":/home/codewire/.claude.json")
				_, _ = localRunCommand("limactl", "shell", "--workdir", "/", name, "rm", "-f", vmTmp)
			}
		}
	}

	cleanup = false
	return nil
}

func startLocalLimaInstance(instance *cwconfig.LocalInstance) error {
	if _, err := localLookPath("limactl"); err != nil {
		if installErr := offerLimaInstall(); installErr != nil {
			return installErr
		}
	}
	name := limaInstanceName(instance)
	fmt.Fprintf(os.Stderr, "  Starting Lima VM %q...\n", name)
	if err := localRunCommandStream("limactl", "start", "--tty=false", name); err != nil {
		return fmt.Errorf("limactl start %s: %v", name, err)
	}
	// Start the workspace container
	fmt.Fprintf(os.Stderr, "  Starting workspace container...\n")
	out, err := localRunCommand("limactl", "shell", "--workdir", "/", name, "docker", "start", limaContainerName)
	if err != nil {
		return fmt.Errorf("docker start %s: %v\n%s", limaContainerName, err, strings.TrimSpace(string(out)))
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
	_, _ = localRunCommand("limactl", "shell", "--workdir", "/", name, "docker", "stop", limaContainerName)
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
			return nil
		}
		return fmt.Errorf("limactl delete --force %s: %v\n%s", name, err, strings.TrimSpace(string(out)))
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
	out, err := localRunCommand("limactl", "list", "--format", "json", name)
	if err != nil {
		lower := strings.ToLower(string(out))
		if strings.Contains(lower, "not found") || strings.Contains(lower, "no such") {
			return "missing", nil
		}
		return "", fmt.Errorf("limactl list --format json %s: %v\n%s", name, err, strings.TrimSpace(string(out)))
	}

	data := bytes.TrimSpace(out)
	if len(data) == 0 {
		return "missing", nil
	}

	var entries []limaListEntry
	if data[0] == '{' {
		var entry limaListEntry
		if err := json.Unmarshal(data, &entry); err != nil {
			return "", fmt.Errorf("parse limactl list output: %w", err)
		}
		entries = []limaListEntry{entry}
	} else {
		if err := json.Unmarshal(data, &entries); err != nil {
			return "", fmt.Errorf("parse limactl list output: %w", err)
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
