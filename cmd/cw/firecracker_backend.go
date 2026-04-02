package main

import (
	"fmt"
	"os"
	osExec "os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"

	cwconfig "github.com/codewiresh/codewire/internal/config"
)

const (
	fcDefaultBootArgs = "console=ttyS0 reboot=k panic=1 pci=off"
	fcDefaultVCPUs    = 2
	fcDefaultMemMB    = 512
)

// offerFirecrackerInstall prompts the user to install Firecracker automatically.
func offerFirecrackerInstall() error {
	fmt.Fprintln(os.Stderr, "Firecracker is not installed.")
	ok, err := promptConfirm("Install Firecracker now?")
	if err != nil {
		return fmt.Errorf("firecracker not found in PATH")
	}
	if !ok {
		return fmt.Errorf("firecracker not found in PATH")
	}

	fmt.Fprintf(os.Stderr, "\n  Fetching latest Firecracker release...\n")

	// Detect architecture
	arch := "x86_64"
	if runtime.GOARCH == "arm64" {
		arch = "aarch64"
	}

	// Get latest version tag
	out, err := localRunCommand("curl", "-fsSL",
		"https://api.github.com/repos/firecracker-microvm/firecracker/releases/latest")
	if err != nil {
		return fmt.Errorf("failed to fetch latest release: %w", err)
	}
	// Extract tag_name from JSON (avoid importing encoding/json just for this)
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
		return fmt.Errorf("could not determine latest firecracker version")
	}

	fmt.Fprintf(os.Stderr, "  Installing Firecracker %s (%s)...\n", version, arch)

	// Download and extract
	url := fmt.Sprintf("https://github.com/firecracker-microvm/firecracker/releases/download/%s/firecracker-%s-%s.tgz", version, version, arch)
	tmpDir := filepath.Join(os.TempDir(), "cw-fc-install")
	os.MkdirAll(tmpDir, 0o755)
	defer os.RemoveAll(tmpDir)

	out, err = localRunCommand("sh", "-c",
		fmt.Sprintf("curl -fsSL %q | tar xz -C %q", url, tmpDir))
	if err != nil {
		return fmt.Errorf("download failed: %v\n%s", err, strings.TrimSpace(string(out)))
	}

	// Find the binary
	binaryName := fmt.Sprintf("firecracker-%s-%s", version, arch)
	binaryPath := filepath.Join(tmpDir, fmt.Sprintf("release-%s-%s", version, arch), binaryName)
	if _, statErr := os.Stat(binaryPath); statErr != nil {
		return fmt.Errorf("binary not found at expected path: %s", binaryPath)
	}

	// Install to /usr/local/bin
	fmt.Fprintf(os.Stderr, "  Installing to /usr/local/bin (requires sudo)...\n")
	out, err = localRunCommand("sudo", "install", "-o", "root", "-g", "root", "-m", "0755",
		binaryPath, "/usr/local/bin/firecracker")
	if err != nil {
		return fmt.Errorf("install failed: %v\n%s\n\n  You can install manually:\n    sudo cp %s /usr/local/bin/firecracker",
			err, strings.TrimSpace(string(out)), binaryPath)
	}

	// Verify
	if _, err := localLookPath("firecracker"); err != nil {
		return fmt.Errorf("firecracker installed but not found in PATH")
	}

	fmt.Fprintf(os.Stderr, "  Firecracker %s installed.\n\n", version)
	return nil
}

// createLocalFirecrackerInstance creates and boots a Firecracker microVM.
func createLocalFirecrackerInstance(instance *cwconfig.LocalInstance) error {
	// Prerequisites
	if _, err := localLookPath("firecracker"); err != nil {
		if installErr := offerFirecrackerInstall(); installErr != nil {
			return installErr
		}
	}
	if _, err := os.Stat("/dev/kvm"); err != nil {
		return fmt.Errorf("/dev/kvm not found\n\n" +
			"  Firecracker requires hardware virtualization (KVM).\n" +
			"  Ensure your CPU supports VT-x/AMD-V and KVM is enabled:\n" +
			"    sudo modprobe kvm\n" +
			"    sudo modprobe kvm_intel  # or kvm_amd")
	}
	f, err := os.OpenFile("/dev/kvm", os.O_RDWR, 0)
	if err != nil {
		fmt.Fprintln(os.Stderr, "/dev/kvm exists but is not accessible (permission denied).")
		ok, promptErr := promptConfirm("Add your user to the kvm group? (requires sudo)")
		if promptErr != nil || !ok {
			return fmt.Errorf("/dev/kvm not accessible\n  Run manually: sudo usermod -aG kvm $USER && newgrp kvm")
		}
		out, cmdErr := localRunCommand("sudo", "usermod", "-aG", "kvm", os.Getenv("USER"))
		if cmdErr != nil {
			return fmt.Errorf("failed to add user to kvm group: %v\n%s", cmdErr, strings.TrimSpace(string(out)))
		}
		fmt.Fprintf(os.Stderr, "  Added to kvm group. You may need to log out and back in.\n")
		fmt.Fprintf(os.Stderr, "  Trying newgrp kvm...\n")
		// Re-check after group add (newgrp can't help us in-process, but try opening again)
		f, err = os.OpenFile("/dev/kvm", os.O_RDWR, 0)
		if err != nil {
			return fmt.Errorf("/dev/kvm still not accessible after group change\n  Log out and back in, then retry")
		}
	}
	f.Close()

	dd := dataDir()

	// Download kernel if needed
	kernelPath, err := ensureFirecrackerKernel(dd)
	if err != nil {
		return fmt.Errorf("kernel: %w", err)
	}

	// Build rootfs from OCI image
	diskGB := instance.Disk
	if diskGB <= 0 {
		diskGB = 4
	}
	rootfsPath, err := buildFirecrackerRootfs(instance.Image, instance.Name, dd, diskGB)
	if err != nil {
		return fmt.Errorf("rootfs: %w", err)
	}

	// Start Firecracker process
	instance.KernelPath = kernelPath
	instance.RootfsPath = rootfsPath

	if err := startFirecrackerProcess(instance, dd); err != nil {
		// Cleanup on failure
		fcRuntimeDir := filepath.Join(dd, "firecracker", instance.Name)
		os.RemoveAll(fcRuntimeDir)
		return err
	}

	return nil
}

// startFirecrackerProcess launches the firecracker binary and configures it via API.
func startFirecrackerProcess(instance *cwconfig.LocalInstance, dataDir string) error {
	runtimeDir := filepath.Join(dataDir, "firecracker", instance.Name)
	if err := os.MkdirAll(runtimeDir, 0o755); err != nil {
		return fmt.Errorf("create runtime dir: %w", err)
	}

	socketPath := filepath.Join(runtimeDir, "api.sock")
	// Remove stale socket
	os.Remove(socketPath)

	logPath := filepath.Join(runtimeDir, "firecracker.log")
	logFile, err := os.Create(logPath)
	if err != nil {
		return fmt.Errorf("create log file: %w", err)
	}

	// Start firecracker process
	cmd := osExec.Command("firecracker", "--api-sock", socketPath)
	cmd.Stdout = logFile
	cmd.Stderr = logFile
	// Detach from parent process group so it survives CLI exit
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}

	if err := cmd.Start(); err != nil {
		logFile.Close()
		return fmt.Errorf("start firecracker: %w", err)
	}
	logFile.Close()

	instance.FirecrackerPID = cmd.Process.Pid
	instance.FirecrackerSocket = socketPath

	// Wait for socket to be ready
	if err := fcWaitForSocket(socketPath, 5*time.Second); err != nil {
		cmd.Process.Kill()
		return err
	}

	// Configure via API
	vcpus := fcDefaultVCPUs
	if instance.CPU > 0 {
		vcpus = instance.CPU / 1000
		if vcpus < 1 {
			vcpus = 1
		}
	}
	memMB := fcDefaultMemMB
	if instance.Memory > 0 {
		memMB = instance.Memory
	}

	if err := fcPutMachineConfig(socketPath, vcpus, memMB); err != nil {
		cmd.Process.Kill()
		return fmt.Errorf("configure machine: %w", err)
	}

	if err := fcPutBootSource(socketPath, instance.KernelPath, fcDefaultBootArgs); err != nil {
		cmd.Process.Kill()
		return fmt.Errorf("configure boot source: %w", err)
	}

	if err := fcPutDrive(socketPath, "rootfs", instance.RootfsPath); err != nil {
		cmd.Process.Kill()
		return fmt.Errorf("configure root drive: %w", err)
	}

	// Configure vsock for guest agent communication
	if err := fcPutVsock(socketPath, 3); err != nil {
		cmd.Process.Kill()
		return fmt.Errorf("configure vsock: %w", err)
	}

	// Boot the VM
	if err := fcPutAction(socketPath, "InstanceStart"); err != nil {
		cmd.Process.Kill()
		return fmt.Errorf("start instance: %w", err)
	}

	// Release the process so it runs independently
	cmd.Process.Release()

	return nil
}

// stopLocalFirecrackerInstance gracefully stops a Firecracker VM.
func stopLocalFirecrackerInstance(instance *cwconfig.LocalInstance) error {
	if instance.FirecrackerPID == 0 {
		return nil
	}

	// Check if process is alive
	if err := syscall.Kill(instance.FirecrackerPID, 0); err != nil {
		instance.FirecrackerPID = 0
		return nil // already dead
	}

	// Try graceful shutdown
	if instance.FirecrackerSocket != "" {
		_ = fcPutAction(instance.FirecrackerSocket, "SendCtrlAltDel")
	}

	// Wait up to 3 seconds for graceful shutdown
	for i := 0; i < 30; i++ {
		time.Sleep(100 * time.Millisecond)
		if err := syscall.Kill(instance.FirecrackerPID, 0); err != nil {
			instance.FirecrackerPID = 0
			return nil
		}
	}

	// Force kill
	syscall.Kill(instance.FirecrackerPID, syscall.SIGKILL)
	instance.FirecrackerPID = 0
	return nil
}

// startLocalFirecrackerInstance starts a previously stopped Firecracker VM.
// Firecracker doesn't support restart -- must launch a new process.
func startLocalFirecrackerInstance(instance *cwconfig.LocalInstance) error {
	// Verify rootfs exists
	if instance.RootfsPath == "" {
		return fmt.Errorf("no rootfs path recorded for instance %q", instance.Name)
	}
	if _, err := os.Stat(instance.RootfsPath); err != nil {
		return fmt.Errorf("rootfs not found at %s: %w", instance.RootfsPath, err)
	}
	if instance.KernelPath == "" {
		var kerr error
		instance.KernelPath, kerr = ensureFirecrackerKernel(dataDir())
		if kerr != nil {
			return fmt.Errorf("kernel: %w", kerr)
		}
	}

	return startFirecrackerProcess(instance, dataDir())
}

// deleteLocalFirecrackerInstance stops and removes a Firecracker VM and its artifacts.
func deleteLocalFirecrackerInstance(instance *cwconfig.LocalInstance) error {
	// Stop if running
	_ = stopLocalFirecrackerInstance(instance)

	// Remove runtime directory (rootfs, socket, logs)
	runtimeDir := filepath.Join(dataDir(), "firecracker", instance.Name)
	if err := os.RemoveAll(runtimeDir); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("remove runtime dir: %w", err)
	}

	return nil
}

// firecrackerInstanceStatus returns the status of a Firecracker VM.
func firecrackerInstanceStatus(instance *cwconfig.LocalInstance) (string, error) {
	if instance.FirecrackerPID == 0 {
		// Check if rootfs exists (instance was created but not running)
		if instance.RootfsPath != "" {
			if _, err := os.Stat(instance.RootfsPath); err == nil {
				return "stopped", nil
			}
		}
		return "missing", nil
	}

	// Check if process is alive
	if err := syscall.Kill(instance.FirecrackerPID, 0); err != nil {
		return "stopped", nil
	}

	// Query Firecracker API for state
	if instance.FirecrackerSocket != "" {
		state, err := fcGetInfo(instance.FirecrackerSocket)
		if err == nil {
			return strings.ToLower(state), nil
		}
	}

	return "running", nil
}
