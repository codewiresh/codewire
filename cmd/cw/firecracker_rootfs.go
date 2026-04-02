package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// buildFirecrackerRootfs converts an OCI image to an ext4 rootfs using Docker.
// Returns the path to the rootfs file.
func buildFirecrackerRootfs(image, instanceName, dataDir string, diskGB int, agentBinaryPath string) (string, error) {
	if _, err := localLookPath("docker"); err != nil {
		return "", fmt.Errorf("docker is required to build firecracker rootfs: %w", err)
	}

	dir := filepath.Join(dataDir, "firecracker", instanceName)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", fmt.Errorf("create instance dir: %w", err)
	}

	rootfsPath := filepath.Join(dir, "rootfs.ext4")
	tarPath := filepath.Join(dir, "rootfs.tar")

	// Step 1: Create temporary container from image
	fmt.Fprintf(os.Stderr, "  Exporting image filesystem...\n")
	out, err := localRunCommand("docker", "create", "--name", "cw-rootfs-tmp-"+instanceName, image)
	if err != nil {
		return "", fmt.Errorf("docker create: %v\n%s", err, strings.TrimSpace(string(out)))
	}
	containerID := strings.TrimSpace(string(out))

	defer func() {
		localRunCommand("docker", "rm", "-f", containerID)
	}()

	// Step 2: Export filesystem to tarball
	out, err = localRunCommand("docker", "export", "-o", tarPath, containerID)
	if err != nil {
		return "", fmt.Errorf("docker export: %v\n%s", err, strings.TrimSpace(string(out)))
	}

	// Step 3: Build ext4 rootfs
	if diskGB <= 0 {
		diskGB = 4
	}
	sizeMB := diskGB * 1024

	fmt.Fprintf(os.Stderr, "  Building %dGB rootfs...\n", diskGB)

	// Create sparse file
	out, err = localRunCommand("dd", "if=/dev/zero", fmt.Sprintf("of=%s", rootfsPath),
		"bs=1M", "count=0", fmt.Sprintf("seek=%d", sizeMB))
	if err != nil {
		return "", fmt.Errorf("create sparse file: %v\n%s", err, strings.TrimSpace(string(out)))
	}

	// Format as ext4, then mount and populate using the host's mount capabilities.
	// We need loopback mount, so use a Docker container with /dev access.
	out, err = localRunCommand("docker", "run", "--rm", "--privileged",
		"--device", "/dev/loop-control",
		"-v", "/dev:/dev",
		"-v", rootfsPath+":/rootfs.ext4",
		"-v", tarPath+":/rootfs.tar",
		"-v", agentBinaryPath+":/cw-guest-agent",
		"alpine:latest",
		"sh", "-c",
		"apk add --no-cache e2fsprogs losetup > /dev/null 2>&1; "+
			"mkfs.ext4 -q -F /rootfs.ext4 && "+
			"LOOP=$(losetup -f --show /rootfs.ext4) && "+
			"mkdir -p /mnt/rootfs && "+
			"mount $LOOP /mnt/rootfs && "+
			"tar xf /rootfs.tar -C /mnt/rootfs 2>/dev/null; "+
			"cp /cw-guest-agent /mnt/rootfs/usr/local/bin/cw-guest-agent && "+
			"chmod 755 /mnt/rootfs/usr/local/bin/cw-guest-agent && "+
			"printf '#!/bin/sh\\nmount -t proc proc /proc 2>/dev/null\\nmount -t sysfs sys /sys 2>/dev/null\\nmount -t devtmpfs devtmpfs /dev 2>/dev/null\\n/usr/local/bin/cw-guest-agent &\\nexec /bin/sh\\n' > /mnt/rootfs/usr/local/bin/cw-init && "+
			"chmod 755 /mnt/rootfs/usr/local/bin/cw-init && "+
			"sync && umount /mnt/rootfs && losetup -d $LOOP",
	)
	if err != nil {
		os.Remove(rootfsPath)
		return "", fmt.Errorf("build rootfs: %v\n%s", err, strings.TrimSpace(string(out)))
	}

	// Cleanup tarball
	os.Remove(tarPath)

	return rootfsPath, nil
}
