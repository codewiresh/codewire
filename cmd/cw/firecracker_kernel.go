package main

import (
	"crypto/sha256"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
)

// Firecracker-compatible kernel builds from Amazon's CI artifacts.
var firecrackerKernels = map[string]struct {
	url    string
	sha256 string
}{
	"amd64": {
		url:    "https://s3.amazonaws.com/spec.ccfc.min/firecracker-ci/v1.11/x86_64/vmlinux-6.1.102",
		sha256: "cf42303c29e8c4a02798f357ba056c5567baf074aaed4eec78c997fb9df08cf9",
	},
	"arm64": {
		url:    "https://s3.amazonaws.com/spec.ccfc.min/firecracker-ci/v1.11/aarch64/vmlinux-6.1.102",
		sha256: "",
	},
}

// ensureFirecrackerKernel downloads the kernel if not cached and returns its path.
func ensureFirecrackerKernel(dataDir string) (string, error) {
	arch := runtime.GOARCH
	kernel, ok := firecrackerKernels[arch]
	if !ok {
		return "", fmt.Errorf("no firecracker kernel available for %s", arch)
	}

	dir := filepath.Join(dataDir, "firecracker")
	kernelPath := filepath.Join(dir, "vmlinux")

	// Return cached kernel if it exists
	if _, err := os.Stat(kernelPath); err == nil {
		return kernelPath, nil
	}

	fmt.Fprintf(os.Stderr, "  Downloading Firecracker kernel for %s...\n", arch)

	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", fmt.Errorf("create kernel dir: %w", err)
	}

	resp, err := http.Get(kernel.url)
	if err != nil {
		return "", fmt.Errorf("download kernel: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("download kernel: HTTP %d", resp.StatusCode)
	}

	tmpPath := kernelPath + ".tmp"
	f, err := os.Create(tmpPath)
	if err != nil {
		return "", fmt.Errorf("create kernel file: %w", err)
	}

	hasher := sha256.New()
	written, err := io.Copy(io.MultiWriter(f, hasher), resp.Body)
	f.Close()
	if err != nil {
		os.Remove(tmpPath)
		return "", fmt.Errorf("write kernel: %w", err)
	}

	// Validate checksum if configured
	if kernel.sha256 != "" {
		got := fmt.Sprintf("%x", hasher.Sum(nil))
		if got != kernel.sha256 {
			os.Remove(tmpPath)
			return "", fmt.Errorf("kernel checksum mismatch: got %s, want %s", got, kernel.sha256)
		}
	}

	if err := os.Rename(tmpPath, kernelPath); err != nil {
		os.Remove(tmpPath)
		return "", fmt.Errorf("install kernel: %w", err)
	}

	fmt.Fprintf(os.Stderr, "  Kernel downloaded (%d MB)\n", written/1024/1024)
	return kernelPath, nil
}
