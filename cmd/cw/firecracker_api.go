package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"
)

// fcClient returns an HTTP client that connects to a Firecracker Unix socket.
func fcClient(socketPath string) *http.Client {
	return &http.Client{
		Transport: &http.Transport{
			DialContext: func(_ context.Context, _, _ string) (net.Conn, error) {
				return net.DialTimeout("unix", socketPath, 5*time.Second)
			},
		},
		Timeout: 10 * time.Second,
	}
}

func fcPut(socketPath, path string, body any) error {
	data, err := json.Marshal(body)
	if err != nil {
		return fmt.Errorf("marshal: %w", err)
	}

	req, err := http.NewRequest("PUT", "http://localhost"+path, bytes.NewReader(data))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := fcClient(socketPath).Do(req)
	if err != nil {
		return fmt.Errorf("firecracker API %s: %w", path, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 300 {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("firecracker API %s: %d %s", path, resp.StatusCode, string(body))
	}
	return nil
}

// fcPutBootSource configures the kernel and boot arguments.
func fcPutBootSource(socketPath, kernelPath, bootArgs string) error {
	return fcPut(socketPath, "/boot-source", map[string]string{
		"kernel_image_path": kernelPath,
		"boot_args":         bootArgs,
	})
}

// fcPutDrive attaches a root filesystem drive.
func fcPutDrive(socketPath, driveID, rootfsPath string) error {
	return fcPut(socketPath, "/drives/"+driveID, map[string]any{
		"drive_id":       driveID,
		"path_on_host":   rootfsPath,
		"is_root_device": true,
		"is_read_only":   false,
	})
}

// fcPutMachineConfig sets vCPU count and memory.
func fcPutMachineConfig(socketPath string, vcpus, memMB int) error {
	return fcPut(socketPath, "/machine-config", map[string]int{
		"vcpu_count":  vcpus,
		"mem_size_mib": memMB,
	})
}

// fcPutVsock configures a virtio-vsock device with the given guest CID.
func fcPutVsock(socketPath string, guestCID int) error {
	return fcPut(socketPath, "/vsock", map[string]any{
		"guest_cid": guestCID,
		"uds_path":  socketPath + ".vsock",
	})
}

// fcPutAction sends an action (InstanceStart, SendCtrlAltDel).
func fcPutAction(socketPath, actionType string) error {
	return fcPut(socketPath, "/actions", map[string]string{
		"action_type": actionType,
	})
}

// fcGetInfo queries the Firecracker instance state.
func fcGetInfo(socketPath string) (string, error) {
	resp, err := fcClient(socketPath).Get("http://localhost/")
	if err != nil {
		return "", fmt.Errorf("firecracker API GET /: %w", err)
	}
	defer resp.Body.Close()

	var info struct {
		State string `json:"state"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&info); err != nil {
		return "", fmt.Errorf("decode instance info: %w", err)
	}
	return info.State, nil
}

// fcWaitForSocket polls until the Firecracker API socket is ready.
func fcWaitForSocket(socketPath string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("unix", socketPath, 100*time.Millisecond)
		if err == nil {
			conn.Close()
			return nil
		}
		time.Sleep(50 * time.Millisecond)
	}
	return fmt.Errorf("firecracker socket %s not ready after %s", socketPath, timeout)
}
