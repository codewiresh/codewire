//go:build integration

package main

import (
	"os"
	"testing"
)

func TestFirecrackerLifecycle(t *testing.T) {
	if os.Getenv("CODEWIRE_TEST_FIRECRACKER") != "1" {
		t.Skip("set CODEWIRE_TEST_FIRECRACKER=1 to run")
	}
	if _, err := os.Stat("/dev/kvm"); err != nil {
		t.Skip("no /dev/kvm")
	}
	if _, err := localLookPath("firecracker"); err != nil {
		t.Skip("firecracker not in PATH")
	}

	// TODO: Full integration test
	// 1. Create instance with alpine image
	// 2. Verify status is "running"
	// 3. Exec "uname -a" via guest agent
	// 4. Stop instance, verify "stopped"
	// 5. Start instance, verify "running"
	// 6. Delete instance, verify gone
	t.Log("Firecracker integration test skeleton - implement when CI has /dev/kvm")
}
