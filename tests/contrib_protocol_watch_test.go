package tests

import (
	"encoding/json"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestContribProtocolWatchParsesCodexTurnEvents(t *testing.T) {
	scriptPath := filepath.Join("..", "contrib", "protocol-watch.py")
	descriptorPath := filepath.Join("..", "contrib", "protocols", "codex.json")

	cmd := exec.Command("python3", scriptPath, descriptorPath)
	cmd.Stdin = strings.NewReader(strings.Join([]string{
		`{"jsonrpc":"2.0","method":"turn/started","params":{"threadId":"thread-1","turnId":"turn-1"}}`,
		`{"jsonrpc":"2.0","method":"tokenUsage/updated","params":{"inputTokens":10,"outputTokens":20}}`,
		`{"jsonrpc":"2.0","method":"other/event","params":{}}`,
	}, "\n"))

	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("protocol-watch.py failed: %v", err)
	}

	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	if len(lines) != 2 {
		t.Fatalf("lines = %d, want 2 (%q)", len(lines), string(out))
	}

	var started map[string]any
	if err := json.Unmarshal([]byte(lines[0]), &started); err != nil {
		t.Fatalf("unmarshal started event: %v", err)
	}
	if started["method"] != "turn/started" {
		t.Fatalf("method = %v, want turn/started", started["method"])
	}
	if started["state"] != "started" {
		t.Fatalf("state = %v, want started", started["state"])
	}
	if started["turn_id"] != "turn-1" {
		t.Fatalf("turn_id = %v, want turn-1", started["turn_id"])
	}
	if started["thread_id"] != "thread-1" {
		t.Fatalf("thread_id = %v, want thread-1", started["thread_id"])
	}

	var progress map[string]any
	if err := json.Unmarshal([]byte(lines[1]), &progress); err != nil {
		t.Fatalf("unmarshal progress event: %v", err)
	}
	if progress["method"] != "tokenUsage/updated" {
		t.Fatalf("method = %v, want tokenUsage/updated", progress["method"])
	}
	if progress["state"] != "running" {
		t.Fatalf("state = %v, want running", progress["state"])
	}
	if progress["kind"] != "progress" {
		t.Fatalf("kind = %v, want progress", progress["kind"])
	}
	if _, ok := progress["token_usage"].(map[string]any); !ok {
		t.Fatalf("token_usage missing from %#v", progress)
	}
}
