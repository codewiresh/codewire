package main

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	cwconfig "github.com/codewiresh/codewire/internal/config"
	"github.com/codewiresh/codewire/internal/platform"
	"github.com/codewiresh/codewire/internal/protocol"
)

func TestListEnvironmentRunsUsesLocalSessionListing(t *testing.T) {
	var (
		gotMethod string
		gotPath   string
		gotBody   platform.ExecRequest
	)

	client := &platform.Client{
		ServerURL:    "https://example.invalid",
		SessionToken: "session-token",
		HTTP: &http.Client{
			Timeout: 5 * time.Second,
			Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
				gotMethod = r.Method
				gotPath = r.URL.Path
				body, err := io.ReadAll(r.Body)
				if err != nil {
					t.Fatalf("read request body: %v", err)
				}
				if err := json.Unmarshal(body, &gotBody); err != nil {
					t.Fatalf("decode request body: %v", err)
				}

				respBody, _ := json.Marshal(platform.ExecResult{
					ExitCode: 0,
					Stdout: `[{
						"id": 7,
						"name": "planner",
						"prompt": "claude -p plan",
						"created_at": "2026-03-16T12:00:00Z",
						"status": "running",
						"attached_count": 0
					}]`,
				})
				return &http.Response{
					StatusCode: http.StatusOK,
					Header:     http.Header{"Content-Type": []string{"application/json"}},
					Body:       io.NopCloser(bytes.NewReader(respBody)),
				}, nil
			}),
		},
	}

	env := platform.Environment{
		ID:        "env_123",
		Type:      "sandbox",
		State:     "running",
		CreatedAt: "2026-03-16T10:00:00Z",
	}

	sessions, lookup, errMsg := listEnvironmentRuns(client, "org_123", env)
	if lookup != "available" {
		t.Fatalf("lookup = %q, want available", lookup)
	}
	if errMsg != "" {
		t.Fatalf("errMsg = %q, want empty", errMsg)
	}
	if len(sessions) != 1 || sessions[0].Name != "planner" {
		t.Fatalf("sessions = %#v, want planner session", sessions)
	}
	if gotMethod != http.MethodPost {
		t.Fatalf("method = %q, want POST", gotMethod)
	}
	if gotPath != "/api/v1/organizations/org_123/environments/env_123/exec" {
		t.Fatalf("path = %q", gotPath)
	}
	if len(gotBody.Command) != 4 {
		t.Fatalf("command = %#v, want cw list --local --json", gotBody.Command)
	}
	if gotBody.Command[0] != "cw" || gotBody.Command[1] != "list" || gotBody.Command[2] != "--local" || gotBody.Command[3] != "--json" {
		t.Fatalf("command = %#v, want cw list --local --json", gotBody.Command)
	}
}

func TestListEnvironmentRunsSkipsStoppedEnvironment(t *testing.T) {
	client := &platform.Client{
		ServerURL:    "https://example.invalid",
		SessionToken: "session-token",
		HTTP: &http.Client{
			Timeout: 5 * time.Second,
			Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
				t.Fatalf("unexpected HTTP request for stopped environment")
				return nil, nil
			}),
		},
	}

	env := platform.Environment{
		ID:        "env_123",
		Type:      "sandbox",
		State:     "stopped",
		CreatedAt: "2026-03-16T10:00:00Z",
	}

	sessions, lookup, errMsg := listEnvironmentRuns(client, "org_123", env)
	if lookup != "skipped" {
		t.Fatalf("lookup = %q, want skipped", lookup)
	}
	if errMsg != "" {
		t.Fatalf("errMsg = %q, want empty", errMsg)
	}
	if len(sessions) != 0 {
		t.Fatalf("sessions = %#v, want none", sessions)
	}
}

func TestListPlatformEntriesSkipsRunInspectionByDefault(t *testing.T) {
	client := &platform.Client{
		ServerURL:    "https://example.invalid",
		SessionToken: "session-token",
		HTTP: &http.Client{
			Timeout: 5 * time.Second,
			Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
				t.Fatalf("unexpected HTTP request when run inspection is disabled")
				return nil, nil
			}),
		},
	}

	envs := []platform.Environment{{
		ID:        "env_123",
		Type:      "sandbox",
		State:     "running",
		CreatedAt: "2026-03-16T10:00:00Z",
	}}

	entries := listPlatformEntries(client, "org_123", envs, false)
	if len(entries) != 1 {
		t.Fatalf("entries = %#v, want one entry", entries)
	}
	if entries[0].SessionLookup != "" {
		t.Fatalf("SessionLookup = %q, want empty when run inspection is disabled", entries[0].SessionLookup)
	}
}

func TestListPlatformEntriesIncludesRunInspectionWhenRequested(t *testing.T) {
	var requests int
	client := &platform.Client{
		ServerURL:    "https://example.invalid",
		SessionToken: "session-token",
		HTTP: &http.Client{
			Timeout: 5 * time.Second,
			Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
				requests++
				respBody, _ := json.Marshal(platform.ExecResult{
					ExitCode: 0,
					Stdout:   `[]`,
				})
				return &http.Response{
					StatusCode: http.StatusOK,
					Header:     http.Header{"Content-Type": []string{"application/json"}},
					Body:       io.NopCloser(bytes.NewReader(respBody)),
				}, nil
			}),
		},
	}

	envs := []platform.Environment{{
		ID:        "env_123",
		Type:      "sandbox",
		State:     "running",
		CreatedAt: "2026-03-16T10:00:00Z",
	}}

	entries := listPlatformEntries(client, "org_123", envs, true)
	if len(entries) != 1 {
		t.Fatalf("entries = %#v, want one entry", entries)
	}
	if requests != 1 {
		t.Fatalf("requests = %d, want 1 run inspection request", requests)
	}
	if entries[0].SessionLookup != "available" {
		t.Fatalf("SessionLookup = %q, want available", entries[0].SessionLookup)
	}
}

func TestFilterEnvironmentsByNetwork(t *testing.T) {
	networkA := "project-alpha"
	networkB := "project-beta"
	envs := []platform.Environment{
		{ID: "env_a", Network: &networkA},
		{ID: "env_b", Network: &networkB},
		{ID: "env_none"},
	}

	filtered := filterEnvironmentsByNetwork(envs, "project-alpha")
	if len(filtered) != 1 || filtered[0].ID != "env_a" {
		t.Fatalf("filtered = %#v, want env_a", filtered)
	}

	unfiltered := filterEnvironmentsByNetwork(envs, "")
	if len(unfiltered) != 3 {
		t.Fatalf("unfiltered len = %d, want 3", len(unfiltered))
	}
}

func TestPrintPlatformEntriesUsesSameEnvironmentCardLayout(t *testing.T) {
	alpha := "alpha"
	origLoad := loadCLIConfigForTarget
	defer func() { loadCLIConfigForTarget = origLoad }()
	loadCLIConfigForTarget = func() (*cwconfig.Config, error) {
		return &cwconfig.Config{}, nil
	}

	entries := []platformListEntry{{
		Environment: platform.Environment{
			ID:            "12345678-1234-1234-1234-123456789abc",
			Name:          &alpha,
			State:         "running",
			Type:          "sandbox",
			CPUMillicores: 2000,
			MemoryMB:      4096,
			CreatedAt:     time.Now().UTC().Add(-2 * time.Hour).Format(time.RFC3339),
		},
	}}

	oldStdout := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	os.Stdout = w
	defer func() { os.Stdout = oldStdout }()

	if err := printPlatformEntries(entries); err != nil {
		t.Fatalf("printPlatformEntries: %v", err)
	}

	_ = w.Close()
	output, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("read output: %v", err)
	}
	got := string(output)
	if !strings.Contains(got, "alpha [12345678]  running") {
		t.Fatalf("expected shared card header, got %q", got)
	}
	if !strings.Contains(got, "connect: cw shell 12345678") {
		t.Fatalf("expected shared connect hint, got %q", got)
	}
}

func TestSummarizeExecErrorNormalizesMissingCodewireCLI(t *testing.T) {
	got := summarizeExecError(&platform.ExecResult{
		ExitCode: 127,
		Stderr:   "sh: 1: exec: cw: not found",
	})
	if got != "codewire CLI missing in image" {
		t.Fatalf("unexpected summary %q", got)
	}
}

func TestPrintPlatformEntriesNestsRunsUnderEnvironmentCard(t *testing.T) {
	alpha := "alpha"
	network := "project-alpha"
	entries := []platformListEntry{{
		Environment: platform.Environment{
			ID:            "12345678-1234-1234-1234-123456789abc",
			Name:          &alpha,
			State:         "running",
			Type:          "sandbox",
			CPUMillicores: 2000,
			MemoryMB:      4096,
			CreatedAt:     time.Now().UTC().Add(-2 * time.Hour).Format(time.RFC3339),
			Network:       &network,
		},
		SessionLookup: "available",
		Sessions: []protocol.SessionInfo{{
			ID:        7,
			Name:      "planner",
			Status:    "running",
			Prompt:    "claude -p plan",
			CreatedAt: time.Now().UTC().Add(-20 * time.Minute).Format(time.RFC3339),
		}},
	}}

	oldStdout := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	os.Stdout = w
	defer func() { os.Stdout = oldStdout }()

	if err := printPlatformEntries(entries); err != nil {
		t.Fatalf("printPlatformEntries: %v", err)
	}

	_ = w.Close()
	output, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("read output: %v", err)
	}
	got := string(output)
	if !strings.Contains(got, "  runs: 1\n") {
		t.Fatalf("expected runs summary line, got %q", got)
	}
	if !strings.Contains(got, "  network: project-alpha") {
		t.Fatalf("expected network annotation, got %q", got)
	}
	if !strings.Contains(got, "    ID") {
		t.Fatalf("expected nested runs table header, got %q", got)
	}
	if !strings.Contains(got, "    7") {
		t.Fatalf("expected nested session row, got %q", got)
	}
}

func TestPrintPlatformEntriesGroupsByNetwork(t *testing.T) {
	alpha := "project-alpha"
	beta := "project-beta"
	lead := "lead"
	worker := "worker"
	standalone := "standalone"

	origLoad := loadCLIConfigForTarget
	defer func() { loadCLIConfigForTarget = origLoad }()
	loadCLIConfigForTarget = func() (*cwconfig.Config, error) {
		return &cwconfig.Config{}, nil
	}

	entries := []platformListEntry{
		{
			Environment: platform.Environment{
				ID:        "12345678-1234-1234-1234-123456789abc",
				Name:      &lead,
				State:     "running",
				Type:      "sandbox",
				CreatedAt: time.Now().UTC().Add(-2 * time.Hour).Format(time.RFC3339),
				Network:   &alpha,
			},
		},
		{
			Environment: platform.Environment{
				ID:        "22345678-1234-1234-1234-123456789abc",
				Name:      &worker,
				State:     "running",
				Type:      "sandbox",
				CreatedAt: time.Now().UTC().Add(-90 * time.Minute).Format(time.RFC3339),
				Network:   &beta,
			},
		},
		{
			Environment: platform.Environment{
				ID:        "32345678-1234-1234-1234-123456789abc",
				Name:      &standalone,
				State:     "running",
				Type:      "sandbox",
				CreatedAt: time.Now().UTC().Add(-30 * time.Minute).Format(time.RFC3339),
			},
		},
	}

	oldStdout := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	os.Stdout = w
	defer func() { os.Stdout = oldStdout }()

	if err := printPlatformEntries(entries); err != nil {
		t.Fatalf("printPlatformEntries: %v", err)
	}

	_ = w.Close()
	output, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("read output: %v", err)
	}
	got := string(output)

	alphaHeader := strings.Index(got, "Network: project-alpha")
	betaHeader := strings.Index(got, "Network: project-beta")
	noNetworkHeader := strings.Index(got, "Network: No Network")
	if alphaHeader == -1 || betaHeader == -1 || noNetworkHeader == -1 {
		t.Fatalf("expected grouped network headers, got %q", got)
	}
	if !(alphaHeader < betaHeader && betaHeader < noNetworkHeader) {
		t.Fatalf("expected network groups ordered alpha, beta, no-network; got %q", got)
	}
	if !strings.Contains(got, "lead [12345678]") {
		t.Fatalf("expected alpha entry, got %q", got)
	}
	if !strings.Contains(got, "worker [22345678]") {
		t.Fatalf("expected beta entry, got %q", got)
	}
	if !strings.Contains(got, "standalone [32345678]") {
		t.Fatalf("expected no-network entry, got %q", got)
	}
}

func TestPrintLocalTargetEntriesIncludesLocalNodes(t *testing.T) {
	sessions := []protocol.SessionInfo{{
		ID:        7,
		Name:      "planner",
		Prompt:    "claude -p plan the refactor",
		CreatedAt: time.Now().UTC().Add(-5 * time.Minute).Format(time.RFC3339),
		Status:    "running",
	}}
	localNodes := []localNodeEntry{{
		Instance: cwconfig.LocalInstance{
			Name:     "vm-a",
			Backend:  "lima",
			Image:    "ghcr.io/codewire/base:latest",
			RepoPath: "/tmp/repo",
		},
		Status: "running",
	}}

	oldStdout := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	os.Stdout = w
	defer func() { os.Stdout = oldStdout }()

	if err := printLocalTargetEntries(sessions, localNodes); err != nil {
		t.Fatalf("printLocalTargetEntries: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("close writer: %v", err)
	}
	out, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("read output: %v", err)
	}
	text := string(out)
	for _, want := range []string{"Runs", "Local Nodes", "planner", "vm-a", "lima"} {
		if !strings.Contains(text, want) {
			t.Fatalf("output missing %q:\n%s", want, text)
		}
	}
}

func TestPrintLocalTargetEntriesEmptyState(t *testing.T) {
	oldStdout := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	os.Stdout = w
	defer func() { os.Stdout = oldStdout }()

	if err := printLocalTargetEntries(nil, nil); err != nil {
		t.Fatalf("printLocalTargetEntries: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("close writer: %v", err)
	}
	out, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("read output: %v", err)
	}
	if got := string(out); !strings.Contains(got, "No sessions or local nodes.") {
		t.Fatalf("unexpected output: %q", got)
	}
}
