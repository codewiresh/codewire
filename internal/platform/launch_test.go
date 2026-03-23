package platform

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"testing"
	"time"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (fn roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return fn(req)
}

func TestGetLaunchOptions(t *testing.T) {
	var gotPath string

	client := &Client{
		ServerURL:    "https://example.invalid",
		SessionToken: "test-token",
		HTTP: &http.Client{
			Timeout: 5 * time.Second,
			Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
				gotPath = r.URL.Path
				body, _ := json.Marshal(LaunchOptions{
					GitHubStatus:   GitHubStatus{Connected: true, Username: "noel"},
					Presets:        []Preset{{ID: "preset_1", Name: "Go"}},
					SecretProjects: []SecretProject{{ID: "sp_1", Name: "default"}},
				})
				return &http.Response{
					StatusCode: http.StatusOK,
					Header:     http.Header{"Content-Type": []string{"application/json"}},
					Body:       io.NopCloser(bytes.NewReader(body)),
				}, nil
			}),
		},
	}

	out, err := client.GetLaunchOptions("org_123")
	if err != nil {
		t.Fatalf("GetLaunchOptions: %v", err)
	}

	if gotPath != "/api/v1/organizations/org_123/environment-create/options" {
		t.Fatalf("path = %q, want launch options path", gotPath)
	}
	if !out.GitHubStatus.Connected || out.GitHubStatus.Username != "noel" {
		t.Fatalf("unexpected github status: %+v", out.GitHubStatus)
	}
	if len(out.Presets) != 1 || out.Presets[0].Name != "Go" {
		t.Fatalf("unexpected presets: %+v", out.Presets)
	}
	if len(out.SecretProjects) != 1 || out.SecretProjects[0].Name != "default" {
		t.Fatalf("unexpected secret projects: %+v", out.SecretProjects)
	}
}

func TestPrepareLaunch(t *testing.T) {
	var gotPath string
	var gotBody string

	client := &Client{
		ServerURL:    "https://example.invalid",
		SessionToken: "test-token",
		HTTP: &http.Client{
			Timeout: 5 * time.Second,
			Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
				gotPath = r.URL.Path
				body, _ := io.ReadAll(r.Body)
				gotBody = string(body)

				respBody, _ := json.Marshal(PrepareLaunchResponse{
					Draft: CreateEnvironmentRequest{
						RepoURL:        "https://github.com/codewiresh/codewire",
						Image:          "ghcr.io/codewiresh/full:latest",
						InstallCommand: "pnpm install",
					},
					Detection: &DetectionResult{
						Language:      "typescript",
						SuggestedName: "codewire",
					},
				})
				return &http.Response{
					StatusCode: http.StatusOK,
					Header:     http.Header{"Content-Type": []string{"application/json"}},
					Body:       io.NopCloser(bytes.NewReader(respBody)),
				}, nil
			}),
		},
	}

	analyze := true
	out, err := client.PrepareLaunch("org_123", &PrepareLaunchRequest{
		RepoURL: "https://github.com/codewiresh/codewire",
		Analyze: &analyze,
	})
	if err != nil {
		t.Fatalf("PrepareLaunch: %v", err)
	}

	if gotPath != "/api/v1/organizations/org_123/environment-create/prepare" {
		t.Fatalf("path = %q, want launch prepare path", gotPath)
	}
	var req PrepareLaunchRequest
	if err := json.Unmarshal([]byte(gotBody), &req); err != nil {
		t.Fatalf("unmarshal request body: %v", err)
	}
	if req.RepoURL != "https://github.com/codewiresh/codewire" {
		t.Fatalf("RepoURL = %q, want request repo URL", req.RepoURL)
	}
	if req.Analyze == nil || !*req.Analyze {
		t.Fatalf("Analyze = %+v, want true", req.Analyze)
	}
	if out.Draft.Image != "ghcr.io/codewiresh/full:latest" {
		t.Fatalf("Draft.Image = %q, want prepared image", out.Draft.Image)
	}
	if out.Detection == nil || out.Detection.SuggestedName != "codewire" {
		t.Fatalf("unexpected detection: %+v", out.Detection)
	}
}
