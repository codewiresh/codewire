package main

import (
	"path/filepath"
	"reflect"
	"testing"

	cwconfig "github.com/codewiresh/codewire/internal/config"
	"github.com/codewiresh/codewire/internal/platform"
)

func TestPresetInitCmdExposesWriteAndSaveFlags(t *testing.T) {
	cmd := presetInitCmd()
	if cmd.Flags().Lookup("file") == nil {
		t.Fatal("expected preset init to expose --file")
	}
	if cmd.Flags().Lookup("save-preset") == nil {
		t.Fatal("expected preset init to expose --save-preset")
	}
}

func TestCodewireConfigFromRequest(t *testing.T) {
	f := false
	req := &platform.CreateEnvironmentRequest{
		Image:          "ghcr.io/codewiresh/full:latest",
		InstallCommand: "pnpm install",
		StartupScript:  "pnpm dev",
		EnvVars: map[string]string{
			"NODE_ENV": "development",
		},
		Agents:            []platform.SetupAgent{{Type: "codex"}},
		InstallAgents:     boolPtr(true),
		SecretProject:     "my-project",
		AppPorts:          []platform.AppPort{{Port: 3000, Label: "web"}},
		CPUMillicores:     intPtr(2000),
		MemoryMB:          intPtr(4096),
		DiskGB:            intPtr(20),
		IncludeOrgSecrets: &f,
	}

	cfg := codewireConfigFromRequest(req)
	if cfg.Image != req.Image {
		t.Fatalf("cfg.Image = %q, want %q", cfg.Image, req.Image)
	}
	if cfg.Install != req.InstallCommand {
		t.Fatalf("cfg.Install = %q, want %q", cfg.Install, req.InstallCommand)
	}
	if cfg.Startup != req.StartupScript {
		t.Fatalf("cfg.Startup = %q, want %q", cfg.Startup, req.StartupScript)
	}
	if cfg.Secrets == nil || cfg.Secrets.Project != req.SecretProject {
		t.Fatalf("cfg.Secrets = %#v, want project %q", cfg.Secrets, req.SecretProject)
	}
	if !reflect.DeepEqual(cfg.Env, req.EnvVars) {
		t.Fatalf("cfg.Env = %#v, want %#v", cfg.Env, req.EnvVars)
	}
	if !reflect.DeepEqual(cfg.Ports, []cwconfig.PortConfig{{Port: 3000, Label: "web"}}) {
		t.Fatalf("cfg.Ports = %#v", cfg.Ports)
	}
	if cfg.CPU != 2000 || cfg.Memory != 4096 || cfg.Disk != 20 {
		t.Fatalf("unexpected resources: cpu=%d mem=%d disk=%d", cfg.CPU, cfg.Memory, cfg.Disk)
	}
	if cfg.Agents == nil || !reflect.DeepEqual(cfg.Agents.Tools, []string{"codex"}) {
		t.Fatalf("cfg.Agents = %#v, want [codex]", cfg.Agents)
	}
	if cfg.Agents.Install == nil || !*cfg.Agents.Install {
		t.Fatalf("expected agents.install to be true, got %#v", cfg.Agents)
	}
	if cfg.Secrets.Org == nil || *cfg.Secrets.Org {
		t.Fatalf("expected secrets.org to be false, got %#v", cfg.Secrets)
	}
	if cfg.Secrets.User == nil || !*cfg.Secrets.User {
		t.Fatalf("expected secrets.user to default true, got %#v", cfg.Secrets)
	}
}

func TestCreatePresetRequestFromEnvironment(t *testing.T) {
	f := false
	req := &platform.CreateEnvironmentRequest{
		Image:              "ghcr.io/codewiresh/full:latest",
		InstallCommand:     "pnpm install",
		StartupScript:      "pnpm dev",
		EnvVars:            map[string]string{"NODE_ENV": "development"},
		Agents:             []platform.SetupAgent{{Type: "codex"}},
		InstallAgents:      boolPtr(true),
		AppPorts:           []platform.AppPort{{Port: 3000, Label: "web"}},
		IncludeUserSecrets: &f,
	}

	presetReq, err := createPresetRequestFromEnvironment("Fullstack Dev", req)
	if err != nil {
		t.Fatalf("createPresetRequestFromEnvironment: %v", err)
	}
	if presetReq.Name != "Fullstack Dev" {
		t.Fatalf("presetReq.Name = %q", presetReq.Name)
	}
	if presetReq.Slug != "fullstack-dev" {
		t.Fatalf("presetReq.Slug = %q", presetReq.Slug)
	}
	if presetReq.Image != req.Image {
		t.Fatalf("presetReq.Image = %q, want %q", presetReq.Image, req.Image)
	}
	if !reflect.DeepEqual(presetReq.EnvVars, req.EnvVars) {
		t.Fatalf("presetReq.EnvVars = %#v, want %#v", presetReq.EnvVars, req.EnvVars)
	}
	if !reflect.DeepEqual(presetReq.AppPorts, req.AppPorts) {
		t.Fatalf("presetReq.AppPorts = %#v, want %#v", presetReq.AppPorts, req.AppPorts)
	}
	if !reflect.DeepEqual(presetReq.Agents, req.Agents) {
		t.Fatalf("presetReq.Agents = %#v, want %#v", presetReq.Agents, req.Agents)
	}
	if presetReq.InstallAgents == nil || !*presetReq.InstallAgents {
		t.Fatalf("expected install_agents to be true, got %#v", presetReq.InstallAgents)
	}
	if presetReq.IncludeUserSecrets == nil || *presetReq.IncludeUserSecrets {
		t.Fatalf("expected include_user_secrets to be false, got %#v", presetReq.IncludeUserSecrets)
	}
}

func TestWriteResolvedCodewireYAMLRoundTrip(t *testing.T) {
	req := &platform.CreateEnvironmentRequest{
		Image:          "ghcr.io/codewiresh/full:latest",
		InstallCommand: "pnpm install",
		StartupScript:  "pnpm dev",
		EnvVars:        map[string]string{"NODE_ENV": "development"},
		AppPorts:       []platform.AppPort{{Port: 3000, Label: "web"}},
	}
	path := filepath.Join(t.TempDir(), "codewire.yaml")
	if err := writeResolvedCodewireYAML(path, req); err != nil {
		t.Fatalf("writeResolvedCodewireYAML: %v", err)
	}
	cfg, err := cwconfig.LoadCodewireConfig(path)
	if err != nil {
		t.Fatalf("LoadCodewireConfig: %v", err)
	}
	if cfg.Image != req.Image {
		t.Fatalf("cfg.Image = %q, want %q", cfg.Image, req.Image)
	}
	if cfg.Install != req.InstallCommand || cfg.Startup != req.StartupScript {
		t.Fatalf("unexpected install/startup round-trip: %#v", cfg)
	}
	if cfg.Secrets == nil || cfg.Secrets.Org == nil || !*cfg.Secrets.Org || cfg.Secrets.User == nil || !*cfg.Secrets.User {
		t.Fatalf("expected default secrets sources to round-trip as true, got %#v", cfg.Secrets)
	}
}

func intPtr(v int) *int {
	return &v
}
