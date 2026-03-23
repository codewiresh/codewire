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
		Agent:             "codex",
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
	if cfg.Secrets != req.SecretProject {
		t.Fatalf("cfg.Secrets = %q, want %q", cfg.Secrets, req.SecretProject)
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
	if cfg.IncludeOrgSecrets == nil || *cfg.IncludeOrgSecrets {
		t.Fatalf("expected include_org_secrets to be false, got %#v", cfg.IncludeOrgSecrets)
	}
}

func TestCreatePresetRequestFromEnvironment(t *testing.T) {
	f := false
	req := &platform.CreateEnvironmentRequest{
		Image:              "ghcr.io/codewiresh/full:latest",
		InstallCommand:     "pnpm install",
		StartupScript:      "pnpm dev",
		EnvVars:            map[string]string{"NODE_ENV": "development"},
		Agent:              "codex",
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
}

func intPtr(v int) *int {
	return &v
}
