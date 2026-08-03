package codewire

import (
	"math"
	"reflect"
	"testing"
	"time"

	codewirev1 "github.com/codewiresh/codewire/libs/gen-go/codewire/v1"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestFromProtoAPIKeyGolden(t *testing.T) {
	lastUsedAt := timestamppb.New(time.Date(2026, 1, 1, 1, 2, 3, 0, time.UTC))
	expiresAt := timestamppb.New(time.Date(2027, 1, 1, 1, 2, 3, 0, time.UTC))
	disabledAt := timestamppb.New(time.Date(2026, 1, 2, 1, 2, 3, 0, time.UTC))
	createdAt := timestamppb.New(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))

	got, err := fromProtoAPIKey(&codewirev1.ApiKey{
		Id:             "key_1",
		UserId:         "user_1",
		OrgId:          "org_1",
		Name:           "build",
		KeyPrefix:      "cw_abc",
		Scopes:         []string{"read", "write"},
		LastUsedAt:     lastUsedAt,
		ExpiresAt:      expiresAt,
		DisabledAt:     disabledAt,
		CreatedAt:      createdAt,
		CreatedByName:  "Test User",
		CreatedByEmail: "test@example.com",
	})
	if err != nil {
		t.Fatalf("convert API key: %v", err)
	}

	want := APIKey{
		Id:             "key_1",
		UserId:         "user_1",
		OrgId:          "org_1",
		Name:           "build",
		KeyPrefix:      "cw_abc",
		Scopes:         stringSlicePointer([]string{"read", "write"}),
		LastUsedAt:     stringPointer("2026-01-01T01:02:03Z"),
		ExpiresAt:      stringPointer("2027-01-01T01:02:03Z"),
		DisabledAt:     stringPointer("2026-01-02T01:02:03Z"),
		CreatedAt:      "2026-01-01T00:00:00Z",
		CreatedByName:  stringPointer("Test User"),
		CreatedByEmail: stringPointer("test@example.com"),
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("converted API key mismatch (-want +got):\nwant: %#v\n got: %#v", want, got)
	}
}

func TestAPIKeyConverterDescriptorCoverage(t *testing.T) {
	if err := ensureAPIKeyConverterCoverage(); err != nil {
		t.Fatalf("API key converter descriptor coverage: %v", err)
	}
}

func TestUpdateAPIKeyDisabledPreservesPresence(t *testing.T) {
	if got := updateAPIKeyDisabled(map[string]any{}); got != nil {
		t.Errorf("missing disabled = %v, want nil", *got)
	}
	if got := updateAPIKeyDisabled(map[string]any{"disabled": "true"}); got != nil {
		t.Errorf("non-boolean disabled = %v, want nil", *got)
	}
	if got := updateAPIKeyDisabled(map[string]any{"disabled": false}); got == nil || *got {
		t.Errorf("false disabled = %v, want false", got)
	}
}

func TestFromProtoPresetGolden(t *testing.T) {
	setup := &codewirev1.SetupConfig{
		RepoUrl: "https://example.test/repo", Branch: "main",
		Repos:          []*codewirev1.RepoEntry{{Url: "https://example.test/extra", Branch: "dev"}},
		InstallCommand: "bun install", StartupScript: "bun run dev",
		EnvVars: map[string]string{"A": "1"}, Agents: []*codewirev1.SetupAgent{{Type: "codex"}},
		InstallAgents: testBoolPointer(true), Agent: "codex", AgentEnv: map[string]string{"B": "2"},
		AppPorts:          []*codewirev1.AppPort{{Port: 3000, Label: "web", Access: "public"}},
		IncludeOrgSecrets: testBoolPointer(true), IncludeUserSecrets: testBoolPointer(false),
	}
	got, err := fromProtoPreset(&codewirev1.Preset{
		Id: "preset_1", OrgId: testStringPointer("org_1"), Name: "Node", Slug: testStringPointer("node"),
		Language: testStringPointer("typescript"), Official: true, Description: testStringPointer("starter"),
		BuildStatus: "ready", BuildError: testStringPointer(""), DefaultCpuMillicores: 2000,
		DefaultMemoryMb: 4096, DefaultDiskGb: 20, DefaultTtlSeconds: testInt32Pointer(3600),
		Image: testStringPointer("node:22"), DefaultSetupConfig: setup, SecretProjectId: testStringPointer("project_1"),
		CreatedAt: timestamppb.New(time.Date(2026, 2, 3, 4, 5, 6, 789, time.UTC)),
	})
	if err != nil {
		t.Fatalf("convert preset: %v", err)
	}
	want := Preset{
		Id: "preset_1", OrgId: testStringPointer("org_1"), Name: "Node", Slug: testStringPointer("node"),
		Language: testStringPointer("typescript"), Official: true, Description: testStringPointer("starter"),
		BuildStatus: "ready", BuildError: testStringPointer(""), DefaultCpuMillicores: 2000,
		DefaultMemoryMb: 4096, DefaultDiskGb: 20, DefaultTtlSeconds: testInt64Pointer(3600),
		Image: testStringPointer("node:22"), SecretProjectId: testStringPointer("project_1"),
		CreatedAt: "2026-02-03T04:05:06Z",
		DefaultSetupConfig: &SetupConfig{
			RepoUrl: testStringPointer("https://example.test/repo"), Branch: testStringPointer("main"),
			Repos:          testRepoEntriesPointer([]RepoEntry{{Url: "https://example.test/extra", Branch: testStringPointer("dev")}}),
			InstallCommand: testStringPointer("bun install"), StartupScript: testStringPointer("bun run dev"),
			EnvVars: testStringMapPointer(map[string]string{"A": "1"}), Agents: testSetupAgentsPointer([]SetupAgent{{Type: "codex"}}),
			InstallAgents: testBoolPointer(true), Agent: testStringPointer("codex"), AgentEnv: testStringMapPointer(map[string]string{"B": "2"}),
			AppPorts:          testAppPortsPointer([]AppPort{{Port: 3000, Label: "web", Access: testStringPointer("public")}}),
			IncludeOrgSecrets: testBoolPointer(true), IncludeUserSecrets: testBoolPointer(false),
		},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("converted preset mismatch (-want +got):\nwant: %#v\n got: %#v", want, got)
	}
}

func TestFromProtoPresetUnsetOptionalsAndEmptySetupConfig(t *testing.T) {
	got, err := fromProtoPreset(&codewirev1.Preset{
		Id: "preset_1", Name: "empty", DefaultSetupConfig: &codewirev1.SetupConfig{},
	})
	if err != nil {
		t.Fatalf("convert preset: %v", err)
	}
	if got.CreatedAt != "" || got.OrgId != nil || got.Slug != nil || got.Language != nil || got.Description != nil || got.BuildError != nil || got.DefaultTtlSeconds != nil || got.Image != nil || got.SecretProjectId != nil {
		t.Errorf("unset optional preset fields were not preserved: %#v", got)
	}
	if got.DefaultSetupConfig == nil {
		t.Fatal("default setup config = nil, want present empty config")
	}
	setup := got.DefaultSetupConfig
	if setup.RepoUrl != nil || setup.Branch != nil || setup.Repos != nil || setup.InstallCommand != nil || setup.StartupScript != nil || setup.EnvVars != nil || setup.Agents != nil || setup.InstallAgents != nil || setup.Agent != nil || setup.AgentEnv != nil || setup.AppPorts != nil || setup.IncludeOrgSecrets != nil || setup.IncludeUserSecrets != nil {
		t.Errorf("empty setup config did not preserve nil optional fields: %#v", setup)
	}

	withoutSetup, err := fromProtoPreset(&codewirev1.Preset{Id: "preset_2", Name: "no-setup"})
	if err != nil {
		t.Fatalf("convert preset without setup config: %v", err)
	}
	if withoutSetup.DefaultSetupConfig != nil {
		t.Errorf("absent setup config = %#v, want nil", withoutSetup.DefaultSetupConfig)
	}
}

func TestPresetRequestPresenceAndOverflow(t *testing.T) {
	empty := ""
	zero := int64(0)
	falseValue := false
	emptyMap := map[string]string{}
	emptyAgents := []SetupAgent{}
	emptyPorts := []AppPort{}
	create, err := createPresetRequest("org_1", CreatePresetBody{
		Name: "preset", Description: &empty, DefaultCpuMillicores: &zero, DefaultMemoryMb: &zero,
		DefaultDiskGb: &zero, DefaultTtlSeconds: &zero, Image: &empty, InstallCommand: &empty,
		StartupScript: &empty, EnvVars: &emptyMap, Agents: &emptyAgents, InstallAgents: &falseValue,
		Agent: &empty, AgentEnv: &emptyMap, AppPorts: &emptyPorts, IncludeOrgSecrets: &falseValue,
		IncludeUserSecrets: &falseValue,
	}, testStringPointer("project_1"))
	if err != nil {
		t.Fatalf("create request: %v", err)
	}
	if create.Description == nil || create.DefaultCpuMillicores == nil || create.DefaultMemoryMb == nil || create.DefaultDiskGb == nil || create.DefaultTtlSeconds == nil || create.InstallAgents == nil || create.IncludeOrgSecrets == nil || create.IncludeUserSecrets == nil || create.SecretProjectId == nil {
		t.Errorf("create request lost optional presence: %#v", create)
	}
	if create.GetDefaultCpuMillicores() != 0 || create.GetImage() != "" || create.GetInstallCommand() != "" || create.GetStartupScript() != "" || create.GetSecretProjectId() != "project_1" {
		t.Errorf("create request changed optional values: %#v", create)
	}
	if create.EnvVars == nil || create.AgentEnv == nil || create.Agents == nil || create.AppPorts == nil {
		t.Errorf("create request lost empty collection values: %#v", create)
	}

	update, err := updatePresetRequest("org_1", "preset_1", UpdatePresetBody{
		Name: &empty, Description: &empty, DefaultCpuMillicores: &zero, DefaultMemoryMb: &zero,
		DefaultDiskGb: &zero, DefaultTtlSeconds: &zero, Image: &empty, InstallCommand: &empty,
		StartupScript: &empty, EnvVars: &emptyMap, Agents: &emptyAgents, InstallAgents: &falseValue,
		Agent: &empty, AgentEnv: &emptyMap, AppPorts: &emptyPorts, IncludeOrgSecrets: &falseValue,
		IncludeUserSecrets: &falseValue,
	}, testStringPointer(""))
	if err != nil {
		t.Fatalf("update request: %v", err)
	}
	if update.Name == nil || update.Description == nil || update.DefaultCpuMillicores == nil || update.DefaultMemoryMb == nil || update.DefaultDiskGb == nil || update.DefaultTtlSeconds == nil || update.Image == nil || update.InstallCommand == nil || update.StartupScript == nil || update.InstallAgents == nil || update.Agent == nil || update.IncludeOrgSecrets == nil || update.IncludeUserSecrets == nil || update.SecretProjectId == nil {
		t.Errorf("update request lost scalar optional presence: %#v", update)
	}
	if update.EnvVars == nil || update.Agents == nil || update.AgentEnv == nil || update.AppPorts == nil {
		t.Errorf("update request lost empty collection presence: %#v", update)
	}
	if len(update.EnvVars.GetValues()) != 0 || len(update.Agents.GetValues()) != 0 || len(update.AgentEnv.GetValues()) != 0 || len(update.AppPorts.GetValues()) != 0 || update.GetSecretProjectId() != "" {
		t.Errorf("update request changed empty values: %#v", update)
	}

	overflow := int64(math.MaxInt32) + 1
	if _, err := createPresetRequest("org_1", CreatePresetBody{Name: "preset", DefaultCpuMillicores: &overflow}, nil); err == nil {
		t.Error("create request accepted overflow CPU value")
	}
	if _, err := updatePresetRequest("org_1", "preset_1", UpdatePresetBody{DefaultTtlSeconds: &overflow}, nil); err == nil {
		t.Error("update request accepted overflow TTL value")
	}
	if _, err := toProtoAppPorts(&[]AppPort{{Port: int64(math.MaxInt32) + 1}}); err == nil {
		t.Error("app port conversion accepted overflow value")
	}
}

func TestEnvironmentConvertersGolden(t *testing.T) {
	ttl := int32(3600)
	protoEnvironment := &codewirev1.Environment{
		Id: "env_1", OrgId: "org_1", CreatedBy: "user_1", PresetId: "preset_1", Type: "sandbox", Name: "work",
		State: codewirev1.EnvironmentState_ENVIRONMENT_STATE_RUNNING, DesiredState: codewirev1.DesiredState_DESIRED_STATE_STARTED,
		ErrorReason: "retrying", Recoverable: true, StateChangedAt: timestamppb.New(time.Date(2026, 3, 1, 1, 2, 3, 0, time.UTC)),
		RetryCount: 2, SetupPhase: 3, SetupComplete: true, SetupError: "setup warning", TtlSeconds: &ttl,
		ShutdownAt:    timestamppb.New(time.Date(2026, 3, 2, 1, 2, 3, 0, time.UTC)),
		CpuMillicores: 2000, MemoryMb: 4096, DiskGb: 20, TotalRunningSeconds: 123,
		CreatedAt:           timestamppb.New(time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC)),
		StartedAt:           timestamppb.New(time.Date(2026, 3, 1, 0, 1, 0, 0, time.UTC)),
		StoppedAt:           timestamppb.New(time.Date(2026, 3, 1, 0, 2, 0, 0, time.UTC)),
		DestroyedAt:         timestamppb.New(time.Date(2026, 3, 1, 0, 3, 0, 0, time.UTC)),
		Protected:           true,
		DeletionRequestedAt: timestamppb.New(time.Date(2026, 3, 1, 0, 4, 0, 0, time.UTC)),
		DeletionGraceUntil:  timestamppb.New(time.Date(2026, 3, 1, 0, 5, 0, 0, time.UTC)),
		PresetName:          "Starter", Network: "tailnet",
		IsolationTier: codewirev1.IsolationTier_ISOLATION_TIER_CONFIDENTIAL,
		Ports: []*codewirev1.Port{{
			Id: "port_1", EnvironmentId: "env_1", Port: 3000, Label: "web", Access: codewirev1.PortAccess_PORT_ACCESS_PUBLIC,
			PreviewUrl: testStringPointer("https://preview.example.test"), CreatedAt: timestamppb.New(time.Date(2026, 3, 1, 0, 6, 0, 0, time.UTC)),
		}},
	}
	got, err := fromProtoEnvironment(protoEnvironment)
	if err != nil {
		t.Fatalf("convert environment: %v", err)
	}
	want := EnvironmentData{
		CpuMillicores: 2000, CreatedAt: "2026-03-01T00:00:00Z", CreatedBy: "user_1",
		DeletionGraceUntil: testStringPointer("2026-03-01T00:05:00Z"), DeletionRequestedAt: testStringPointer("2026-03-01T00:04:00Z"),
		DesiredState: "started", DestroyedAt: testStringPointer("2026-03-01T00:03:00Z"), DiskGb: 20, ErrorReason: testStringPointer("retrying"),
		Id: "env_1", IsolationTier: "confidential", MemoryMb: 4096, Name: testStringPointer("work"), Network: testStringPointer("tailnet"), OrgId: "org_1",
		Ports:    &[]EnvironmentPort{{Access: "public", CreatedAt: "2026-03-01T00:06:00Z", EnvironmentId: "env_1", Id: "port_1", Label: "web", Port: 3000, PreviewUrl: testStringPointer("https://preview.example.test")}},
		PresetId: testStringPointer("preset_1"), PresetName: testStringPointer("Starter"), Protected: true, Recoverable: true,
		RetryCount: 2, SetupComplete: true, SetupError: testStringPointer("setup warning"), SetupPhase: 3,
		ShutdownAt: testStringPointer("2026-03-02T01:02:03Z"), StartedAt: testStringPointer("2026-03-01T00:01:00Z"),
		State: "running", StateChangedAt: "2026-03-01T01:02:03Z", StoppedAt: testStringPointer("2026-03-01T00:02:00Z"),
		TotalRunningSeconds: 123, TtlSeconds: testInt64Pointer(3600), Type: "sandbox",
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("converted environment mismatch (-want +got):\nwant: %#v\n got: %#v", want, got)
	}
	invalidEnvironment := &codewirev1.Environment{IsolationTier: codewirev1.IsolationTier(-1)}
	if _, err := fromProtoEnvironment(invalidEnvironment); err == nil {
		t.Error("environment converter accepted an unknown isolation tier")
	}

	file, err := fromProtoFileEntry(&codewirev1.FileEntry{
		Name: "main.go", Size: 42, IsDir: false, Mode: 0o100755,
		ModTime: timestamppb.New(time.Date(2026, 3, 1, 0, 7, 0, 0, time.UTC)),
	})
	if err != nil {
		t.Fatalf("convert file entry: %v", err)
	}
	if wantFile := (FileEntry{Name: "main.go", Size: 42, IsDir: false, Mode: "0755", ModTime: "2026-03-01T00:07:00Z"}); !reflect.DeepEqual(file, wantFile) {
		t.Errorf("converted file mismatch (-want +got):\nwant: %#v\n got: %#v", wantFile, file)
	}

	if result := fromProtoExecResult(&codewirev1.ExecResponse{ExitCode: 7, Stdout: []byte("out"), Stderr: []byte("err")}); result != (ExecResult{ExitCode: 7, Stdout: "out", Stderr: "err"}) {
		t.Errorf("converted exec result = %#v", result)
	}
}

func TestCreateEnvironmentRequestPreservesOwnedNestedValues(t *testing.T) {
	empty := ""
	zero := int64(0)
	falseValue := false
	confidential := "confidential"
	emptyMap := map[string]string{}
	agents := []SetupAgent{{Type: "codex"}}
	ports := []AppPort{{Port: 3000, Label: "web", Access: &empty}}
	repos := []RepoEntry{{Url: "https://example.test/repo", Branch: &empty}}
	request, err := createEnvironmentRequest("org_1", CreateEnvironmentBody{
		Agent: &empty, AgentEnv: &emptyMap, Agents: &agents, AppPorts: &ports, Branch: &empty,
		CpuMillicores: &zero, DiskGb: &zero, EnvVars: &emptyMap, Image: &empty, IncludeOrgSecrets: &falseValue,
		IncludeUserSecrets: &falseValue, InstallAgents: &falseValue, InstallCommand: &empty, IsolationTier: &confidential, MemoryMb: &zero,
		Name: &empty, PresetId: &empty, PresetSlug: &empty, RepoUrl: &empty, Repos: &repos, SecretProject: &empty,
		StartupScript: &empty, TtlSeconds: &zero,
	})
	if err != nil {
		t.Fatalf("create environment request: %v", err)
	}
	if request.PresetId == nil || request.Name == nil || request.CpuMillicores == nil || request.MemoryMb == nil || request.DiskGb == nil || request.TtlSeconds == nil || request.InstallAgents == nil || request.IncludeOrgSecrets == nil || request.IncludeUserSecrets == nil {
		t.Errorf("request lost scalar presence: %#v", request)
	}
	if request.EnvVars == nil || request.AgentEnv == nil || len(request.Agents) != 1 || len(request.AppPorts) != 1 || len(request.Repos) != 1 {
		t.Errorf("request lost collection values: %#v", request)
	}
	if request.GetIsolationTier() != codewirev1.IsolationTier_ISOLATION_TIER_CONFIDENTIAL {
		t.Errorf("request changed isolation tier: %#v", request)
	}
	if request.GetAgents()[0].GetType() != "codex" || request.GetAppPorts()[0].GetPort() != 3000 || request.GetAppPorts()[0].GetLabel() != "web" || request.GetAppPorts()[0].GetAccess() != "" || request.GetRepos()[0].GetUrl() != "https://example.test/repo" || request.GetRepos()[0].GetBranch() != "" {
		t.Errorf("request changed nested values: %#v", request)
	}
	if overflow := int64(math.MaxInt32) + 1; func() bool {
		_, err := createEnvironmentRequest("org_1", CreateEnvironmentBody{CpuMillicores: &overflow})
		return err == nil
	}() {
		t.Error("create environment request accepted overflow CPU value")
	}
	invalidIsolation := "container"
	if _, err := createEnvironmentRequest("org_1", CreateEnvironmentBody{IsolationTier: &invalidIsolation}); err == nil {
		t.Error("create environment request accepted an unknown isolation tier")
	}
}

func TestFromProtoSecretMetadataGolden(t *testing.T) {
	got, err := fromProtoSecretMetadata(&codewirev1.SecretMetadata{
		Key:       "DATABASE_URL",
		CreatedAt: timestamppb.New(time.Date(2026, 2, 3, 4, 5, 6, 123, time.UTC)),
		UpdatedAt: timestamppb.New(time.Date(2026, 2, 4, 4, 5, 6, 456, time.UTC)),
	})
	if err != nil {
		t.Fatalf("convert secret metadata: %v", err)
	}
	want := SecretMetadata{Key: "DATABASE_URL", CreatedAt: testStringPointer("2026-02-03T04:05:06Z"), UpdatedAt: testStringPointer("2026-02-04T04:05:06Z")}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("converted secret metadata mismatch (-want +got):\nwant: %#v\n got: %#v", want, got)
	}
}

func TestFromProtoSecretProjectGolden(t *testing.T) {
	got, err := fromProtoSecretProject(&codewirev1.SecretProject{
		Id: "project_1", OrgId: "org_1", Name: "app", SecretCount: 2,
		CreatedAt: timestamppb.New(time.Date(2026, 2, 3, 4, 5, 6, 123, time.UTC)),
	})
	if err != nil {
		t.Fatalf("convert secret project: %v", err)
	}
	want := SecretProject{Id: "project_1", OrgId: "org_1", Name: "app", SecretCount: testInt64Pointer(2), CreatedAt: "2026-02-03T04:05:06Z"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("converted secret project mismatch (-want +got):\nwant: %#v\n got: %#v", want, got)
	}
	zero, err := fromProtoSecretProject(&codewirev1.SecretProject{})
	if err != nil {
		t.Fatalf("convert zero secret project: %v", err)
	}
	if zero.SecretCount != nil {
		t.Errorf("zero secret count = %v, want nil", *zero.SecretCount)
	}
}

func TestPresetSecretConverterDescriptorCoverage(t *testing.T) {
	if err := ensurePresetConverterCoverage(); err != nil {
		t.Fatalf("preset converter descriptor coverage: %v", err)
	}
	if err := ensureSecretMetadataConverterCoverage(); err != nil {
		t.Fatalf("secret metadata converter descriptor coverage: %v", err)
	}
	if err := ensureSecretProjectConverterCoverage(); err != nil {
		t.Fatalf("secret project converter descriptor coverage: %v", err)
	}
	if err := ensureSetupConfigConverterCoverage(); err != nil {
		t.Fatalf("setup config converter descriptor coverage: %v", err)
	}
	if err := ensureEnvironmentConverterCoverage(); err != nil {
		t.Fatalf("environment converter descriptor coverage: %v", err)
	}
	if err := ensurePortConverterCoverage(); err != nil {
		t.Fatalf("port converter descriptor coverage: %v", err)
	}
	if err := ensureFileEntryConverterCoverage(); err != nil {
		t.Fatalf("file entry converter descriptor coverage: %v", err)
	}
}

func stringSlicePointer(values []string) *[]string {
	return &values
}

func testStringPointer(value string) *string                          { return &value }
func testBoolPointer(value bool) *bool                                { return &value }
func testInt32Pointer(value int32) *int32                             { return &value }
func testInt64Pointer(value int64) *int64                             { return &value }
func testStringMapPointer(value map[string]string) *map[string]string { return &value }
func testSetupAgentsPointer(value []SetupAgent) *[]SetupAgent         { return &value }
func testAppPortsPointer(value []AppPort) *[]AppPort                  { return &value }
func testRepoEntriesPointer(value []RepoEntry) *[]RepoEntry           { return &value }
