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
	platform := codewirev1.ProjectStoragePlacement_PROJECT_STORAGE_PLACEMENT_PLATFORM
	project := &codewirev1.ProjectSpec{
		SchemaVersion: 1, Image: "node:22", WorkingDirectory: "/workspace/app",
		Repositories:     []*codewirev1.RepositorySpec{{Source: "https://example.test/extra", Branch: "dev", Destination: "/workspace/extra", KnownHosts: []string{"example.test ssh-ed25519 AAAA"}}},
		InstallCommand:   "bun install",
		StartupScript:    "bun run dev",
		Environment:      map[string]string{"A": "1"},
		Agents:           &codewirev1.ProjectAgents{Install: testBoolPointer(true), Tools: []string{"codex"}},
		ApplicationPorts: []*codewirev1.ApplicationPort{{Port: 3000, Label: "web", Access: "public"}},
		Secrets:          &codewirev1.ProjectSecretBindings{Project: "development", Organization: true, User: &platform},
		Credentials:      &codewirev1.ProjectCredentialBinding{Profile: "platform:id:profile-one"},
	}
	got, err := fromProtoPreset(&codewirev1.Preset{
		Id: "preset_1", OrgId: testStringPointer("org_1"), Name: "Node", Slug: testStringPointer("node"),
		Language: testStringPointer("typescript"), Official: true, Description: testStringPointer("starter"),
		BuildStatus: "ready", BuildError: testStringPointer(""), DefaultTtlSeconds: testInt32Pointer(3600),
		CreatedAt:   timestamppb.New(time.Date(2026, 2, 3, 4, 5, 6, 789, time.UTC)),
		ProjectSpec: project,
	})
	if err != nil {
		t.Fatalf("convert preset: %v", err)
	}
	want := Preset{
		Id: "preset_1", OrgId: testStringPointer("org_1"), Name: "Node", Slug: testStringPointer("node"),
		Language: testStringPointer("typescript"), Official: true, Description: testStringPointer("starter"),
		BuildStatus: "ready", BuildError: testStringPointer(""), DefaultTtlSeconds: testInt64Pointer(3600),
		CreatedAt: "2026-02-03T04:05:06Z", ProjectSpec: ProjectSpec{
			SchemaVersion: 1, Image: "node:22", WorkingDirectory: "/workspace/app",
			Repositories:     []RepositorySpec{{Source: "https://example.test/extra", Branch: testStringPointer("dev"), Destination: testStringPointer("/workspace/extra"), KnownHosts: []string{"example.test ssh-ed25519 AAAA"}}},
			InstallCommand:   "bun install",
			StartupScript:    "bun run dev",
			Environment:      map[string]string{"A": "1"},
			Agents:           &ProjectAgents{Install: testBoolPointer(true), Tools: []string{"codex"}},
			ApplicationPorts: []ApplicationPort{{Port: 3000, Label: "web", Access: testStringPointer("public")}},
			Secrets:          &ProjectSecretBindings{Project: "development", Organization: true, User: projectStoragePlacementPointer(ProjectStoragePlacementPlatform)},
			Credentials:      &ProjectCredentialBinding{Profile: "platform:id:profile-one"},
		},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("converted preset mismatch (-want +got):\nwant: %#v\n got: %#v", want, got)
	}
}

func TestFromProtoPresetRequiresProjectSpec(t *testing.T) {
	if _, err := fromProtoPreset(nil); err == nil {
		t.Fatal("nil preset response payload was accepted")
	}
	got, err := fromProtoPreset(&codewirev1.Preset{
		Id: "preset_1", Name: "empty", ProjectSpec: &codewirev1.ProjectSpec{},
	})
	if err != nil {
		t.Fatalf("convert preset: %v", err)
	}
	if got.CreatedAt != "" || got.OrgId != nil || got.Slug != nil || got.Language != nil || got.Description != nil || got.BuildError != nil || got.DefaultTtlSeconds != nil {
		t.Errorf("unset optional preset fields were not preserved: %#v", got)
	}
	if _, err := fromProtoPreset(&codewirev1.Preset{Id: "preset_2", Name: "missing"}); err == nil {
		t.Fatal("preset without project_spec was accepted")
	}
}

func TestPresetRequestPresenceAndOverflow(t *testing.T) {
	empty := ""
	zero := int64(0)
	create, err := createPresetRequest("org_1", CreatePresetBody{
		Name: "preset", Description: &empty, DefaultTtlSeconds: &zero,
		ProjectSpec: ProjectSpec{SchemaVersion: 1, WorkingDirectory: "/workspace"},
	})
	if err != nil {
		t.Fatalf("create request: %v", err)
	}
	if create.Description == nil || create.DefaultTtlSeconds == nil || create.ProjectSpec == nil {
		t.Errorf("create request lost optional presence: %#v", create)
	}
	if create.GetProjectSpec().GetSchemaVersion() != 1 || create.GetProjectSpec().GetWorkingDirectory() != "/workspace" {
		t.Errorf("create request changed project spec: %#v", create)
	}

	update, err := updatePresetRequest("org_1", "preset_1", UpdatePresetBody{
		Name: &empty, Description: &empty, DefaultTtlSeconds: &zero,
		ProjectSpec: &ProjectSpec{},
	})
	if err != nil {
		t.Fatalf("update request: %v", err)
	}
	if update.Name == nil || update.Description == nil || update.DefaultTtlSeconds == nil || update.ProjectSpec == nil {
		t.Errorf("update request lost scalar optional presence: %#v", update)
	}

	overflow := int64(math.MaxInt32) + 1
	if _, err := updatePresetRequest("org_1", "preset_1", UpdatePresetBody{DefaultTtlSeconds: &overflow}); err == nil {
		t.Error("update request accepted overflow TTL value")
	}
	if _, err := toProtoApplicationPorts(&[]ApplicationPort{{Port: int64(math.MaxInt32) + 1}}); err == nil {
		t.Error("app port conversion accepted overflow value")
	}
}

func TestEnvironmentConvertersGolden(t *testing.T) {
	ttl := int32(3600)
	profileRevision := uint64(9_007_199_254_741_009)
	platform := codewirev1.ProjectStoragePlacement_PROJECT_STORAGE_PLACEMENT_PLATFORM
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
		OperationGeneration: profileRevision,
		SourceSelection: &codewirev1.EnvironmentSourceSelection{
			Secrets:     &codewirev1.ProjectSecretBindings{Project: "platform:id:project-one", User: &platform},
			Credentials: &codewirev1.ProjectCredentialBinding{Profile: "platform:id:profile-one"}, ProfileRevision: &profileRevision,
		},
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
		OperationGeneration: profileRevision,
		SourceSelection: &EnvironmentSourceSelection{
			Secrets:     &ProjectSecretBindings{Project: "platform:id:project-one", User: projectStoragePlacementPointer(ProjectStoragePlacementPlatform)},
			Credentials: &ProjectCredentialBinding{Profile: "platform:id:profile-one"}, ProfileRevision: &profileRevision,
		},
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
	confidential := "confidential"
	destination := "/workspace/repo"
	profileRevision := uint64(9_007_199_254_741_009)
	platform := ProjectStoragePlacementPlatform
	request, err := createEnvironmentRequest("org_1", CreateEnvironmentBody{
		Name: &empty, PresetId: &empty, IsolationTier: &confidential, TtlSeconds: &zero,
		ExpectedProfileRevision: &profileRevision, ConfirmPersonalCredentials: true, ConfirmPersonalSecrets: true,
		ProjectSpec: ProjectSpec{
			SchemaVersion: 1, WorkingDirectory: destination,
			Repositories:     []RepositorySpec{{Source: "ssh://git@example.test/repo", Branch: &empty, Destination: &destination, KnownHosts: []string{"example.test ssh-ed25519 AAAA"}}},
			Agents:           &ProjectAgents{Tools: []string{"codex"}},
			ApplicationPorts: []ApplicationPort{{Port: 3000, Label: "web", Access: &empty}},
			Secrets:          &ProjectSecretBindings{User: &platform},
			Credentials:      &ProjectCredentialBinding{Profile: "platform:id:profile-one"},
		},
	})
	if err != nil {
		t.Fatalf("create environment request: %v", err)
	}
	if request.PresetId == nil || request.Name == nil || request.TtlSeconds == nil || request.ProjectSpec == nil || request.ExpectedProfileRevision == nil {
		t.Errorf("request lost scalar presence: %#v", request)
	}
	if len(request.GetProjectSpec().GetAgents().GetTools()) != 1 || len(request.GetProjectSpec().GetApplicationPorts()) != 1 || len(request.GetProjectSpec().GetRepositories()) != 1 {
		t.Errorf("request lost collection values: %#v", request)
	}
	if request.GetIsolationTier() != codewirev1.IsolationTier_ISOLATION_TIER_CONFIDENTIAL {
		t.Errorf("request changed isolation tier: %#v", request)
	}
	if request.GetProjectSpec().GetAgents().GetTools()[0] != "codex" || request.GetProjectSpec().GetApplicationPorts()[0].GetPort() != 3000 || request.GetProjectSpec().GetRepositories()[0].GetSource() != "ssh://git@example.test/repo" || request.GetProjectSpec().GetRepositories()[0].GetDestination() != destination || len(request.GetProjectSpec().GetRepositories()[0].GetKnownHosts()) != 1 {
		t.Errorf("request changed nested values: %#v", request)
	}
	if request.GetExpectedProfileRevision() != profileRevision || !request.GetConfirmPersonalCredentials() || !request.GetConfirmPersonalSecrets() || request.GetProjectSpec().GetSecrets().GetUser() != codewirev1.ProjectStoragePlacement_PROJECT_STORAGE_PLACEMENT_PLATFORM || request.GetProjectSpec().GetCredentials().GetProfile() != "platform:id:profile-one" {
		t.Errorf("request changed source selection: %#v", request)
	}
	invalidIsolation := "container"
	if _, err := createEnvironmentRequest("org_1", CreateEnvironmentBody{IsolationTier: &invalidIsolation}); err == nil {
		t.Error("create environment request accepted an unknown isolation tier")
	}
}

func TestProjectSpecRoundTripPreservesOpaquePortableIntent(t *testing.T) {
	revision := "deadbeef"
	destination := "/workspace/app"
	cpu := uint32(2000)
	memory := uint64(16384)
	disk := uint64(40)
	local := ProjectStoragePlacementLocal
	project := &ProjectSpec{
		SchemaVersion: 1,
		Image:         "ghcr.io/example/workspace@sha256:abc",
		Repositories: []RepositorySpec{{
			Source: "ssh://git@example.test/org/app.git", Revision: &revision, Destination: &destination, KnownHosts: []string{"example.test ssh-ed25519 AAAA"},
		}},
		WorkingDirectory: "/workspace/app",
		Environment:      map[string]string{"RUST_LOG": "info"},
		Agents:           &ProjectAgents{Tools: []string{"codex"}},
		Skills:           []ProjectSkillSelection{{Source: "repository", Reference: ".agents/skills/rust", Agents: []string{"codex"}}},
		ApplicationPorts: []ApplicationPort{{Port: 8080, Label: "api"}},
		Resources:        &ProjectResources{CpuMillicores: &cpu, MemoryMib: &memory, DiskGib: &disk},
		Secrets:          &ProjectSecretBindings{Project: "development", User: &local},
		Credentials:      &ProjectCredentialBinding{Profile: "local:id:profile-one"},
	}
	protoProject, err := toProtoProjectSpec(project)
	if err != nil {
		t.Fatalf("encode project spec: %v", err)
	}
	got, err := fromProtoProjectSpec(protoProject)
	if err != nil {
		t.Fatalf("decode project spec: %v", err)
	}
	if !reflect.DeepEqual(got, project) {
		t.Errorf("project round trip mismatch (-want +got):\nwant: %#v\n got: %#v", project, got)
	}
	project.Environment["RUST_LOG"] = "changed"
	project.Credentials.Profile = "local:id:changed"
	project.Repositories[0].KnownHosts[0] = "changed"
	if protoProject.GetEnvironment()["RUST_LOG"] != "info" || protoProject.GetCredentials().GetProfile() != "local:id:profile-one" || protoProject.GetRepositories()[0].GetKnownHosts()[0] != "example.test ssh-ed25519 AAAA" {
		t.Errorf("protobuf request aliases caller-owned project values: %#v", protoProject)
	}
}

func TestProjectSpecRejectsUnknownPersonalSecretPlacement(t *testing.T) {
	unknown := codewirev1.ProjectStoragePlacement_PROJECT_STORAGE_PLACEMENT_UNSPECIFIED
	if _, err := fromProtoProjectSpec(&codewirev1.ProjectSpec{Secrets: &codewirev1.ProjectSecretBindings{User: &unknown}}); err == nil {
		t.Fatal("project conversion silently dropped a present unknown personal secret source")
	}
	invalid := ProjectStoragePlacement("foreign")
	if _, err := toProtoProjectSpec(&ProjectSpec{Secrets: &ProjectSecretBindings{User: &invalid}}); err == nil {
		t.Fatal("project conversion accepted an unknown personal secret source")
	}
}

func projectStoragePlacementPointer(value ProjectStoragePlacement) *ProjectStoragePlacement {
	return &value
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

func testStringPointer(value string) *string { return &value }
func testBoolPointer(value bool) *bool       { return &value }
func testInt32Pointer(value int32) *int32    { return &value }
func testInt64Pointer(value int64) *int64    { return &value }
