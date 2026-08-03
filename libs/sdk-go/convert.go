package codewire

import (
	"fmt"
	"math"
	"sync"
	"time"

	codewirev1 "github.com/codewiresh/codewire/libs/gen-go/codewire/v1"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/types/known/timestamppb"
)

var (
	apiKeyConverterCoverageOnce sync.Once
	apiKeyConverterCoverageErr  error
	presetConverterCoverageOnce sync.Once
	presetConverterCoverageErr  error
	secretMetadataCoverageOnce  sync.Once
	secretMetadataCoverageErr   error
	secretProjectCoverageOnce   sync.Once
	secretProjectCoverageErr    error
	environmentCoverageOnce     sync.Once
	environmentCoverageErr      error
	portCoverageOnce            sync.Once
	portCoverageErr             error
	fileEntryCoverageOnce       sync.Once
	fileEntryCoverageErr        error
)

func fromProtoAPIKey(key *codewirev1.ApiKey) (APIKey, error) {
	if err := ensureAPIKeyConverterCoverage(); err != nil {
		return APIKey{}, err
	}
	if key == nil {
		return APIKey{}, nil
	}

	lastUsedAt, err := formatAPIKeyTimestamp("last_used_at", key.GetLastUsedAt())
	if err != nil {
		return APIKey{}, err
	}
	expiresAt, err := formatAPIKeyTimestamp("expires_at", key.GetExpiresAt())
	if err != nil {
		return APIKey{}, err
	}
	disabledAt, err := formatAPIKeyTimestamp("disabled_at", key.GetDisabledAt())
	if err != nil {
		return APIKey{}, err
	}
	createdAt, err := formatAPIKeyTimestamp("created_at", key.GetCreatedAt())
	if err != nil {
		return APIKey{}, err
	}

	scopes := append([]string(nil), key.GetScopes()...)
	return APIKey{
		CreatedAt:      valueOrEmpty(createdAt),
		CreatedByEmail: stringPointer(key.GetCreatedByEmail()),
		CreatedByName:  stringPointer(key.GetCreatedByName()),
		DisabledAt:     disabledAt,
		ExpiresAt:      expiresAt,
		Id:             key.GetId(),
		KeyPrefix:      key.GetKeyPrefix(),
		LastUsedAt:     lastUsedAt,
		Name:           key.GetName(),
		OrgId:          key.GetOrgId(),
		Scopes:         &scopes,
		UserId:         key.GetUserId(),
	}, nil
}

func fromProtoCreateAPIKeyResponse(response *codewirev1.CreateApiKeyResponse) (CreateAPIKeyResponse, error) {
	key, err := fromProtoAPIKey(response.GetApiKey())
	if err != nil {
		return CreateAPIKeyResponse{}, err
	}
	return CreateAPIKeyResponse{
		CreatedAt:      key.CreatedAt,
		CreatedByEmail: key.CreatedByEmail,
		CreatedByName:  key.CreatedByName,
		DisabledAt:     key.DisabledAt,
		ExpiresAt:      key.ExpiresAt,
		Id:             key.Id,
		Key:            response.GetKey(),
		KeyPrefix:      key.KeyPrefix,
		LastUsedAt:     key.LastUsedAt,
		Name:           key.Name,
		OrgId:          key.OrgId,
		Scopes:         key.Scopes,
		UserId:         key.UserId,
	}, nil
}

func formatAPIKeyTimestamp(name string, timestamp *timestamppb.Timestamp) (*string, error) {
	if timestamp == nil {
		return nil, nil
	}
	if err := timestamp.CheckValid(); err != nil {
		return nil, fmt.Errorf("codewire: API key %s: invalid timestamp: %w", name, err)
	}
	formatted := timestamp.AsTime().UTC().Format(time.RFC3339)
	return &formatted, nil
}

func ensureAPIKeyConverterCoverage() error {
	apiKeyConverterCoverageOnce.Do(func() {
		expected := map[protoreflect.FieldNumber]protoreflect.Name{
			1: "id", 2: "user_id", 3: "org_id", 4: "name", 5: "key_prefix", 6: "scopes",
			7: "last_used_at", 8: "expires_at", 9: "disabled_at", 10: "created_at", 11: "created_by_name", 12: "created_by_email",
		}
		fields := codewirev1.File_codewire_v1_api_key_proto.Messages().ByName("ApiKey").Fields()
		if fields.Len() != len(expected) {
			apiKeyConverterCoverageErr = fmt.Errorf("codewire: API key converter covers %d descriptor fields, expected %d", fields.Len(), len(expected))
			return
		}
		for i := 0; i < fields.Len(); i++ {
			field := fields.Get(i)
			if expectedName, ok := expected[field.Number()]; !ok || expectedName != field.Name() {
				apiKeyConverterCoverageErr = fmt.Errorf("codewire: API key converter does not cover descriptor field %s", fields.Get(i).FullName())
				return
			}
		}
	})
	return apiKeyConverterCoverageErr
}

func valueOrEmpty(value *string) string {
	if value == nil {
		return ""
	}
	return *value
}

func stringPointer(value string) *string {
	if value == "" {
		return nil
	}
	return &value
}

func copyStringPointer(value *string) *string {
	if value == nil {
		return nil
	}
	copy := *value
	return &copy
}

func copyBoolPointer(value *bool) *bool {
	if value == nil {
		return nil
	}
	copy := *value
	return &copy
}

func copyStringMap(value map[string]string) map[string]string {
	if value == nil {
		return nil
	}
	copy := make(map[string]string, len(value))
	for key, item := range value {
		copy[key] = item
	}
	return copy
}

func int64Pointer(value int64) *int64 {
	return &value
}

func int32FromInt64(name string, value *int64) (*int32, error) {
	if value == nil {
		return nil, nil
	}
	if *value < math.MinInt32 || *value > math.MaxInt32 {
		return nil, fmt.Errorf("codewire: %s is outside the API integer range", name)
	}
	converted := int32(*value)
	return &converted, nil
}

func fromProtoPreset(preset *codewirev1.Preset) (Preset, error) {
	if err := ensurePresetConverterCoverage(); err != nil {
		return Preset{}, err
	}
	if preset == nil {
		return Preset{}, nil
	}
	createdAt, err := formatSDKTimestamp("preset created_at", preset.GetCreatedAt())
	if err != nil {
		return Preset{}, err
	}
	defaultSetupConfig, err := fromProtoSetupConfig(preset.GetDefaultSetupConfig())
	if err != nil {
		return Preset{}, err
	}
	var ttl *int64
	if preset.DefaultTtlSeconds != nil {
		value := int64(*preset.DefaultTtlSeconds)
		ttl = &value
	}
	return Preset{
		BuildError:           copyStringPointer(preset.BuildError),
		BuildStatus:          preset.GetBuildStatus(),
		CreatedAt:            valueOrEmpty(createdAt),
		DefaultCpuMillicores: int64(preset.GetDefaultCpuMillicores()),
		DefaultDiskGb:        int64(preset.GetDefaultDiskGb()),
		DefaultMemoryMb:      int64(preset.GetDefaultMemoryMb()),
		DefaultSetupConfig:   defaultSetupConfig,
		DefaultTtlSeconds:    ttl,
		Description:          copyStringPointer(preset.Description),
		Id:                   preset.GetId(),
		Image:                copyStringPointer(preset.Image),
		Language:             copyStringPointer(preset.Language),
		Name:                 preset.GetName(),
		Official:             preset.GetOfficial(),
		OrgId:                copyStringPointer(preset.OrgId),
		SecretProjectId:      copyStringPointer(preset.SecretProjectId),
		Slug:                 copyStringPointer(preset.Slug),
	}, nil
}

func fromProtoSecretMetadata(secret *codewirev1.SecretMetadata) (SecretMetadata, error) {
	if err := ensureSecretMetadataConverterCoverage(); err != nil {
		return SecretMetadata{}, err
	}
	if secret == nil {
		return SecretMetadata{}, nil
	}
	createdAt, err := formatSDKTimestamp("secret created_at", secret.GetCreatedAt())
	if err != nil {
		return SecretMetadata{}, err
	}
	updatedAt, err := formatSDKTimestamp("secret updated_at", secret.GetUpdatedAt())
	if err != nil {
		return SecretMetadata{}, err
	}
	return SecretMetadata{CreatedAt: createdAt, Key: secret.GetKey(), UpdatedAt: updatedAt}, nil
}

func fromProtoSecretProject(project *codewirev1.SecretProject) (SecretProject, error) {
	if err := ensureSecretProjectConverterCoverage(); err != nil {
		return SecretProject{}, err
	}
	if project == nil {
		return SecretProject{}, nil
	}
	createdAt, err := formatSDKTimestamp("secret project created_at", project.GetCreatedAt())
	if err != nil {
		return SecretProject{}, err
	}
	var secretCount *int64
	if project.GetSecretCount() != 0 {
		secretCount = int64Pointer(project.GetSecretCount())
	}
	return SecretProject{
		CreatedAt:   valueOrEmpty(createdAt),
		Id:          project.GetId(),
		Name:        project.GetName(),
		OrgId:       project.GetOrgId(),
		SecretCount: secretCount,
	}, nil
}

func formatSDKTimestamp(name string, timestamp *timestamppb.Timestamp) (*string, error) {
	if timestamp == nil {
		return nil, nil
	}
	if err := timestamp.CheckValid(); err != nil {
		return nil, fmt.Errorf("codewire: %s: invalid timestamp: %w", name, err)
	}
	formatted := timestamp.AsTime().UTC().Format(time.RFC3339)
	return &formatted, nil
}

func fromProtoSetupConfig(config *codewirev1.SetupConfig) (*SetupConfig, error) {
	if err := ensureSetupConfigConverterCoverage(); err != nil {
		return nil, err
	}
	if config == nil {
		return nil, nil
	}
	converted := &SetupConfig{
		Agent:              stringPointer(config.GetAgent()),
		AgentEnv:           stringMapPointer(config.GetAgentEnv()),
		AppPorts:           fromProtoAppPorts(config.GetAppPorts()),
		Branch:             stringPointer(config.GetBranch()),
		EnvVars:            stringMapPointer(config.GetEnvVars()),
		IncludeOrgSecrets:  copyBoolPointer(config.IncludeOrgSecrets),
		IncludeUserSecrets: copyBoolPointer(config.IncludeUserSecrets),
		InstallAgents:      copyBoolPointer(config.InstallAgents),
		InstallCommand:     stringPointer(config.GetInstallCommand()),
		RepoUrl:            stringPointer(config.GetRepoUrl()),
		Repos:              fromProtoRepoEntries(config.GetRepos()),
		StartupScript:      stringPointer(config.GetStartupScript()),
	}
	converted.Agents = fromProtoSetupAgents(config.GetAgents())
	return converted, nil
}

func stringMapPointer(value map[string]string) *map[string]string {
	if len(value) == 0 {
		return nil
	}
	copy := copyStringMap(value)
	return &copy
}

func fromProtoSetupAgents(agents []*codewirev1.SetupAgent) *[]SetupAgent {
	if len(agents) == 0 {
		return nil
	}
	converted := make([]SetupAgent, 0, len(agents))
	for _, agent := range agents {
		converted = append(converted, SetupAgent{Type: agent.GetType()})
	}
	return &converted
}

func fromProtoAppPorts(ports []*codewirev1.AppPort) *[]AppPort {
	if len(ports) == 0 {
		return nil
	}
	converted := make([]AppPort, 0, len(ports))
	for _, port := range ports {
		converted = append(converted, AppPort{
			Access: stringPointer(port.GetAccess()), Label: port.GetLabel(), Port: int64(port.GetPort()),
		})
	}
	return &converted
}

func fromProtoRepoEntries(repos []*codewirev1.RepoEntry) *[]RepoEntry {
	if len(repos) == 0 {
		return nil
	}
	converted := make([]RepoEntry, 0, len(repos))
	for _, repo := range repos {
		converted = append(converted, RepoEntry{Url: repo.GetUrl(), Branch: stringPointer(repo.GetBranch())})
	}
	return &converted
}

func createPresetRequest(orgID string, body CreatePresetBody, secretProjectID *string) (*codewirev1.CreatePresetRequest, error) {
	cpu, err := int32FromInt64("default_cpu_millicores", body.DefaultCpuMillicores)
	if err != nil {
		return nil, err
	}
	memory, err := int32FromInt64("default_memory_mb", body.DefaultMemoryMb)
	if err != nil {
		return nil, err
	}
	disk, err := int32FromInt64("default_disk_gb", body.DefaultDiskGb)
	if err != nil {
		return nil, err
	}
	ttl, err := int32FromInt64("default_ttl_seconds", body.DefaultTtlSeconds)
	if err != nil {
		return nil, err
	}
	agents, err := toProtoSetupAgents(body.Agents)
	if err != nil {
		return nil, err
	}
	ports, err := toProtoAppPorts(body.AppPorts)
	if err != nil {
		return nil, err
	}
	return &codewirev1.CreatePresetRequest{
		OrgId: orgID, Name: body.Name, Slug: valueOrEmpty(body.Slug), Description: copyStringPointer(body.Description),
		DefaultCpuMillicores: cpu, DefaultMemoryMb: memory, DefaultDiskGb: disk, DefaultTtlSeconds: ttl,
		Image: valueOrEmpty(body.Image), InstallCommand: valueOrEmpty(body.InstallCommand), StartupScript: valueOrEmpty(body.StartupScript),
		EnvVars: copyStringMapPointer(body.EnvVars), Agents: agents, InstallAgents: copyBoolPointer(body.InstallAgents),
		Agent: valueOrEmpty(body.Agent), AgentEnv: copyStringMapPointer(body.AgentEnv), AppPorts: ports,
		IncludeOrgSecrets: copyBoolPointer(body.IncludeOrgSecrets), IncludeUserSecrets: copyBoolPointer(body.IncludeUserSecrets),
		SecretProjectId: copyStringPointer(secretProjectID),
	}, nil
}

func updatePresetRequest(orgID, presetID string, body UpdatePresetBody, secretProjectID *string) (*codewirev1.UpdatePresetRequest, error) {
	cpu, err := int32FromInt64("default_cpu_millicores", body.DefaultCpuMillicores)
	if err != nil {
		return nil, err
	}
	memory, err := int32FromInt64("default_memory_mb", body.DefaultMemoryMb)
	if err != nil {
		return nil, err
	}
	disk, err := int32FromInt64("default_disk_gb", body.DefaultDiskGb)
	if err != nil {
		return nil, err
	}
	ttl, err := int32FromInt64("default_ttl_seconds", body.DefaultTtlSeconds)
	if err != nil {
		return nil, err
	}
	agents, err := toProtoSetupAgents(body.Agents)
	if err != nil {
		return nil, err
	}
	ports, err := toProtoAppPorts(body.AppPorts)
	if err != nil {
		return nil, err
	}
	request := &codewirev1.UpdatePresetRequest{
		OrgId: orgID, PresetId: presetID, Name: copyStringPointer(body.Name), Description: copyStringPointer(body.Description),
		Slug: copyStringPointer(body.Slug), DefaultCpuMillicores: cpu, DefaultMemoryMb: memory, DefaultDiskGb: disk,
		DefaultTtlSeconds: ttl, Image: copyStringPointer(body.Image), InstallCommand: copyStringPointer(body.InstallCommand),
		StartupScript: copyStringPointer(body.StartupScript), InstallAgents: copyBoolPointer(body.InstallAgents), Agent: copyStringPointer(body.Agent),
		IncludeOrgSecrets: copyBoolPointer(body.IncludeOrgSecrets), IncludeUserSecrets: copyBoolPointer(body.IncludeUserSecrets),
		SecretProjectId: copyStringPointer(secretProjectID),
	}
	if body.EnvVars != nil {
		request.EnvVars = &codewirev1.EnvVarMap{Values: copyStringMap(*body.EnvVars)}
	}
	if body.Agents != nil {
		request.Agents = &codewirev1.AgentList{Values: agents}
	}
	if body.AgentEnv != nil {
		request.AgentEnv = &codewirev1.AgentEnvMap{Values: copyStringMap(*body.AgentEnv)}
	}
	if body.AppPorts != nil {
		request.AppPorts = &codewirev1.AppPortList{Values: ports}
	}
	return request, nil
}

func copyStringMapPointer(value *map[string]string) map[string]string {
	if value == nil {
		return nil
	}
	return copyStringMap(*value)
}

func toProtoSetupAgents(agents *[]SetupAgent) ([]*codewirev1.SetupAgent, error) {
	if agents == nil {
		return nil, nil
	}
	converted := make([]*codewirev1.SetupAgent, 0, len(*agents))
	for _, agent := range *agents {
		converted = append(converted, &codewirev1.SetupAgent{Type: agent.Type})
	}
	return converted, nil
}

func toProtoAppPorts(ports *[]AppPort) ([]*codewirev1.AppPort, error) {
	if ports == nil {
		return nil, nil
	}
	converted := make([]*codewirev1.AppPort, 0, len(*ports))
	for _, port := range *ports {
		if port.Port < math.MinInt32 || port.Port > math.MaxInt32 {
			return nil, fmt.Errorf("codewire: app port is outside the API integer range")
		}
		converted = append(converted, &codewirev1.AppPort{Port: int32(port.Port), Label: port.Label, Access: valueOrEmpty(port.Access)})
	}
	return converted, nil
}

func toProtoRepoEntries(repos *[]RepoEntry) []*codewirev1.RepoEntry {
	if repos == nil {
		return nil
	}
	converted := make([]*codewirev1.RepoEntry, 0, len(*repos))
	for _, repo := range *repos {
		converted = append(converted, &codewirev1.RepoEntry{
			Url: repo.Url, Branch: valueOrEmpty(repo.Branch),
		})
	}
	return converted
}

func createEnvironmentRequest(orgID string, body CreateEnvironmentBody) (*codewirev1.CreateEnvironmentRequest, error) {
	if err := ensureEnvironmentConverterCoverage(); err != nil {
		return nil, err
	}
	cpu, err := int32FromInt64("cpu_millicores", body.CpuMillicores)
	if err != nil {
		return nil, err
	}
	memory, err := int32FromInt64("memory_mb", body.MemoryMb)
	if err != nil {
		return nil, err
	}
	disk, err := int32FromInt64("disk_gb", body.DiskGb)
	if err != nil {
		return nil, err
	}
	ttl, err := int32FromInt64("ttl_seconds", body.TtlSeconds)
	if err != nil {
		return nil, err
	}
	agents, err := toProtoSetupAgents(body.Agents)
	if err != nil {
		return nil, err
	}
	ports, err := toProtoAppPorts(body.AppPorts)
	if err != nil {
		return nil, err
	}
	isolation, err := toProtoIsolationTier(body.IsolationTier)
	if err != nil {
		return nil, err
	}
	return &codewirev1.CreateEnvironmentRequest{
		OrgId: orgID, PresetId: copyStringPointer(body.PresetId), Name: copyStringPointer(body.Name),
		CpuMillicores: cpu, MemoryMb: memory, DiskGb: disk, TtlSeconds: ttl,
		PresetSlug: valueOrEmpty(body.PresetSlug), RepoUrl: valueOrEmpty(body.RepoUrl), Branch: valueOrEmpty(body.Branch),
		Repos: toProtoRepoEntries(body.Repos), Image: valueOrEmpty(body.Image),
		InstallCommand: valueOrEmpty(body.InstallCommand), StartupScript: valueOrEmpty(body.StartupScript),
		EnvVars: copyStringMapPointer(body.EnvVars), Agents: agents, InstallAgents: copyBoolPointer(body.InstallAgents),
		Agent: valueOrEmpty(body.Agent), AgentEnv: copyStringMapPointer(body.AgentEnv),
		SecretProject: valueOrEmpty(body.SecretProject), AppPorts: ports,
		IncludeOrgSecrets: copyBoolPointer(body.IncludeOrgSecrets), IncludeUserSecrets: copyBoolPointer(body.IncludeUserSecrets),
		IsolationTier: isolation,
	}, nil
}

func fromProtoEnvironment(environment *codewirev1.Environment) (EnvironmentData, error) {
	if err := ensureEnvironmentConverterCoverage(); err != nil {
		return EnvironmentData{}, err
	}
	if environment == nil {
		return EnvironmentData{}, nil
	}
	stateChangedAt, err := formatSDKTimestamp("environment state_changed_at", environment.GetStateChangedAt())
	if err != nil {
		return EnvironmentData{}, err
	}
	createdAt, err := formatSDKTimestamp("environment created_at", environment.GetCreatedAt())
	if err != nil {
		return EnvironmentData{}, err
	}
	shutdownAt, err := formatSDKTimestamp("environment shutdown_at", environment.GetShutdownAt())
	if err != nil {
		return EnvironmentData{}, err
	}
	startedAt, err := formatSDKTimestamp("environment started_at", environment.GetStartedAt())
	if err != nil {
		return EnvironmentData{}, err
	}
	stoppedAt, err := formatSDKTimestamp("environment stopped_at", environment.GetStoppedAt())
	if err != nil {
		return EnvironmentData{}, err
	}
	destroyedAt, err := formatSDKTimestamp("environment destroyed_at", environment.GetDestroyedAt())
	if err != nil {
		return EnvironmentData{}, err
	}
	deletionRequestedAt, err := formatSDKTimestamp("environment deletion_requested_at", environment.GetDeletionRequestedAt())
	if err != nil {
		return EnvironmentData{}, err
	}
	deletionGraceUntil, err := formatSDKTimestamp("environment deletion_grace_until", environment.GetDeletionGraceUntil())
	if err != nil {
		return EnvironmentData{}, err
	}
	ports, err := fromProtoEnvironmentPorts(environment.GetPorts())
	if err != nil {
		return EnvironmentData{}, err
	}
	isolation, err := isolationTier(environment.GetIsolationTier())
	if err != nil {
		return EnvironmentData{}, err
	}
	var ttl *int64
	if environment.TtlSeconds != nil {
		value := int64(*environment.TtlSeconds)
		ttl = &value
	}
	return EnvironmentData{
		CpuMillicores: int64(environment.GetCpuMillicores()), CreatedAt: valueOrEmpty(createdAt),
		CreatedBy: environment.GetCreatedBy(), DeletionGraceUntil: deletionGraceUntil,
		DeletionRequestedAt: deletionRequestedAt, DesiredState: environmentDesiredState(environment.GetDesiredState()),
		DestroyedAt: destroyedAt, DiskGb: int64(environment.GetDiskGb()), ErrorReason: stringPointer(environment.GetErrorReason()),
		Id: environment.GetId(), IsolationTier: isolation,
		MemoryMb: int64(environment.GetMemoryMb()), Name: stringPointer(environment.GetName()),
		Network: stringPointer(environment.GetNetwork()), OrgId: environment.GetOrgId(), Ports: ports,
		PresetId: stringPointer(environment.GetPresetId()), PresetName: stringPointer(environment.GetPresetName()),
		Protected: environment.GetProtected(), Recoverable: environment.GetRecoverable(), RetryCount: int64(environment.GetRetryCount()),
		SetupComplete: environment.GetSetupComplete(), SetupError: stringPointer(environment.GetSetupError()),
		SetupPhase: int64(environment.GetSetupPhase()), ShutdownAt: shutdownAt, StartedAt: startedAt,
		State: environmentState(environment.GetState()), StateChangedAt: valueOrEmpty(stateChangedAt), StoppedAt: stoppedAt,
		TotalRunningSeconds: int64(environment.GetTotalRunningSeconds()), TtlSeconds: ttl, Type: environment.GetType(),
	}, nil
}

func fromProtoEnvironmentPorts(ports []*codewirev1.Port) (*[]EnvironmentPort, error) {
	if len(ports) == 0 {
		return nil, nil
	}
	converted := make([]EnvironmentPort, 0, len(ports))
	for _, port := range ports {
		value, err := fromProtoEnvironmentPort(port)
		if err != nil {
			return nil, err
		}
		converted = append(converted, value)
	}
	return &converted, nil
}

func fromProtoEnvironmentPort(port *codewirev1.Port) (EnvironmentPort, error) {
	if err := ensurePortConverterCoverage(); err != nil {
		return EnvironmentPort{}, err
	}
	if port == nil {
		return EnvironmentPort{}, nil
	}
	createdAt, err := formatSDKTimestamp("environment port created_at", port.GetCreatedAt())
	if err != nil {
		return EnvironmentPort{}, err
	}
	return EnvironmentPort{
		Access: portAccess(port.GetAccess()), CreatedAt: valueOrEmpty(createdAt),
		EnvironmentId: port.GetEnvironmentId(), Id: port.GetId(), Label: port.GetLabel(),
		Port: int64(port.GetPort()), PreviewUrl: copyStringPointer(port.PreviewUrl),
	}, nil
}

func fromProtoFileEntry(entry *codewirev1.FileEntry) (FileEntry, error) {
	if err := ensureFileEntryConverterCoverage(); err != nil {
		return FileEntry{}, err
	}
	if entry == nil {
		return FileEntry{}, nil
	}
	modTime, err := formatSDKTimestamp("file mod_time", entry.GetModTime())
	if err != nil {
		return FileEntry{}, err
	}
	return FileEntry{
		IsDir: entry.GetIsDir(), ModTime: valueOrEmpty(modTime), Mode: fmt.Sprintf("%04o", entry.GetMode()&0o777),
		Name: entry.GetName(), Size: entry.GetSize(),
	}, nil
}

func fromProtoExecResult(result *codewirev1.ExecResponse) ExecResult {
	if result == nil {
		return ExecResult{}
	}
	return ExecResult{ExitCode: int64(result.GetExitCode()), Stdout: string(result.GetStdout()), Stderr: string(result.GetStderr())}
}

func environmentState(state codewirev1.EnvironmentState) string {
	switch state {
	case codewirev1.EnvironmentState_ENVIRONMENT_STATE_UNSPECIFIED:
		return ""
	case codewirev1.EnvironmentState_ENVIRONMENT_STATE_PENDING:
		return "pending"
	case codewirev1.EnvironmentState_ENVIRONMENT_STATE_PENDING_BUILD:
		return "pending_build"
	case codewirev1.EnvironmentState_ENVIRONMENT_STATE_BUILDING:
		return "building"
	case codewirev1.EnvironmentState_ENVIRONMENT_STATE_BUILD_FAILED:
		return "build_failed"
	case codewirev1.EnvironmentState_ENVIRONMENT_STATE_PULLING_SNAPSHOT:
		return "pulling_snapshot"
	case codewirev1.EnvironmentState_ENVIRONMENT_STATE_CREATING:
		return "creating"
	case codewirev1.EnvironmentState_ENVIRONMENT_STATE_STARTING:
		return "starting"
	case codewirev1.EnvironmentState_ENVIRONMENT_STATE_RUNNING:
		return "running"
	case codewirev1.EnvironmentState_ENVIRONMENT_STATE_STOPPING:
		return "stopping"
	case codewirev1.EnvironmentState_ENVIRONMENT_STATE_STOPPED:
		return "stopped"
	case codewirev1.EnvironmentState_ENVIRONMENT_STATE_ARCHIVING:
		return "archiving"
	case codewirev1.EnvironmentState_ENVIRONMENT_STATE_ARCHIVED:
		return "archived"
	case codewirev1.EnvironmentState_ENVIRONMENT_STATE_RESTORING:
		return "restoring"
	case codewirev1.EnvironmentState_ENVIRONMENT_STATE_RESIZING:
		return "resizing"
	case codewirev1.EnvironmentState_ENVIRONMENT_STATE_DESTROYING:
		return "destroying"
	case codewirev1.EnvironmentState_ENVIRONMENT_STATE_DESTROYED:
		return "destroyed"
	case codewirev1.EnvironmentState_ENVIRONMENT_STATE_ERROR:
		return "error"
	case codewirev1.EnvironmentState_ENVIRONMENT_STATE_UNKNOWN:
		return "unknown"
	default:
		return "unknown"
	}
}

func environmentDesiredState(state codewirev1.DesiredState) string {
	switch state {
	case codewirev1.DesiredState_DESIRED_STATE_UNSPECIFIED:
		return ""
	case codewirev1.DesiredState_DESIRED_STATE_STARTED:
		return "started"
	case codewirev1.DesiredState_DESIRED_STATE_STOPPED:
		return "stopped"
	case codewirev1.DesiredState_DESIRED_STATE_DESTROYED:
		return "destroyed"
	case codewirev1.DesiredState_DESIRED_STATE_ARCHIVED:
		return "archived"
	case codewirev1.DesiredState_DESIRED_STATE_RESIZED:
		return "resized"
	default:
		return "unknown"
	}
}

func isolationTier(tier codewirev1.IsolationTier) (string, error) {
	switch tier {
	case codewirev1.IsolationTier_ISOLATION_TIER_UNSPECIFIED,
		codewirev1.IsolationTier_ISOLATION_TIER_STANDARD:
		return "standard", nil
	case codewirev1.IsolationTier_ISOLATION_TIER_CONFIDENTIAL:
		return "confidential", nil
	default:
		return "", fmt.Errorf("codewire: unknown environment isolation tier %d", tier)
	}
}

func toProtoIsolationTier(tier *string) (codewirev1.IsolationTier, error) {
	if tier == nil || *tier == "" || *tier == "standard" {
		return codewirev1.IsolationTier_ISOLATION_TIER_STANDARD, nil
	}
	if *tier == "confidential" {
		return codewirev1.IsolationTier_ISOLATION_TIER_CONFIDENTIAL, nil
	}
	return codewirev1.IsolationTier_ISOLATION_TIER_UNSPECIFIED, fmt.Errorf("codewire: isolation_tier must be standard or confidential")
}

func toProtoEnvironmentState(state *string) codewirev1.EnvironmentState {
	if state == nil || *state == "" {
		return codewirev1.EnvironmentState_ENVIRONMENT_STATE_UNSPECIFIED
	}
	for value, wire := range map[string]codewirev1.EnvironmentState{
		"pending": codewirev1.EnvironmentState_ENVIRONMENT_STATE_PENDING, "pending_build": codewirev1.EnvironmentState_ENVIRONMENT_STATE_PENDING_BUILD,
		"building": codewirev1.EnvironmentState_ENVIRONMENT_STATE_BUILDING, "build_failed": codewirev1.EnvironmentState_ENVIRONMENT_STATE_BUILD_FAILED,
		"pulling_snapshot": codewirev1.EnvironmentState_ENVIRONMENT_STATE_PULLING_SNAPSHOT, "creating": codewirev1.EnvironmentState_ENVIRONMENT_STATE_CREATING,
		"starting": codewirev1.EnvironmentState_ENVIRONMENT_STATE_STARTING, "running": codewirev1.EnvironmentState_ENVIRONMENT_STATE_RUNNING,
		"stopping": codewirev1.EnvironmentState_ENVIRONMENT_STATE_STOPPING, "stopped": codewirev1.EnvironmentState_ENVIRONMENT_STATE_STOPPED,
		"archiving": codewirev1.EnvironmentState_ENVIRONMENT_STATE_ARCHIVING, "archived": codewirev1.EnvironmentState_ENVIRONMENT_STATE_ARCHIVED,
		"restoring": codewirev1.EnvironmentState_ENVIRONMENT_STATE_RESTORING, "resizing": codewirev1.EnvironmentState_ENVIRONMENT_STATE_RESIZING,
		"destroying": codewirev1.EnvironmentState_ENVIRONMENT_STATE_DESTROYING, "destroyed": codewirev1.EnvironmentState_ENVIRONMENT_STATE_DESTROYED,
		"error": codewirev1.EnvironmentState_ENVIRONMENT_STATE_ERROR, "unknown": codewirev1.EnvironmentState_ENVIRONMENT_STATE_UNKNOWN,
	} {
		if *state == value {
			return wire
		}
	}
	return codewirev1.EnvironmentState(-1)
}

func portAccess(access codewirev1.PortAccess) string {
	switch access {
	case codewirev1.PortAccess_PORT_ACCESS_UNSPECIFIED:
		return ""
	case codewirev1.PortAccess_PORT_ACCESS_PUBLIC:
		return "public"
	case codewirev1.PortAccess_PORT_ACCESS_ORG_MEMBERS:
		return "org_members"
	case codewirev1.PortAccess_PORT_ACCESS_CREATOR:
		return "creator"
	default:
		return "unknown"
	}
}

func toProtoPortAccess(access *string) codewirev1.PortAccess {
	if access == nil || *access == "" {
		return codewirev1.PortAccess_PORT_ACCESS_UNSPECIFIED
	}
	switch *access {
	case "public":
		return codewirev1.PortAccess_PORT_ACCESS_PUBLIC
	case "org_members":
		return codewirev1.PortAccess_PORT_ACCESS_ORG_MEMBERS
	case "creator":
		return codewirev1.PortAccess_PORT_ACCESS_CREATOR
	default:
		return codewirev1.PortAccess(-1)
	}
}

func ensurePresetConverterCoverage() error {
	presetConverterCoverageOnce.Do(func() {
		presetConverterCoverageErr = ensureDescriptorCoverage("preset", codewirev1.File_codewire_v1_preset_proto.Messages().ByName("Preset"), map[protoreflect.FieldNumber]protoreflect.Name{
			1: "id", 2: "org_id", 3: "name", 4: "slug", 5: "language", 6: "official", 7: "description", 8: "build_status", 9: "build_error", 10: "default_cpu_millicores", 11: "default_memory_mb", 12: "default_disk_gb", 13: "default_ttl_seconds", 14: "image", 15: "default_setup_config", 16: "secret_project_id", 17: "created_at",
		})
	})
	return presetConverterCoverageErr
}

func ensureSecretMetadataConverterCoverage() error {
	secretMetadataCoverageOnce.Do(func() {
		secretMetadataCoverageErr = ensureDescriptorCoverage("secret metadata", codewirev1.File_codewire_v1_secret_proto.Messages().ByName("SecretMetadata"), map[protoreflect.FieldNumber]protoreflect.Name{1: "key", 2: "created_at", 3: "updated_at"})
	})
	return secretMetadataCoverageErr
}

func ensureSecretProjectConverterCoverage() error {
	secretProjectCoverageOnce.Do(func() {
		secretProjectCoverageErr = ensureDescriptorCoverage("secret project", codewirev1.File_codewire_v1_secret_proto.Messages().ByName("SecretProject"), map[protoreflect.FieldNumber]protoreflect.Name{1: "id", 2: "org_id", 3: "name", 4: "secret_count", 5: "created_at"})
	})
	return secretProjectCoverageErr
}

func ensureSetupConfigConverterCoverage() error {
	messages := codewirev1.File_codewire_v1_common_proto.Messages()
	if err := ensureDescriptorCoverage("setup config", messages.ByName("SetupConfig"), map[protoreflect.FieldNumber]protoreflect.Name{
		1: "repo_url", 2: "branch", 3: "repos", 4: "install_command", 5: "startup_script", 6: "env_vars", 7: "agents", 8: "install_agents", 9: "agent", 10: "agent_env", 11: "app_ports", 12: "include_org_secrets", 13: "include_user_secrets",
	}); err != nil {
		return err
	}
	if err := ensureDescriptorCoverage("setup agent", messages.ByName("SetupAgent"), map[protoreflect.FieldNumber]protoreflect.Name{1: "type"}); err != nil {
		return err
	}
	if err := ensureDescriptorCoverage("app port", messages.ByName("AppPort"), map[protoreflect.FieldNumber]protoreflect.Name{1: "port", 2: "label", 3: "access"}); err != nil {
		return err
	}
	return ensureDescriptorCoverage("repo entry", messages.ByName("RepoEntry"), map[protoreflect.FieldNumber]protoreflect.Name{1: "url", 2: "branch"})
}

func ensureEnvironmentConverterCoverage() error {
	environmentCoverageOnce.Do(func() {
		environmentCoverageErr = ensureDescriptorCoverage("environment", codewirev1.File_codewire_v1_environment_proto.Messages().ByName("Environment"), map[protoreflect.FieldNumber]protoreflect.Name{
			1: "id", 2: "org_id", 3: "created_by", 4: "preset_id", 5: "type", 6: "name", 7: "state", 8: "desired_state", 9: "error_reason", 10: "recoverable", 11: "state_changed_at", 12: "retry_count", 13: "setup_phase", 14: "setup_complete", 15: "setup_error", 16: "ttl_seconds", 17: "shutdown_at", 18: "cpu_millicores", 19: "memory_mb", 20: "disk_gb", 21: "total_running_seconds", 22: "created_at", 23: "started_at", 24: "stopped_at", 25: "destroyed_at", 26: "protected", 27: "deletion_requested_at", 28: "deletion_grace_until", 29: "preset_name", 30: "network", 31: "ports", 32: "isolation_tier",
		})
		if environmentCoverageErr != nil {
			return
		}
		environmentCoverageErr = ensureDescriptorCoverage("create environment request", codewirev1.File_codewire_v1_environment_proto.Messages().ByName("CreateEnvironmentRequest"), map[protoreflect.FieldNumber]protoreflect.Name{
			1: "org_id", 2: "preset_id", 3: "name", 4: "cpu_millicores", 5: "memory_mb", 6: "disk_gb", 7: "ttl_seconds", 8: "preset_slug", 9: "repo_url", 10: "branch", 11: "repos", 12: "image", 13: "install_command", 14: "startup_script", 15: "env_vars", 16: "agents", 17: "install_agents", 18: "agent", 19: "agent_env", 20: "secret_project", 21: "app_ports", 22: "include_org_secrets", 23: "include_user_secrets", 24: "isolation_tier",
		})
	})
	return environmentCoverageErr
}

func ensurePortConverterCoverage() error {
	portCoverageOnce.Do(func() {
		portCoverageErr = ensureDescriptorCoverage("environment port", codewirev1.File_codewire_v1_port_proto.Messages().ByName("Port"), map[protoreflect.FieldNumber]protoreflect.Name{
			1: "id", 2: "environment_id", 3: "port", 4: "label", 5: "access", 6: "preview_url", 7: "created_at",
		})
	})
	return portCoverageErr
}

func ensureFileEntryConverterCoverage() error {
	fileEntryCoverageOnce.Do(func() {
		fileEntryCoverageErr = ensureDescriptorCoverage("file entry", codewirev1.File_codewire_v1_file_proto.Messages().ByName("FileEntry"), map[protoreflect.FieldNumber]protoreflect.Name{
			1: "name", 2: "size", 3: "is_dir", 4: "mode", 5: "mod_time",
		})
	})
	return fileEntryCoverageErr
}

func ensureDescriptorCoverage(name string, descriptor protoreflect.MessageDescriptor, expected map[protoreflect.FieldNumber]protoreflect.Name) error {
	fields := descriptor.Fields()
	if fields.Len() != len(expected) {
		return fmt.Errorf("codewire: %s converter covers %d descriptor fields, expected %d", name, fields.Len(), len(expected))
	}
	for i := 0; i < fields.Len(); i++ {
		field := fields.Get(i)
		if expectedName, ok := expected[field.Number()]; !ok || expectedName != field.Name() {
			return fmt.Errorf("codewire: %s converter does not cover descriptor field %s", name, field.FullName())
		}
	}
	return nil
}
