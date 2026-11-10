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
	resizePlanCoverageOnce      sync.Once
	resizePlanCoverageErr       error
	resizeOperationCoverageOnce sync.Once
	resizeOperationCoverageErr  error
	resizeRequestCoverageOnce   sync.Once
	resizeRequestCoverageErr    error
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

func copyUint32Pointer(value *uint32) *uint32 {
	if value == nil {
		return nil
	}
	copy := *value
	return &copy
}

func copyUint64Pointer(value *uint64) *uint64 {
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
		return Preset{}, fmt.Errorf("codewire: preset response omitted preset")
	}
	createdAt, err := formatSDKTimestamp("preset created_at", preset.GetCreatedAt())
	if err != nil {
		return Preset{}, err
	}
	if preset.GetProjectSpec() == nil {
		return Preset{}, fmt.Errorf("codewire: preset response omitted project_spec")
	}
	projectSpec, err := fromProtoProjectSpec(preset.GetProjectSpec())
	if err != nil {
		return Preset{}, err
	}
	var ttl *int64
	if preset.DefaultTtlSeconds != nil {
		value := int64(*preset.DefaultTtlSeconds)
		ttl = &value
	}
	return Preset{
		BuildError:        copyStringPointer(preset.BuildError),
		BuildStatus:       preset.GetBuildStatus(),
		CreatedAt:         valueOrEmpty(createdAt),
		DefaultTtlSeconds: ttl,
		Description:       copyStringPointer(preset.Description),
		Id:                preset.GetId(),
		Language:          copyStringPointer(preset.Language),
		Name:              preset.GetName(),
		Official:          preset.GetOfficial(),
		OrgId:             copyStringPointer(preset.OrgId),
		Slug:              copyStringPointer(preset.Slug),
		ProjectSpec:       *projectSpec,
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

func fromProtoApplicationPorts(ports []*codewirev1.ApplicationPort) *[]ApplicationPort {
	if len(ports) == 0 {
		return nil
	}
	converted := make([]ApplicationPort, 0, len(ports))
	for _, port := range ports {
		converted = append(converted, ApplicationPort{
			Access: stringPointer(port.GetAccess()), Label: port.GetLabel(), Port: int64(port.GetPort()),
		})
	}
	return &converted
}

func fromProtoRepositorySpecs(repositories []*codewirev1.RepositorySpec) *[]RepositorySpec {
	if len(repositories) == 0 {
		return nil
	}
	converted := make([]RepositorySpec, 0, len(repositories))
	for _, repository := range repositories {
		converted = append(converted, RepositorySpec{
			Source: repository.GetSource(), Branch: stringPointer(repository.GetBranch()), Destination: stringPointer(repository.GetDestination()),
			Revision: stringPointer(repository.GetRevision()), KnownHosts: append([]string(nil), repository.GetKnownHosts()...),
		})
	}
	return &converted
}

func createPresetRequest(orgID string, body CreatePresetBody) (*codewirev1.CreatePresetRequest, error) {
	if err := ensurePresetConverterCoverage(); err != nil {
		return nil, err
	}
	ttl, err := int32FromInt64("default_ttl_seconds", body.DefaultTtlSeconds)
	if err != nil {
		return nil, err
	}
	projectSpec, err := toProtoProjectSpec(&body.ProjectSpec)
	if err != nil {
		return nil, err
	}
	return &codewirev1.CreatePresetRequest{
		OrgId: orgID, Name: body.Name, Slug: valueOrEmpty(body.Slug), Description: copyStringPointer(body.Description),
		DefaultTtlSeconds: ttl, ProjectSpec: projectSpec,
	}, nil
}

func updatePresetRequest(orgID, presetID string, body UpdatePresetBody) (*codewirev1.UpdatePresetRequest, error) {
	if err := ensurePresetConverterCoverage(); err != nil {
		return nil, err
	}
	ttl, err := int32FromInt64("default_ttl_seconds", body.DefaultTtlSeconds)
	if err != nil {
		return nil, err
	}
	projectSpec, err := toProtoProjectSpec(body.ProjectSpec)
	if err != nil {
		return nil, err
	}
	return &codewirev1.UpdatePresetRequest{
		OrgId: orgID, PresetId: presetID, Name: copyStringPointer(body.Name), Description: copyStringPointer(body.Description),
		Slug: copyStringPointer(body.Slug), DefaultTtlSeconds: ttl, ProjectSpec: projectSpec,
	}, nil
}

func copyStringMapPointer(value *map[string]string) map[string]string {
	if value == nil {
		return nil
	}
	return copyStringMap(*value)
}

func toProtoApplicationPorts(ports *[]ApplicationPort) ([]*codewirev1.ApplicationPort, error) {
	if ports == nil {
		return nil, nil
	}
	converted := make([]*codewirev1.ApplicationPort, 0, len(*ports))
	for _, port := range *ports {
		if port.Port < math.MinInt32 || port.Port > math.MaxInt32 {
			return nil, fmt.Errorf("codewire: app port is outside the API integer range")
		}
		converted = append(converted, &codewirev1.ApplicationPort{Port: int32(port.Port), Label: port.Label, Access: valueOrEmpty(port.Access)})
	}
	return converted, nil
}

func toProtoRepositorySpecs(repositories *[]RepositorySpec) []*codewirev1.RepositorySpec {
	if repositories == nil {
		return nil
	}
	converted := make([]*codewirev1.RepositorySpec, 0, len(*repositories))
	for _, repository := range *repositories {
		converted = append(converted, &codewirev1.RepositorySpec{
			Source: repository.Source, Branch: valueOrEmpty(repository.Branch), Destination: valueOrEmpty(repository.Destination),
			Revision: valueOrEmpty(repository.Revision), KnownHosts: append([]string(nil), repository.KnownHosts...),
		})
	}
	return converted
}

func fromProtoProjectSpec(value *codewirev1.ProjectSpec) (*ProjectSpec, error) {
	if value == nil {
		return nil, nil
	}
	result := &ProjectSpec{
		SchemaVersion:    value.GetSchemaVersion(),
		Preset:           value.GetPreset(),
		Image:            value.GetImage(),
		WorkingDirectory: value.GetWorkingDirectory(),
		InstallCommand:   value.GetInstallCommand(),
		StartupScript:    value.GetStartupScript(),
		Environment:      copyStringMap(value.GetEnvironment()),
	}
	if repositories := fromProtoRepositorySpecs(value.GetRepositories()); repositories != nil {
		result.Repositories = *repositories
	}
	if agents := value.GetAgents(); agents != nil {
		result.Agents = &ProjectAgents{Install: copyBoolPointer(agents.Install), Tools: append([]string(nil), agents.GetTools()...)}
	}
	for _, skill := range value.GetSkills() {
		result.Skills = append(result.Skills, ProjectSkillSelection{
			Source: projectSkillSource(skill.GetSource()), Reference: skill.GetReference(), Agents: append([]string(nil), skill.GetAgents()...),
		})
	}
	if ports := fromProtoApplicationPorts(value.GetApplicationPorts()); ports != nil {
		result.ApplicationPorts = *ports
	}
	if resources := value.GetResources(); resources != nil {
		result.Resources = &ProjectResources{
			CpuMillicores: copyUint32Pointer(resources.CpuMillicores),
			MemoryMib:     copyUint64Pointer(resources.MemoryMib),
			DiskGib:       copyUint64Pointer(resources.DiskGib),
		}
	}
	if secrets := value.GetSecrets(); secrets != nil {
		var user *ProjectStoragePlacement
		if secrets.User != nil {
			user = projectStoragePlacement(secrets.GetUser())
			if user == nil {
				return nil, fmt.Errorf("codewire: project spec has an unknown personal secret source")
			}
		}
		result.Secrets = &ProjectSecretBindings{
			Project: secrets.GetProject(), Organization: secrets.GetOrganization(), User: user,
		}
	}
	if credentials := value.GetCredentials(); credentials != nil {
		result.Credentials = &ProjectCredentialBinding{Profile: credentials.GetProfile()}
	}
	return result, nil
}

func toProtoProjectSpec(value *ProjectSpec) (*codewirev1.ProjectSpec, error) {
	if value == nil {
		return nil, nil
	}
	ports := value.ApplicationPorts
	applicationPorts, err := toProtoApplicationPorts(&ports)
	if err != nil {
		return nil, err
	}
	result := &codewirev1.ProjectSpec{
		SchemaVersion:    value.SchemaVersion,
		Preset:           value.Preset,
		Image:            value.Image,
		WorkingDirectory: value.WorkingDirectory,
		InstallCommand:   value.InstallCommand,
		StartupScript:    value.StartupScript,
		Environment:      copyStringMap(value.Environment),
		ApplicationPorts: applicationPorts,
	}
	repositories := value.Repositories
	result.Repositories = toProtoRepositorySpecs(&repositories)
	if value.Agents != nil {
		result.Agents = &codewirev1.ProjectAgents{Install: copyBoolPointer(value.Agents.Install), Tools: append([]string(nil), value.Agents.Tools...)}
	}
	for _, skill := range value.Skills {
		source, err := toProtoProjectSkillSource(skill.Source)
		if err != nil {
			return nil, err
		}
		result.Skills = append(result.Skills, &codewirev1.ProjectSkillSelection{
			Source: source, Reference: skill.Reference, Agents: append([]string(nil), skill.Agents...),
		})
	}
	if value.Resources != nil {
		result.Resources = &codewirev1.ProjectResources{
			CpuMillicores: copyUint32Pointer(value.Resources.CpuMillicores),
			MemoryMib:     copyUint64Pointer(value.Resources.MemoryMib),
			DiskGib:       copyUint64Pointer(value.Resources.DiskGib),
		}
	}
	if value.Secrets != nil {
		user, err := toProtoProjectStoragePlacement(value.Secrets.User)
		if err != nil {
			return nil, err
		}
		result.Secrets = &codewirev1.ProjectSecretBindings{
			Project: value.Secrets.Project, Organization: value.Secrets.Organization, User: user,
		}
	}
	if value.Credentials != nil {
		result.Credentials = &codewirev1.ProjectCredentialBinding{Profile: value.Credentials.Profile}
	}
	return result, nil
}

func projectStoragePlacement(value codewirev1.ProjectStoragePlacement) *ProjectStoragePlacement {
	var placement ProjectStoragePlacement
	switch value {
	case codewirev1.ProjectStoragePlacement_PROJECT_STORAGE_PLACEMENT_LOCAL:
		placement = ProjectStoragePlacementLocal
	case codewirev1.ProjectStoragePlacement_PROJECT_STORAGE_PLACEMENT_PLATFORM:
		placement = ProjectStoragePlacementPlatform
	default:
		return nil
	}
	return &placement
}

func toProtoProjectStoragePlacement(value *ProjectStoragePlacement) (*codewirev1.ProjectStoragePlacement, error) {
	if value == nil {
		return nil, nil
	}
	var placement codewirev1.ProjectStoragePlacement
	switch *value {
	case ProjectStoragePlacementLocal:
		placement = codewirev1.ProjectStoragePlacement_PROJECT_STORAGE_PLACEMENT_LOCAL
	case ProjectStoragePlacementPlatform:
		placement = codewirev1.ProjectStoragePlacement_PROJECT_STORAGE_PLACEMENT_PLATFORM
	default:
		return nil, fmt.Errorf("codewire: personal secret source must be local or platform")
	}
	return &placement, nil
}

func fromProtoEnvironmentSourceSelection(value *codewirev1.EnvironmentSourceSelection) (*EnvironmentSourceSelection, error) {
	if value == nil {
		return nil, nil
	}
	result := &EnvironmentSourceSelection{}
	if secrets := value.GetSecrets(); secrets != nil {
		result.Secrets = &ProjectSecretBindings{Project: secrets.GetProject(), Organization: secrets.GetOrganization()}
		if secrets.User != nil {
			result.Secrets.User = projectStoragePlacement(secrets.GetUser())
			if result.Secrets.User == nil {
				return nil, fmt.Errorf("codewire: environment source selection has an unknown personal secret source")
			}
		}
	}
	if credentials := value.GetCredentials(); credentials != nil {
		result.Credentials = &ProjectCredentialBinding{Profile: credentials.GetProfile()}
	}
	if value.ProfileRevision != nil {
		revision := value.GetProfileRevision()
		if err := accessProfileRevision(revision); err != nil {
			return nil, err
		}
		result.ProfileRevision = &revision
	}
	if (result.Credentials == nil) != (result.ProfileRevision == nil) {
		return nil, fmt.Errorf("codewire: environment credential selection requires an exact profile revision")
	}
	return result, nil
}

func toProtoEnvironmentSourceSelection(value EnvironmentSourceSelection) (*codewirev1.EnvironmentSourceSelection, error) {
	if (value.Credentials == nil) != (value.ProfileRevision == nil) {
		return nil, fmt.Errorf("codewire: environment credential selection requires an exact profile revision")
	}
	result := &codewirev1.EnvironmentSourceSelection{}
	if value.Secrets != nil {
		user, err := toProtoProjectStoragePlacement(value.Secrets.User)
		if err != nil {
			return nil, err
		}
		result.Secrets = &codewirev1.ProjectSecretBindings{
			Project: value.Secrets.Project, Organization: value.Secrets.Organization, User: user,
		}
	}
	if value.Credentials != nil {
		if err := accessProfileRevision(*value.ProfileRevision); err != nil {
			return nil, err
		}
		revision := *value.ProfileRevision
		result.Credentials = &codewirev1.ProjectCredentialBinding{Profile: value.Credentials.Profile}
		result.ProfileRevision = &revision
	}
	return result, nil
}

func environmentSourcesUpdateOutcome(value codewirev1.EnvironmentSourcesUpdateOutcome) (EnvironmentSourcesUpdateOutcome, error) {
	switch value {
	case codewirev1.EnvironmentSourcesUpdateOutcome_ENVIRONMENT_SOURCES_UPDATE_OUTCOME_UNCHANGED:
		return EnvironmentSourcesUpdateOutcomeUnchanged, nil
	case codewirev1.EnvironmentSourcesUpdateOutcome_ENVIRONMENT_SOURCES_UPDATE_OUTCOME_STORED:
		return EnvironmentSourcesUpdateOutcomeStored, nil
	case codewirev1.EnvironmentSourcesUpdateOutcome_ENVIRONMENT_SOURCES_UPDATE_OUTCOME_RESTART_REQUIRED:
		return EnvironmentSourcesUpdateOutcomeRestartRequired, nil
	default:
		return "", fmt.Errorf("codewire: environment sources response has an unknown outcome")
	}
}

func projectSkillSource(value codewirev1.ProjectSkillSource) string {
	switch value {
	case codewirev1.ProjectSkillSource_PROJECT_SKILL_SOURCE_REPOSITORY:
		return "repository"
	case codewirev1.ProjectSkillSource_PROJECT_SKILL_SOURCE_USER:
		return "user"
	default:
		return "unspecified"
	}
}

func toProtoProjectSkillSource(value string) (codewirev1.ProjectSkillSource, error) {
	switch value {
	case "repository":
		return codewirev1.ProjectSkillSource_PROJECT_SKILL_SOURCE_REPOSITORY, nil
	case "user":
		return codewirev1.ProjectSkillSource_PROJECT_SKILL_SOURCE_USER, nil
	default:
		return codewirev1.ProjectSkillSource_PROJECT_SKILL_SOURCE_UNSPECIFIED, fmt.Errorf("codewire: project skill source must be repository or user")
	}
}

func createEnvironmentRequest(orgID string, body CreateEnvironmentBody) (*codewirev1.CreateEnvironmentRequest, error) {
	if err := ensureEnvironmentConverterCoverage(); err != nil {
		return nil, err
	}
	ttl, err := int32FromInt64("ttl_seconds", body.TtlSeconds)
	if err != nil {
		return nil, err
	}
	isolation, err := toProtoIsolationTier(body.IsolationTier)
	if err != nil {
		return nil, err
	}
	projectSpec, err := toProtoProjectSpec(&body.ProjectSpec)
	if err != nil {
		return nil, err
	}
	if (body.ProjectSpec.Credentials == nil) != (body.ExpectedProfileRevision == nil) {
		return nil, fmt.Errorf("codewire: environment credential selection requires an exact profile revision")
	}
	if body.ExpectedProfileRevision != nil {
		if err := accessProfileRevision(*body.ExpectedProfileRevision); err != nil {
			return nil, err
		}
	}
	return &codewirev1.CreateEnvironmentRequest{
		OrgId: orgID, PresetId: copyStringPointer(body.PresetId), Name: copyStringPointer(body.Name),
		TtlSeconds: ttl, IsolationTier: isolation, ProjectSpec: projectSpec,
		ExpectedProfileRevision:    copyUint64Pointer(body.ExpectedProfileRevision),
		ConfirmPersonalCredentials: body.ConfirmPersonalCredentials, ConfirmPersonalSecrets: body.ConfirmPersonalSecrets,
		OmitApplicationPreviews: body.OmitApplicationPreviews,
		Network:                 valueOrEmpty(body.Network),
		SourceSnapshotId:        valueOrEmpty(body.SourceSnapshotId),
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
	sourceSelection, err := fromProtoEnvironmentSourceSelection(environment.GetSourceSelection())
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
		DestroyedAt: destroyedAt, DiskGb: int64(environment.GetDiskGb()), ErrorCode: stringPointer(environment.GetErrorCode()), ErrorReason: stringPointer(environment.GetErrorReason()),
		Id: environment.GetId(), IsolationTier: isolation,
		MemoryMb: int64(environment.GetMemoryMb()), Name: stringPointer(environment.GetName()),
		Network: stringPointer(environment.GetNetwork()), OrgId: environment.GetOrgId(), Ports: ports,
		NetworkState:        networkAttachmentState(environment.GetNetworkState()),
		NetworkFailure:      networkAttachmentFailure(environment.GetNetworkFailure()),
		OperationGeneration: environment.GetOperationGeneration(), SourceSelection: sourceSelection,
		PresetId: stringPointer(environment.GetPresetId()), PresetName: stringPointer(environment.GetPresetName()),
		Protected: environment.GetProtected(), Recoverable: environment.GetRecoverable(), RetryCount: int64(environment.GetRetryCount()),
		SetupComplete: environment.GetSetupComplete(), SetupError: stringPointer(environment.GetSetupError()),
		SetupPhase: int64(environment.GetSetupPhase()), ShutdownAt: shutdownAt, StartedAt: startedAt,
		State: environmentState(environment.GetState()), StateChangedAt: valueOrEmpty(stateChangedAt), StoppedAt: stoppedAt,
		TotalRunningSeconds: int64(environment.GetTotalRunningSeconds()), TtlSeconds: ttl, Type: environment.GetType(),
	}, nil
}

func toProtoEnvironmentResources(resources EnvironmentResources) (*codewirev1.EnvironmentResources, error) {
	cpu, err := int32FromInt64("cpu_millicores", &resources.CpuMillicores)
	if err != nil {
		return nil, err
	}
	memory, err := int32FromInt64("memory_mb", &resources.MemoryMb)
	if err != nil {
		return nil, err
	}
	disk, err := int32FromInt64("disk_gb", &resources.DiskGb)
	if err != nil {
		return nil, err
	}
	return &codewirev1.EnvironmentResources{
		CpuMillicores: valueOrZero(cpu),
		MemoryMb:      valueOrZero(memory),
		DiskGb:        valueOrZero(disk),
	}, nil
}

func fromProtoEnvironmentResources(resources *codewirev1.EnvironmentResources) *EnvironmentResources {
	if resources == nil {
		return nil
	}
	return &EnvironmentResources{
		CpuMillicores: int64(resources.GetCpuMillicores()),
		MemoryMb:      int64(resources.GetMemoryMb()),
		DiskGb:        int64(resources.GetDiskGb()),
	}
}

func fromProtoEnvironmentResizePlan(plan *codewirev1.EnvironmentResizePlan) (EnvironmentResizePlan, error) {
	if err := ensureResizePlanConverterCoverage(); err != nil {
		return EnvironmentResizePlan{}, err
	}
	if plan == nil {
		return EnvironmentResizePlan{}, nil
	}
	return EnvironmentResizePlan{
		PreviousResources:              fromProtoEnvironmentResources(plan.GetPreviousResources()),
		DesiredResources:               fromProtoEnvironmentResources(plan.GetDesiredResources()),
		ExecutionMode:                  environmentResizeExecutionMode(plan.GetExecutionMode()),
		ActiveSessionCount:             int64(plan.GetActiveSessionCount()),
		ActiveSessionsWillBeTerminated: plan.GetActiveSessionsWillBeTerminated(),
		Reason:                         plan.GetReason(),
		Warnings:                       append([]string{}, plan.GetWarnings()...),
	}, nil
}

func fromProtoEnvironmentResizeOperation(operation *codewirev1.EnvironmentResizeOperation) (EnvironmentResizeOperation, error) {
	if err := ensureResizeOperationConverterCoverage(); err != nil {
		return EnvironmentResizeOperation{}, err
	}
	if operation == nil {
		return EnvironmentResizeOperation{}, nil
	}
	createdAt, err := formatSDKTimestamp("environment resize created_at", operation.GetCreatedAt())
	if err != nil {
		return EnvironmentResizeOperation{}, err
	}
	updatedAt, err := formatSDKTimestamp("environment resize updated_at", operation.GetUpdatedAt())
	if err != nil {
		return EnvironmentResizeOperation{}, err
	}
	completedAt, err := formatSDKTimestamp("environment resize completed_at", operation.GetCompletedAt())
	if err != nil {
		return EnvironmentResizeOperation{}, err
	}
	var failure *EnvironmentResizeFailure
	if operation.GetFailure() != nil {
		failure = &EnvironmentResizeFailure{
			Code:    operation.GetFailure().GetCode(),
			Message: operation.GetFailure().GetMessage(),
		}
	}
	return EnvironmentResizeOperation{
		Id:                   operation.GetId(),
		EnvironmentId:        operation.GetEnvironmentId(),
		RequestId:            operation.GetRequestId(),
		PreviousResources:    fromProtoEnvironmentResources(operation.GetPreviousResources()),
		DesiredResources:     fromProtoEnvironmentResources(operation.GetDesiredResources()),
		LastAppliedResources: fromProtoEnvironmentResources(operation.GetLastAppliedResources()),
		State:                environmentResizeOperationState(operation.GetState()),
		DisruptionPolicy:     environmentResizeDisruptionPolicy(operation.GetDisruptionPolicy()),
		PlannedMode:          environmentResizeExecutionMode(operation.GetPlannedMode()),
		AppliedMode:          environmentResizeExecutionMode(operation.GetAppliedMode()),
		PodReplaced:          operation.GetPodReplaced(),
		Failure:              failure,
		CreatedAt:            createdAt,
		UpdatedAt:            updatedAt,
		CompletedAt:          completedAt,
	}, nil
}

func environmentResizeOperationState(state codewirev1.EnvironmentResizeOperationState) string {
	switch state {
	case codewirev1.EnvironmentResizeOperationState_ENVIRONMENT_RESIZE_OPERATION_STATE_UNSPECIFIED:
		return "unspecified"
	case codewirev1.EnvironmentResizeOperationState_ENVIRONMENT_RESIZE_OPERATION_STATE_PENDING:
		return "pending"
	case codewirev1.EnvironmentResizeOperationState_ENVIRONMENT_RESIZE_OPERATION_STATE_APPLYING:
		return "applying"
	case codewirev1.EnvironmentResizeOperationState_ENVIRONMENT_RESIZE_OPERATION_STATE_RESTARTING:
		return "restarting"
	case codewirev1.EnvironmentResizeOperationState_ENVIRONMENT_RESIZE_OPERATION_STATE_COMPLETED:
		return "completed"
	case codewirev1.EnvironmentResizeOperationState_ENVIRONMENT_RESIZE_OPERATION_STATE_FAILED:
		return "failed"
	default:
		return "unknown"
	}
}

func environmentResizeDisruptionPolicy(policy codewirev1.EnvironmentResizeDisruptionPolicy) string {
	switch policy {
	case codewirev1.EnvironmentResizeDisruptionPolicy_ENVIRONMENT_RESIZE_DISRUPTION_POLICY_UNSPECIFIED:
		return "unspecified"
	case codewirev1.EnvironmentResizeDisruptionPolicy_ENVIRONMENT_RESIZE_DISRUPTION_POLICY_LIVE_ONLY:
		return "live_only"
	case codewirev1.EnvironmentResizeDisruptionPolicy_ENVIRONMENT_RESIZE_DISRUPTION_POLICY_ALLOW_RESTART:
		return "allow_restart"
	default:
		return "unknown"
	}
}

func environmentResizeExecutionMode(mode codewirev1.EnvironmentResizeExecutionMode) string {
	switch mode {
	case codewirev1.EnvironmentResizeExecutionMode_ENVIRONMENT_RESIZE_EXECUTION_MODE_UNSPECIFIED:
		return "unspecified"
	case codewirev1.EnvironmentResizeExecutionMode_ENVIRONMENT_RESIZE_EXECUTION_MODE_NOOP:
		return "noop"
	case codewirev1.EnvironmentResizeExecutionMode_ENVIRONMENT_RESIZE_EXECUTION_MODE_APPLY_ON_START:
		return "apply_on_start"
	case codewirev1.EnvironmentResizeExecutionMode_ENVIRONMENT_RESIZE_EXECUTION_MODE_IN_PLACE:
		return "in_place"
	case codewirev1.EnvironmentResizeExecutionMode_ENVIRONMENT_RESIZE_EXECUTION_MODE_RESTART:
		return "restart"
	default:
		return "unknown"
	}
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

func networkAttachmentState(state codewirev1.NetworkAttachmentState) *string {
	var name string
	switch state {
	case codewirev1.NetworkAttachmentState_NETWORK_ATTACHMENT_STATE_UNSPECIFIED:
		return nil
	case codewirev1.NetworkAttachmentState_NETWORK_ATTACHMENT_STATE_PENDING:
		name = "pending"
	case codewirev1.NetworkAttachmentState_NETWORK_ATTACHMENT_STATE_ATTACHED:
		name = "attached"
	case codewirev1.NetworkAttachmentState_NETWORK_ATTACHMENT_STATE_FAILED:
		name = "failed"
	case codewirev1.NetworkAttachmentState_NETWORK_ATTACHMENT_STATE_REVOKED:
		name = "revoked"
	default:
		name = "unknown"
	}
	return &name
}

func networkAttachmentFailure(failure codewirev1.NetworkAttachmentFailure) *string {
	var name string
	switch failure {
	case codewirev1.NetworkAttachmentFailure_NETWORK_ATTACHMENT_FAILURE_UNSPECIFIED:
		return nil
	case codewirev1.NetworkAttachmentFailure_NETWORK_ATTACHMENT_FAILURE_MESH_UNREACHABLE:
		name = "mesh_unreachable"
	case codewirev1.NetworkAttachmentFailure_NETWORK_ATTACHMENT_FAILURE_NETWORK_NOT_FOUND:
		name = "network_not_found"
	case codewirev1.NetworkAttachmentFailure_NETWORK_ATTACHMENT_FAILURE_NOT_A_MEMBER:
		name = "not_a_member"
	case codewirev1.NetworkAttachmentFailure_NETWORK_ATTACHMENT_FAILURE_NODE_NAME_TAKEN:
		name = "node_name_taken"
	case codewirev1.NetworkAttachmentFailure_NETWORK_ATTACHMENT_FAILURE_REFUSED:
		name = "refused"
	default:
		name = "unknown"
	}
	return &name
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
		if err := ensureProjectSpecConverterCoverage(); err != nil {
			presetConverterCoverageErr = err
			return
		}
		messages := codewirev1.File_codewire_v1_preset_proto.Messages()
		for name, fields := range map[string]map[protoreflect.FieldNumber]protoreflect.Name{
			"Preset":              {1: "id", 2: "org_id", 3: "name", 4: "slug", 5: "language", 6: "official", 7: "description", 8: "build_status", 9: "build_error", 13: "default_ttl_seconds", 17: "created_at", 18: "project_spec"},
			"CreatePresetRequest": {1: "org_id", 2: "name", 3: "slug", 4: "description", 8: "default_ttl_seconds", 21: "project_spec"},
			"UpdatePresetRequest": {1: "org_id", 2: "preset_id", 3: "name", 4: "description", 5: "slug", 9: "default_ttl_seconds", 22: "project_spec"},
		} {
			if err := ensureDescriptorCoverage("preset "+name, messages.ByName(protoreflect.Name(name)), fields); err != nil {
				presetConverterCoverageErr = err
				return
			}
		}
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

func ensureProjectSpecConverterCoverage() error {
	messages := codewirev1.File_codewire_v1_common_proto.Messages()
	for name, fields := range map[string]map[protoreflect.FieldNumber]protoreflect.Name{
		"RepositorySpec":           {1: "source", 2: "branch", 3: "destination", 4: "revision", 5: "known_hosts"},
		"ApplicationPort":          {1: "port", 2: "label", 3: "access"},
		"ProjectAgents":            {1: "install", 2: "tools"},
		"ProjectSkillSelection":    {1: "source", 2: "reference", 3: "agents"},
		"ProjectResources":         {1: "cpu_millicores", 2: "memory_mib", 3: "disk_gib"},
		"ProjectSecretBindings":    {1: "project", 4: "organization", 6: "user"},
		"ProjectCredentialBinding": {1: "profile"},
		"ProjectSpec": {
			1: "schema_version", 2: "preset", 3: "image", 4: "repositories", 5: "working_directory", 6: "install_command", 7: "startup_script", 8: "environment", 9: "agents", 11: "skills", 12: "application_ports", 13: "resources", 14: "secrets", 18: "credentials",
		},
	} {
		if err := ensureDescriptorCoverage("project "+name, messages.ByName(protoreflect.Name(name)), fields); err != nil {
			return err
		}
	}
	return nil
}

func ensureEnvironmentConverterCoverage() error {
	environmentCoverageOnce.Do(func() {
		if err := ensureProjectSpecConverterCoverage(); err != nil {
			environmentCoverageErr = err
			return
		}
		messages := codewirev1.File_codewire_v1_environment_proto.Messages()
		environmentCoverageErr = ensureDescriptorCoverage("environment", messages.ByName("Environment"), map[protoreflect.FieldNumber]protoreflect.Name{
			1: "id", 2: "org_id", 3: "created_by", 4: "preset_id", 5: "type", 6: "name", 7: "state", 8: "desired_state", 9: "error_reason", 10: "recoverable", 11: "state_changed_at", 12: "retry_count", 13: "setup_phase", 14: "setup_complete", 15: "setup_error", 16: "ttl_seconds", 17: "shutdown_at", 18: "cpu_millicores", 19: "memory_mb", 20: "disk_gb", 21: "total_running_seconds", 22: "created_at", 23: "started_at", 24: "stopped_at", 25: "destroyed_at", 26: "protected", 27: "deletion_requested_at", 28: "deletion_grace_until", 29: "preset_name", 30: "network", 31: "ports", 32: "isolation_tier",
			33: "operation_generation", 34: "source_selection", 35: "network_state", 36: "network_failure", 37: "error_code",
		})
		if environmentCoverageErr != nil {
			return
		}
		environmentCoverageErr = ensureDescriptorCoverage("create environment request", messages.ByName("CreateEnvironmentRequest"), map[protoreflect.FieldNumber]protoreflect.Name{
			// The SDK always names its organization by org_id, so organization (32) stays unset.
			1: "org_id", 2: "preset_id", 3: "name", 7: "ttl_seconds", 24: "isolation_tier", 25: "project_spec", 26: "expected_profile_revision", 27: "confirm_personal_credentials", 28: "confirm_personal_secrets", 29: "omit_application_previews", 30: "network", 31: "source_snapshot_id", 32: "organization",
		})
		if environmentCoverageErr != nil {
			return
		}
		environmentCoverageErr = ensureDescriptorCoverage("environment source selection", messages.ByName("EnvironmentSourceSelection"), map[protoreflect.FieldNumber]protoreflect.Name{
			1: "secrets", 2: "credentials", 3: "profile_revision",
		})
		if environmentCoverageErr != nil {
			return
		}
		environmentCoverageErr = ensureDescriptorCoverage("update environment sources request", messages.ByName("UpdateEnvironmentSourcesRequest"), map[protoreflect.FieldNumber]protoreflect.Name{
			1: "org_id", 2: "environment_id", 3: "expected_operation_generation", 4: "expected", 5: "replacement", 6: "allow_restart", 7: "confirm_personal_credentials", 8: "confirm_personal_secrets",
		})
		if environmentCoverageErr != nil {
			return
		}
		environmentCoverageErr = ensureDescriptorCoverage("update environment sources response", messages.ByName("UpdateEnvironmentSourcesResponse"), map[protoreflect.FieldNumber]protoreflect.Name{
			1: "environment_id", 2: "operation_generation", 3: "selection", 4: "outcome",
		})
	})
	return environmentCoverageErr
}

func ensureResizePlanConverterCoverage() error {
	resizePlanCoverageOnce.Do(func() {
		messages := codewirev1.File_codewire_v1_environment_proto.Messages()
		if err := ensureDescriptorCoverage("environment resources", messages.ByName("EnvironmentResources"), map[protoreflect.FieldNumber]protoreflect.Name{
			1: "cpu_millicores", 2: "memory_mb", 3: "disk_gb",
		}); err != nil {
			resizePlanCoverageErr = err
			return
		}
		resizePlanCoverageErr = ensureDescriptorCoverage("environment resize plan", messages.ByName("EnvironmentResizePlan"), map[protoreflect.FieldNumber]protoreflect.Name{
			1: "previous_resources", 2: "desired_resources", 3: "execution_mode", 4: "active_session_count",
			5: "active_sessions_will_be_terminated", 6: "reason", 7: "warnings",
		})
	})
	return resizePlanCoverageErr
}

func ensureResizeOperationConverterCoverage() error {
	resizeOperationCoverageOnce.Do(func() {
		messages := codewirev1.File_codewire_v1_environment_proto.Messages()
		if err := ensureDescriptorCoverage("environment resources", messages.ByName("EnvironmentResources"), map[protoreflect.FieldNumber]protoreflect.Name{
			1: "cpu_millicores", 2: "memory_mb", 3: "disk_gb",
		}); err != nil {
			resizeOperationCoverageErr = err
			return
		}
		if err := ensureDescriptorCoverage("environment resize failure", messages.ByName("EnvironmentResizeFailure"), map[protoreflect.FieldNumber]protoreflect.Name{
			1: "code", 2: "message",
		}); err != nil {
			resizeOperationCoverageErr = err
			return
		}
		resizeOperationCoverageErr = ensureDescriptorCoverage("environment resize operation", messages.ByName("EnvironmentResizeOperation"), map[protoreflect.FieldNumber]protoreflect.Name{
			1: "id", 2: "environment_id", 3: "request_id", 4: "previous_resources", 5: "desired_resources",
			6: "last_applied_resources", 7: "state", 8: "failure", 9: "created_at", 10: "updated_at",
			11: "completed_at", 12: "disruption_policy", 13: "planned_mode", 14: "applied_mode", 15: "pod_replaced",
		})
	})
	return resizeOperationCoverageErr
}

func ensureResizeRequestConverterCoverage() error {
	resizeRequestCoverageOnce.Do(func() {
		messages := codewirev1.File_codewire_v1_environment_proto.Messages()
		if err := ensureDescriptorCoverage("plan environment resize request", messages.ByName("PlanEnvironmentResizeRequest"), map[protoreflect.FieldNumber]protoreflect.Name{
			1: "org_id", 2: "environment_id", 3: "cpu_millicores", 4: "memory_mb", 5: "disk_gb",
		}); err != nil {
			resizeRequestCoverageErr = err
			return
		}
		if err := ensureDescriptorCoverage("resize environment request", messages.ByName("ResizeEnvironmentRequest"), map[protoreflect.FieldNumber]protoreflect.Name{
			1: "org_id", 2: "environment_id", 3: "cpu_millicores", 4: "memory_mb", 5: "disk_gb",
			6: "request_id", 7: "force", 8: "disruption_policy",
		}); err != nil {
			resizeRequestCoverageErr = err
			return
		}
		resizeRequestCoverageErr = ensureDescriptorCoverage("get environment resize operation request", messages.ByName("GetEnvironmentResizeOperationRequest"), map[protoreflect.FieldNumber]protoreflect.Name{
			1: "org_id", 2: "environment_id", 3: "operation_id",
		})
	})
	return resizeRequestCoverageErr
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
