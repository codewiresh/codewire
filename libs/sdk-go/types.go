// Package codewire is the Go SDK for the Codewire API. It layers ergonomic
// types and a fluent Environment handle over generated Connect clients.
package codewire

// ApplicationPort configures an application port exposed during setup.
type ApplicationPort struct {
	Access *string `json:"access,omitempty"`
	Label  string  `json:"label"`
	Port   int64   `json:"port"`
}

// RepositorySpec configures an additional repository checked out during setup.
type RepositorySpec struct {
	Branch      *string  `json:"branch,omitempty"`
	Destination *string  `json:"destination,omitempty"`
	KnownHosts  []string `json:"known_hosts,omitempty"`
	Revision    *string  `json:"revision,omitempty"`
	Source      string   `json:"source"`
}

// ProjectAgents configures canonical setup-time agent intent.
type ProjectAgents struct {
	Install *bool    `json:"install,omitempty"`
	Tools   []string `json:"tools,omitempty"`
}

// ProjectSkillSelection selects a repository or named user skill snapshot.
type ProjectSkillSelection struct {
	Source    string   `json:"source"`
	Reference string   `json:"reference"`
	Agents    []string `json:"agents,omitempty"`
}

// ProjectResources configures portable workspace resource intent.
type ProjectResources struct {
	CpuMillicores *uint32 `json:"cpu_millicores,omitempty"`
	MemoryMib     *uint64 `json:"memory_mib,omitempty"`
	DiskGib       *uint64 `json:"disk_gib,omitempty"`
}

// ProjectStoragePlacement identifies the origin of selected personal values.
type ProjectStoragePlacement string

const (
	ProjectStoragePlacementLocal    ProjectStoragePlacement = "local"
	ProjectStoragePlacementPlatform ProjectStoragePlacement = "platform"
)

// ProjectSecretBindings selects workload-secret scopes without carrying values.
type ProjectSecretBindings struct {
	Project      string                   `json:"project,omitempty"`
	Organization bool                     `json:"organization,omitempty"`
	User         *ProjectStoragePlacement `json:"user,omitempty"`
}

// ProjectCredentialBinding selects one scope-qualified credential profile.
type ProjectCredentialBinding struct {
	Profile string `json:"profile"`
}

// ProjectSpec is the versioned placement-neutral codewire.yaml model.
type ProjectSpec struct {
	SchemaVersion    uint32                    `json:"schema_version"`
	Preset           string                    `json:"preset,omitempty"`
	Image            string                    `json:"image,omitempty"`
	Repositories     []RepositorySpec          `json:"repositories,omitempty"`
	WorkingDirectory string                    `json:"working_directory"`
	InstallCommand   string                    `json:"install_command,omitempty"`
	StartupScript    string                    `json:"startup_script,omitempty"`
	Environment      map[string]string         `json:"environment,omitempty"`
	Agents           *ProjectAgents            `json:"agents,omitempty"`
	Skills           []ProjectSkillSelection   `json:"skills,omitempty"`
	ApplicationPorts []ApplicationPort         `json:"application_ports,omitempty"`
	Resources        *ProjectResources         `json:"resources,omitempty"`
	Secrets          *ProjectSecretBindings    `json:"secrets,omitempty"`
	Credentials      *ProjectCredentialBinding `json:"credentials,omitempty"`
}

// EnvironmentSourceSelection is the complete value-free source selection.
type EnvironmentSourceSelection struct {
	Secrets         *ProjectSecretBindings    `json:"secrets,omitempty"`
	Credentials     *ProjectCredentialBinding `json:"credentials,omitempty"`
	ProfileRevision *uint64                   `json:"profile_revision,omitempty"`
}

// EnvironmentData is the SDK-owned public representation of an environment.
type EnvironmentData struct {
	Schema              *string `json:"$schema,omitempty"`
	CpuMillicores       int64   `json:"cpu_millicores"`
	CreatedAt           string  `json:"created_at"`
	CreatedBy           string  `json:"created_by"`
	DeletionGraceUntil  *string `json:"deletion_grace_until,omitempty"`
	DeletionRequestedAt *string `json:"deletion_requested_at,omitempty"`
	DesiredState        string  `json:"desired_state"`
	DestroyedAt         *string `json:"destroyed_at,omitempty"`
	DiskGb              int64   `json:"disk_gb"`
	ErrorReason         *string `json:"error_reason,omitempty"`
	Id                  string  `json:"id"`
	IsolationTier       string  `json:"isolation_tier"`
	MemoryMb            int64   `json:"memory_mb"`
	Name                *string `json:"name,omitempty"`
	Network             *string `json:"network,omitempty"`
	// NetworkState is pending, attached, failed or revoked when Network is set.
	NetworkState *string `json:"network_state,omitempty"`
	// NetworkFailure says why joining Network failed when NetworkState is failed.
	NetworkFailure      *string                     `json:"network_failure,omitempty"`
	OrgId               string                      `json:"org_id"`
	OperationGeneration uint64                      `json:"operation_generation"`
	Ports               *[]EnvironmentPort          `json:"ports,omitempty"`
	PresetId            *string                     `json:"preset_id,omitempty"`
	PresetName          *string                     `json:"preset_name,omitempty"`
	Protected           bool                        `json:"protected"`
	Recoverable         bool                        `json:"recoverable"`
	RetryCount          int64                       `json:"retry_count"`
	SetupComplete       bool                        `json:"setup_complete"`
	SetupError          *string                     `json:"setup_error,omitempty"`
	SetupPhase          int64                       `json:"setup_phase"`
	ShutdownAt          *string                     `json:"shutdown_at,omitempty"`
	StartedAt           *string                     `json:"started_at,omitempty"`
	State               string                      `json:"state"`
	StateChangedAt      string                      `json:"state_changed_at"`
	StoppedAt           *string                     `json:"stopped_at,omitempty"`
	SourceSelection     *EnvironmentSourceSelection `json:"source_selection,omitempty"`
	TotalRunningSeconds int64                       `json:"total_running_seconds"`
	TtlSeconds          *int64                      `json:"ttl_seconds,omitempty"`
	Type                string                      `json:"type"`
}

// EnvironmentResources is a complete environment compute/storage allocation.
type EnvironmentResources struct {
	CpuMillicores int64 `json:"cpu_millicores"`
	MemoryMb      int64 `json:"memory_mb"`
	DiskGb        int64 `json:"disk_gb"`
}

// ResizeEnvironmentRequest configures an idempotent platform resize.
type ResizeEnvironmentRequest struct {
	EnvironmentResources
	RequestId    string `json:"request_id"`
	Force        bool   `json:"force,omitempty"`
	AllowRestart bool   `json:"allow_restart,omitempty"`
}

// EnvironmentResizePlan describes how the platform will apply desired resources.
type EnvironmentResizePlan struct {
	PreviousResources              *EnvironmentResources `json:"previous_resources,omitempty"`
	DesiredResources               *EnvironmentResources `json:"desired_resources,omitempty"`
	ExecutionMode                  string                `json:"execution_mode"`
	ActiveSessionCount             int64                 `json:"active_session_count"`
	ActiveSessionsWillBeTerminated bool                  `json:"active_sessions_will_be_terminated"`
	Reason                         string                `json:"reason"`
	Warnings                       []string              `json:"warnings"`
}

// EnvironmentResizeFailure is the terminal failure attached to a resize operation.
type EnvironmentResizeFailure struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

// EnvironmentResizeOperation is the durable state of a platform resize.
type EnvironmentResizeOperation struct {
	Id                   string                    `json:"id"`
	EnvironmentId        string                    `json:"environment_id"`
	RequestId            string                    `json:"request_id"`
	PreviousResources    *EnvironmentResources     `json:"previous_resources,omitempty"`
	DesiredResources     *EnvironmentResources     `json:"desired_resources,omitempty"`
	LastAppliedResources *EnvironmentResources     `json:"last_applied_resources,omitempty"`
	State                string                    `json:"state"`
	DisruptionPolicy     string                    `json:"disruption_policy"`
	PlannedMode          string                    `json:"planned_mode"`
	AppliedMode          string                    `json:"applied_mode"`
	PodReplaced          bool                      `json:"pod_replaced"`
	Failure              *EnvironmentResizeFailure `json:"failure,omitempty"`
	CreatedAt            *string                   `json:"created_at,omitempty"`
	UpdatedAt            *string                   `json:"updated_at,omitempty"`
	CompletedAt          *string                   `json:"completed_at,omitempty"`
}

// CreateEnvironmentBody configures environment creation.
type CreateEnvironmentBody struct {
	PresetId                   *string     `json:"preset_id,omitempty"`
	Name                       *string     `json:"name,omitempty"`
	TtlSeconds                 *int64      `json:"ttl_seconds,omitempty"`
	IsolationTier              *string     `json:"isolation_tier,omitempty"`
	ProjectSpec                ProjectSpec `json:"project_spec"`
	ExpectedProfileRevision    *uint64     `json:"expected_profile_revision,omitempty"`
	ConfirmPersonalCredentials bool        `json:"confirm_personal_credentials,omitempty"`
	ConfirmPersonalSecrets     bool        `json:"confirm_personal_secrets,omitempty"`
	// OmitApplicationPreviews suppresses inherited creation defaults, not network access.
	OmitApplicationPreviews bool `json:"omit_application_previews,omitempty"`
	// Network joins this hosted Codewire Mesh network, by name, in the
	// organization. The creating user must be a member of it.
	Network *string `json:"network,omitempty"`
}

// UpdateEnvironmentSourcesRequest replaces only an environment's complete
// application-secret and credential-profile source selection.
type UpdateEnvironmentSourcesRequest struct {
	ExpectedOperationGeneration uint64                     `json:"expected_operation_generation"`
	Expected                    EnvironmentSourceSelection `json:"expected"`
	Replacement                 EnvironmentSourceSelection `json:"replacement"`
	AllowRestart                bool                       `json:"allow_restart,omitempty"`
	ConfirmPersonalCredentials  bool                       `json:"confirm_personal_credentials,omitempty"`
	ConfirmPersonalSecrets      bool                       `json:"confirm_personal_secrets,omitempty"`
}

// EnvironmentSourcesUpdateOutcome is the server's source replacement result.
type EnvironmentSourcesUpdateOutcome string

const (
	EnvironmentSourcesUpdateOutcomeUnchanged       EnvironmentSourcesUpdateOutcome = "unchanged"
	EnvironmentSourcesUpdateOutcomeStored          EnvironmentSourcesUpdateOutcome = "stored"
	EnvironmentSourcesUpdateOutcomeRestartRequired EnvironmentSourcesUpdateOutcome = "restart_required"
)

// EnvironmentSourcesUpdate is the exact source selection after an update.
type EnvironmentSourcesUpdate struct {
	EnvironmentID       string                          `json:"environment_id"`
	OperationGeneration uint64                          `json:"operation_generation"`
	Selection           EnvironmentSourceSelection      `json:"selection"`
	Outcome             EnvironmentSourcesUpdateOutcome `json:"outcome"`
}

// ExecBody configures command execution in an environment.
type ExecBody struct {
	Schema     *string            `json:"$schema,omitempty"`
	Command    *[]string          `json:"command"`
	Env        *map[string]string `json:"env,omitempty"`
	Timeout    *int64             `json:"timeout,omitempty"`
	WorkingDir *string            `json:"working_dir,omitempty"`
}

// ExecResult is the completed result of command execution.
type ExecResult struct {
	Schema   *string `json:"$schema,omitempty"`
	ExitCode int64   `json:"exit_code"`
	Stderr   string  `json:"stderr"`
	Stdout   string  `json:"stdout"`
}

// EnvironmentPort is an exposed environment port.
type EnvironmentPort struct {
	Schema        *string `json:"$schema,omitempty"`
	Access        string  `json:"access"`
	CreatedAt     string  `json:"created_at"`
	EnvironmentId string  `json:"environment_id"`
	Id            string  `json:"id"`
	Label         string  `json:"label"`
	Port          int64   `json:"port"`
	PreviewUrl    *string `json:"preview_url,omitempty"`
}

// CreatePortBody configures an environment port.
type CreatePortBody struct {
	Schema *string `json:"$schema,omitempty"`
	Access *string `json:"access,omitempty"`
	Label  string  `json:"label"`
	Port   int64   `json:"port"`
}

// ListEnvironmentsParams filters environment results.
type ListEnvironmentsParams struct {
	Type             *string `form:"type,omitempty" json:"type,omitempty"`
	State            *string `form:"state,omitempty" json:"state,omitempty"`
	IncludeDestroyed *bool   `form:"include_destroyed,omitempty" json:"include_destroyed,omitempty"`
}

// Preset is the SDK-owned public representation of a preset.
type Preset struct {
	BuildError        *string     `json:"build_error,omitempty"`
	BuildStatus       string      `json:"build_status"`
	CreatedAt         string      `json:"created_at"`
	DefaultTtlSeconds *int64      `json:"default_ttl_seconds,omitempty"`
	Description       *string     `json:"description,omitempty"`
	Id                string      `json:"id"`
	Language          *string     `json:"language,omitempty"`
	Name              string      `json:"name"`
	Official          bool        `json:"official"`
	OrgId             *string     `json:"org_id,omitempty"`
	Slug              *string     `json:"slug,omitempty"`
	ProjectSpec       ProjectSpec `json:"project_spec"`
}

// CreatePresetBody configures preset creation.
type CreatePresetBody struct {
	Name              string      `json:"name"`
	Slug              *string     `json:"slug,omitempty"`
	Description       *string     `json:"description,omitempty"`
	DefaultTtlSeconds *int64      `json:"default_ttl_seconds,omitempty"`
	ProjectSpec       ProjectSpec `json:"project_spec"`
}

// UpdatePresetBody configures preset updates.
type UpdatePresetBody struct {
	Name              *string      `json:"name,omitempty"`
	Description       *string      `json:"description,omitempty"`
	Slug              *string      `json:"slug,omitempty"`
	DefaultTtlSeconds *int64       `json:"default_ttl_seconds,omitempty"`
	ProjectSpec       *ProjectSpec `json:"project_spec,omitempty"`
}

// FileEntry describes an environment file.
type FileEntry struct {
	IsDir   bool   `json:"is_dir"`
	ModTime string `json:"mod_time"`
	Mode    string `json:"mode"`
	Name    string `json:"name"`
	Size    int64  `json:"size"`
}

// APIKey is the SDK-owned public representation of an API key.
type APIKey struct {
	Schema         *string   `json:"$schema,omitempty"`
	CreatedAt      string    `json:"created_at"`
	CreatedByEmail *string   `json:"created_by_email,omitempty"`
	CreatedByName  *string   `json:"created_by_name,omitempty"`
	DisabledAt     *string   `json:"disabled_at,omitempty"`
	ExpiresAt      *string   `json:"expires_at,omitempty"`
	Id             string    `json:"id"`
	KeyPrefix      string    `json:"key_prefix"`
	LastUsedAt     *string   `json:"last_used_at,omitempty"`
	Name           string    `json:"name"`
	OrgId          string    `json:"org_id"`
	Scopes         *[]string `json:"scopes"`
	UserId         string    `json:"user_id"`
}

// CreateAPIKeyBody configures API-key creation.
type CreateAPIKeyBody struct {
	Schema        *string   `json:"$schema,omitempty"`
	ExpiresInDays *int64    `json:"expires_in_days,omitempty"`
	Name          string    `json:"name"`
	Scopes        *[]string `json:"scopes,omitempty"`
}

// CreateAPIKeyResponse includes an API key's one-time key material.
type CreateAPIKeyResponse struct {
	Schema         *string   `json:"$schema,omitempty"`
	CreatedAt      string    `json:"created_at"`
	CreatedByEmail *string   `json:"created_by_email,omitempty"`
	CreatedByName  *string   `json:"created_by_name,omitempty"`
	DisabledAt     *string   `json:"disabled_at,omitempty"`
	ExpiresAt      *string   `json:"expires_at,omitempty"`
	Id             string    `json:"id"`
	Key            string    `json:"key"`
	KeyPrefix      string    `json:"key_prefix"`
	LastUsedAt     *string   `json:"last_used_at,omitempty"`
	Name           string    `json:"name"`
	OrgId          string    `json:"org_id"`
	Scopes         *[]string `json:"scopes"`
	UserId         string    `json:"user_id"`
}

// SecretMetadata describes a secret without its value.
type SecretMetadata struct {
	CreatedAt *string `json:"created_at,omitempty"`
	Key       string  `json:"key"`
	UpdatedAt *string `json:"updated_at,omitempty"`
}

// WorkloadSecretSource names one source in workload-secret precedence order.
type WorkloadSecretSource string

const (
	WorkloadSecretSourceOrganization        WorkloadSecretSource = "organization"
	WorkloadSecretSourceProject             WorkloadSecretSource = "project"
	WorkloadSecretSourceUser                WorkloadSecretSource = "user"
	WorkloadSecretSourceExplicitEnvironment WorkloadSecretSource = "explicit_environment"
)

// WorkloadSecretPreviewInput selects the metadata sources to preview.
type WorkloadSecretPreviewInput struct {
	Organization            bool     `json:"organization,omitempty"`
	SecretProjectID         string   `json:"secret_project_id,omitempty"`
	User                    bool     `json:"user,omitempty"`
	ExplicitEnvironmentKeys []string `json:"explicit_environment_keys,omitempty"`
}

// ResolvedWorkloadSecretMetadata describes one winning key without its value.
type ResolvedWorkloadSecretMetadata struct {
	Key               string                 `json:"key"`
	Source            WorkloadSecretSource   `json:"source"`
	OverriddenSources []WorkloadSecretSource `json:"overridden_sources,omitempty"`
}

// ListSecretsOutputBody holds organization or user secret metadata.
type ListSecretsOutputBody struct {
	Schema  *string           `json:"$schema,omitempty"`
	Secrets *[]SecretMetadata `json:"secrets"`
}

// SetSecretInputBody configures an organization secret write.
type SetSecretInputBody struct {
	Schema *string `json:"$schema,omitempty"`
	Key    string  `json:"key"`
	OrgId  string  `json:"org_id"`
	Value  string  `json:"value"`
}

// SetSecretOutputBody reports a secret write result.
type SetSecretOutputBody struct {
	Schema *string `json:"$schema,omitempty"`
	Status string  `json:"status"`
}

// SetUserSecretInputBody configures a user secret write.
type SetUserSecretInputBody struct {
	Schema *string `json:"$schema,omitempty"`
	Key    string  `json:"key"`
	Value  string  `json:"value"`
}

// SecretProject is the SDK-owned public representation of a secret project.
type SecretProject struct {
	Schema      *string `json:"$schema,omitempty"`
	CreatedAt   string  `json:"created_at"`
	Id          string  `json:"id"`
	Name        string  `json:"name"`
	OrgId       string  `json:"org_id"`
	SecretCount *int64  `json:"secret_count,omitempty"`
}

// CreateSecretProjectInputBody configures secret-project creation.
type CreateSecretProjectInputBody struct {
	Schema *string `json:"$schema,omitempty"`
	Name   string  `json:"name"`
}

// SetProjectSecretInputBody configures a secret-project secret write.
type SetProjectSecretInputBody struct {
	Schema *string `json:"$schema,omitempty"`
	Key    string  `json:"key"`
	Value  string  `json:"value"`
}

// ListProjectSecretsOutputBody holds secret-project secret metadata.
type ListProjectSecretsOutputBody struct {
	Schema  *string           `json:"$schema,omitempty"`
	Secrets *[]SecretMetadata `json:"secrets"`
}
