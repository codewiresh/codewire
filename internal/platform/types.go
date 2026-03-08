package platform

import (
	"encoding/json"
	"time"
)

// PlatformConfig is stored at ~/.config/cw/config.json.
type PlatformConfig struct {
	ServerURL        string `json:"server_url"`
	SessionToken     string `json:"session_token"`
	DefaultOrg       string `json:"default_org,omitempty"`
	DefaultResource  string `json:"default_resource,omitempty"`
	CoderBinary      string `json:"coder_binary,omitempty"`
	CurrentWorkspace string `json:"current_workspace,omitempty"`
}

// Auth types

type SignInRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type SignInResponse struct {
	User              *User    `json:"user,omitempty"`
	Session           *Session `json:"session,omitempty"`
	TwoFactorRequired bool     `json:"twoFactorRequired,omitempty"`
	TwoFactorToken    string   `json:"twoFactorToken,omitempty"`
}

type ValidateTOTPRequest struct {
	Code  string `json:"code"`
	Token string `json:"token"`
}

type AuthResponse struct {
	User    *User    `json:"user,omitempty"`
	Session *Session `json:"session,omitempty"`
}

type User struct {
	ID               string `json:"id"`
	Email            string `json:"email"`
	EmailVerified    bool   `json:"email_verified"`
	Name             string `json:"name,omitempty"`
	Image            string `json:"image,omitempty"`
	IsAdmin          bool   `json:"is_admin"`
	TwoFactorEnabled bool   `json:"two_factor_enabled"`
	CreatedAt        string `json:"created_at"`
}

type Session struct {
	ID        string `json:"id"`
	Token     string `json:"token"`
	ExpiresAt string `json:"expires_at"`
}

// Organization types

type Organization struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	Slug      string `json:"slug"`
	CreatedAt string `json:"created_at"`
}

type OrgWithRole struct {
	Organization
	Role          string             `json:"role"`
	BillingPlan   string             `json:"billingPlan,omitempty"`
	BillingStatus string             `json:"billingStatus,omitempty"`
	TrialEndsAt   *string            `json:"trialEndsAt,omitempty"`
	Resources     []ResourceSummary  `json:"resources,omitempty"`
}

type CreateOrgRequest struct {
	Name string `json:"name"`
	Slug string `json:"slug"`
}

type OrgInvitation struct {
	ID        string `json:"id"`
	Email     string `json:"email"`
	Role      string `json:"role"`
	Status    string `json:"status"`
	CreatedAt string `json:"created_at"`
}

type InviteMemberRequest struct {
	Email string `json:"email"`
	Role  string `json:"role"`
}

type ResourceSummary struct {
	ID           string `json:"id"`
	Name         string `json:"name"`
	Slug         string `json:"slug"`
	Type         string `json:"type"`
	Status       string `json:"status"`
	HealthStatus string `json:"health_status,omitempty"`
}

// Resource types

type PlatformResource struct {
	ID                string          `json:"id"`
	OrgID             string          `json:"org_id"`
	Type              string          `json:"type"`
	Name              string          `json:"name"`
	Slug              string          `json:"slug"`
	Status            string          `json:"status"`
	Config            *map[string]any `json:"config,omitempty"`
	Metadata          *map[string]any `json:"metadata,omitempty"`
	ProvisionPhase    string          `json:"provision_phase,omitempty"`
	ProvisionError    string          `json:"provision_error,omitempty"`
	HealthStatus      string          `json:"health_status"`
	HealthCheckedAt   *time.Time      `json:"health_checked_at,omitempty"`
	BillingPlan       string          `json:"billing_plan"`
	BillingStatus     string          `json:"billing_status"`
	CreatedAt         string          `json:"created_at"`
	UpdatedAt         string          `json:"updated_at"`
}

// Workspace types

type WorkspaceSummary struct {
	ID                  string  `json:"id"`
	Name                string  `json:"name"`
	OwnerName           string  `json:"owner_name"`
	Status              string  `json:"status"`
	TemplateDisplayName string  `json:"template_display_name"`
	LastUsedAt          *string `json:"last_used_at,omitempty"`
}

type WorkspacesListResponse struct {
	Workspaces []WorkspaceSummary `json:"workspaces"`
	Count      int                `json:"count"`
}

// Resource CRUD types

type CreateResourceRequest struct {
	OrgID string `json:"orgId"`
	Type  string `json:"type"`
	Name  string `json:"name"`
	Slug  string `json:"slug"`
	Plan  string `json:"plan,omitempty"`
}

type CreateResourceResult struct {
	PlatformResource
	CheckoutURL      string `json:"checkout_url,omitempty"`
	RequiresCheckout bool   `json:"requires_checkout,omitempty"`
}

// Plan represents a billing plan for a resource type.
type Plan struct {
	DisplayName         string  `json:"display_name"`
	PriceCents          int     `json:"price_cents"`
	IncludedDevs        int     `json:"included_devs"`
	MaxConcurrentWS     int     `json:"max_concurrent_ws"`
	MaxTeamMembers      int     `json:"max_team_members"`
	StorageGB           int     `json:"storage_gb"`
	IsContactUs         bool    `json:"is_contact_us"`
	IncludedCPUHours    int     `json:"included_cpu_hours"`
	IncludedMemGBHours  int     `json:"included_mem_gb_hours"`
	IncludedDiskGBHours int     `json:"included_disk_gb_hours"`
	CPUOverageCents     float64 `json:"cpu_overage_cents"`
	MemOverageCents     float64 `json:"mem_overage_cents"`
	DiskOverageCents    float64 `json:"disk_overage_cents"`
}

// Billing checkout types

type ResourceCheckoutRequest struct {
	Plan       string `json:"plan"`
	SuccessURL string `json:"success_url"`
	CancelURL  string `json:"cancel_url"`
}

type CheckoutURLResponse struct {
	CheckoutURL string `json:"checkout_url"`
}

// Device auth types

type DeviceAuthResponse struct {
	DeviceCode      string `json:"device_code"`
	UserCode        string `json:"user_code"`
	VerificationURI string `json:"verification_uri"`
	ExpiresIn       int    `json:"expires_in"`
	Interval        int    `json:"interval"`
}

type DeviceTokenResponse struct {
	Status       string `json:"status,omitempty"`
	SessionToken string `json:"session_token,omitempty"`
	User         *User  `json:"user,omitempty"`
}

// ProvisionEvent represents a provisioning phase event.
type ProvisionEvent struct {
	ID         string          `json:"id"`
	ResourceID string          `json:"resource_id"`
	Phase      string          `json:"phase"`
	Status     string          `json:"status"`
	Message    string          `json:"message,omitempty"`
	Metadata   json.RawMessage `json:"metadata,omitempty"`
	CreatedAt  string          `json:"created_at"`
}

// Detection types

type DetectionResult struct {
	ProjectType    string              `json:"project_type"`
	TemplateImage  string              `json:"template_image"`
	InstallCommand string              `json:"install_command"`
	StartupScript  string              `json:"startup_script"`
	Language       string              `json:"language"`
	Framework      string              `json:"framework"`
	SuggestedName  string              `json:"suggested_name"`
	NeedsDocker    bool                `json:"needs_docker"`
	HasCompose     bool                `json:"has_compose"`
	Services       []ServiceDefinition `json:"services"`
	CPU            string              `json:"cpu"`
	Memory         string              `json:"memory"`
	SetupNotes     string              `json:"setup_notes"`
}

type ServiceDefinition struct {
	Name string `json:"name"`
	Port int    `json:"port"`
}

// API error

type APIError struct {
	Status  int      `json:"status"`
	Title   string   `json:"title"`
	Detail  string   `json:"detail,omitempty"`
	Errors  []string `json:"errors,omitempty"`
}

func (e *APIError) Error() string {
	if e.Detail != "" {
		return e.Detail
	}
	return e.Title
}

// Environment types

type Environment struct {
	ID                  string  `json:"id"`
	OrgID               string  `json:"org_id"`
	CreatedBy           string  `json:"created_by"`
	TemplateID          string  `json:"template_id"`
	Type                string  `json:"type"`
	Name                *string `json:"name,omitempty"`
	State               string  `json:"state"`
	DesiredState        string  `json:"desired_state"`
	ErrorReason         *string `json:"error_reason,omitempty"`
	Recoverable         bool    `json:"recoverable"`
	StateChangedAt      string  `json:"state_changed_at"`
	RetryCount          int     `json:"retry_count"`
	TTLSeconds          *int    `json:"ttl_seconds,omitempty"`
	ShutdownAt          *string `json:"shutdown_at,omitempty"`
	CPUMillicores       int     `json:"cpu_millicores"`
	MemoryMB            int     `json:"memory_mb"`
	DiskGB              int     `json:"disk_gb"`
	TotalRunningSeconds int     `json:"total_running_seconds"`
	CreatedAt           string  `json:"created_at"`
	StartedAt           *string `json:"started_at,omitempty"`
	StoppedAt           *string `json:"stopped_at,omitempty"`
	DestroyedAt         *string `json:"destroyed_at,omitempty"`
}

type EnvironmentTemplate struct {
	ID                   string  `json:"id"`
	OrgID                string  `json:"org_id"`
	Type                 string  `json:"type"`
	Name                 string  `json:"name"`
	Description          *string `json:"description,omitempty"`
	BuildStatus          string  `json:"build_status"`
	BuildError           *string `json:"build_error,omitempty"`
	DefaultCPUMillicores int     `json:"default_cpu_millicores"`
	DefaultMemoryMB      int     `json:"default_memory_mb"`
	DefaultDiskGB        int     `json:"default_disk_gb"`
	DefaultTTLSeconds    *int    `json:"default_ttl_seconds,omitempty"`
	CreatedAt            string  `json:"created_at"`
}

type CreateEnvironmentRequest struct {
	TemplateID     string            `json:"template_id,omitempty"`
	Name           string            `json:"name,omitempty"`
	CPUMillicores  *int              `json:"cpu_millicores,omitempty"`
	MemoryMB       *int              `json:"memory_mb,omitempty"`
	DiskGB         *int              `json:"disk_gb,omitempty"`
	TTLSeconds     *int              `json:"ttl_seconds,omitempty"`
	RepoURL        string            `json:"repo_url,omitempty"`
	Branch         string            `json:"branch,omitempty"`
	Image          string            `json:"image,omitempty"`
	InstallCommand string            `json:"install_command,omitempty"`
	StartupScript  string            `json:"startup_script,omitempty"`
	EnvVars        map[string]string `json:"env_vars,omitempty"`
	Agent          string            `json:"agent,omitempty"`
	AgentEnv       map[string]string `json:"agent_env,omitempty"`
	SecretProject  string            `json:"secret_project,omitempty"`
}

// SecretProject represents a named collection of secrets.
type SecretProject struct {
	ID          string `json:"id"`
	OrgID       string `json:"org_id"`
	Name        string `json:"name"`
	SecretCount int    `json:"secret_count,omitempty"`
	CreatedAt   string `json:"created_at"`
}

type CreateTemplateRequest struct {
	Type                 string `json:"type"`
	Name                 string `json:"name"`
	Description          string `json:"description,omitempty"`
	DefaultCPUMillicores *int   `json:"default_cpu_millicores,omitempty"`
	DefaultMemoryMB      *int   `json:"default_memory_mb,omitempty"`
	DefaultDiskGB        *int   `json:"default_disk_gb,omitempty"`
	DefaultTTLSeconds    *int   `json:"default_ttl_seconds,omitempty"`
	Image                string `json:"image,omitempty"`
}

type StatusResponse struct {
	Status string `json:"status"`
}

type ExecRequest struct {
	Command    []string          `json:"command"`
	WorkingDir string            `json:"working_dir,omitempty"`
	Env        map[string]string `json:"env,omitempty"`
	Timeout    int               `json:"timeout,omitempty"`
}

type ExecResult struct {
	ExitCode int    `json:"exit_code"`
	Stdout   string `json:"stdout"`
	Stderr   string `json:"stderr"`
}

type FileEntry struct {
	Name    string `json:"name"`
	Size    int64  `json:"size"`
	IsDir   bool   `json:"is_dir"`
	Mode    string `json:"mode"`
	ModTime string `json:"mod_time"`
}
