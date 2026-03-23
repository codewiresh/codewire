package platform

import "fmt"

type LaunchOptions struct {
	GitHubStatus   GitHubStatus    `json:"github_status"`
	Presets        []Preset        `json:"presets"`
	SecretProjects []SecretProject `json:"secret_projects"`
}

type PrepareLaunchRequest struct {
	PresetID           *string           `json:"preset_id,omitempty"`
	PresetSlug         string            `json:"preset_slug,omitempty"`
	Name               *string           `json:"name,omitempty"`
	CPUMillicores      *int              `json:"cpu_millicores,omitempty"`
	MemoryMB           *int              `json:"memory_mb,omitempty"`
	DiskGB             *int              `json:"disk_gb,omitempty"`
	TTLSeconds         *int              `json:"ttl_seconds,omitempty"`
	RepoURL            string            `json:"repo_url,omitempty"`
	Branch             string            `json:"branch,omitempty"`
	Repos              []RepoEntry       `json:"repos,omitempty"`
	Image              string            `json:"image,omitempty"`
	InstallCommand     string            `json:"install_command,omitempty"`
	StartupScript      string            `json:"startup_script,omitempty"`
	EnvVars            map[string]string `json:"env_vars,omitempty"`
	Agent              string            `json:"agent,omitempty"`
	AgentEnv           map[string]string `json:"agent_env,omitempty"`
	SecretProject      string            `json:"secret_project,omitempty"`
	AppPorts           []AppPort         `json:"app_ports,omitempty"`
	IncludeOrgSecrets  *bool             `json:"include_org_secrets,omitempty"`
	IncludeUserSecrets *bool             `json:"include_user_secrets,omitempty"`
	Analyze            *bool             `json:"analyze,omitempty"`
}

type PrepareLaunchResponse struct {
	Draft          CreateEnvironmentRequest `json:"draft"`
	Detection      *DetectionResult         `json:"detection,omitempty"`
	ResolvedPreset *Preset                  `json:"resolved_preset,omitempty"`
	RepoConfig     *RepoConfig              `json:"repo_config,omitempty"`
}

func (c *Client) GetLaunchOptions(orgID string) (*LaunchOptions, error) {
	var out LaunchOptions
	if err := c.do("GET", fmt.Sprintf("/api/v1/organizations/%s/environment-create/options", orgID), nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func (c *Client) PrepareLaunch(orgID string, req *PrepareLaunchRequest) (*PrepareLaunchResponse, error) {
	var out PrepareLaunchResponse
	if err := c.do("POST", fmt.Sprintf("/api/v1/organizations/%s/environment-create/prepare", orgID), req, &out); err != nil {
		return nil, err
	}
	return &out, nil
}
