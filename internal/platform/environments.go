package platform

import (
	"fmt"
	"io"
	"net/http"
	"time"
)

const (
	minExecHTTPTimeout   = 10 * time.Minute
	execHTTPTimeoutSlack = 30 * time.Second
)

func execRequestHTTPTimeout(timeoutSeconds int) time.Duration {
	timeout := minExecHTTPTimeout
	if timeoutSeconds > 0 {
		requestTimeout := time.Duration(timeoutSeconds)*time.Second + execHTTPTimeoutSlack
		if requestTimeout > timeout {
			timeout = requestTimeout
		}
	}
	return timeout
}

func (c *Client) withHTTPTimeout(timeout time.Duration) *Client {
	if c == nil || c.HTTP == nil {
		return c
	}
	httpClient := *c.HTTP
	httpClient.Timeout = timeout
	clone := *c
	clone.HTTP = &httpClient
	return &clone
}

func (c *Client) CreateEnvironment(orgID string, req *CreateEnvironmentRequest) (*Environment, error) {
	var env Environment
	if err := c.do("POST", fmt.Sprintf("/api/v1/organizations/%s/environments", orgID), req, &env); err != nil {
		return nil, err
	}
	return &env, nil
}

func (c *Client) ListEnvironments(orgID string, envType, state string, includeDestroyed bool) ([]Environment, error) {
	path := fmt.Sprintf("/api/v1/organizations/%s/environments", orgID)
	sep := "?"
	if envType != "" {
		path += sep + "type=" + envType
		sep = "&"
	}
	if state != "" {
		path += sep + "state=" + state
		sep = "&"
	}
	if includeDestroyed {
		path += sep + "include_destroyed=true"
	}
	var envs []Environment
	if err := c.do("GET", path, nil, &envs); err != nil {
		return nil, err
	}
	return envs, nil
}

func (c *Client) GetEnvironment(orgID, envID string) (*Environment, error) {
	var env Environment
	if err := c.do("GET", fmt.Sprintf("/api/v1/organizations/%s/environments/%s", orgID, envID), nil, &env); err != nil {
		return nil, err
	}
	return &env, nil
}

func (c *Client) DeleteEnvironment(orgID, envID string) error {
	return c.do("DELETE", fmt.Sprintf("/api/v1/organizations/%s/environments/%s", orgID, envID), nil, nil)
}

func (c *Client) StopEnvironment(orgID, envID string) (*StatusResponse, error) {
	var resp StatusResponse
	if err := c.do("POST", fmt.Sprintf("/api/v1/organizations/%s/environments/%s/stop", orgID, envID), nil, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

func (c *Client) StartEnvironment(orgID, envID string) (*StatusResponse, error) {
	var resp StatusResponse
	if err := c.do("POST", fmt.Sprintf("/api/v1/organizations/%s/environments/%s/start", orgID, envID), nil, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

func (c *Client) CreatePort(orgID, envID string, req *CreatePortRequest) (*EnvironmentPort, error) {
	var port EnvironmentPort
	if err := c.do("POST", fmt.Sprintf("/api/v1/organizations/%s/environments/%s/ports", orgID, envID), req, &port); err != nil {
		return nil, err
	}
	return &port, nil
}

func (c *Client) ListPorts(orgID, envID string) ([]EnvironmentPort, error) {
	var ports []EnvironmentPort
	if err := c.do("GET", fmt.Sprintf("/api/v1/organizations/%s/environments/%s/ports", orgID, envID), nil, &ports); err != nil {
		return nil, err
	}
	return ports, nil
}

func (c *Client) DeletePort(orgID, envID, portID string) error {
	return c.do("DELETE", fmt.Sprintf("/api/v1/organizations/%s/environments/%s/ports/%s", orgID, envID, portID), nil, nil)
}

func (c *Client) ListPresets(orgID string) ([]Preset, error) {
	path := fmt.Sprintf("/api/v1/organizations/%s/presets", orgID)
	var presets []Preset
	if err := c.do("GET", path, nil, &presets); err != nil {
		return nil, err
	}
	return presets, nil
}

func (c *Client) CreatePreset(orgID string, req *CreatePresetRequest) (*Preset, error) {
	var preset Preset
	if err := c.do("POST", fmt.Sprintf("/api/v1/organizations/%s/presets", orgID), req, &preset); err != nil {
		return nil, err
	}
	return &preset, nil
}

func (c *Client) DeletePreset(orgID, presetID string) error {
	return c.do("DELETE", fmt.Sprintf("/api/v1/organizations/%s/presets/%s", orgID, presetID), nil, nil)
}

func (c *Client) ExecInEnvironment(orgID, envID string, req *ExecRequest) (*ExecResult, error) {
	var result ExecResult
	client := c.withHTTPTimeout(execRequestHTTPTimeout(req.Timeout))
	if err := client.do("POST", fmt.Sprintf("/api/v1/organizations/%s/environments/%s/exec", orgID, envID), req, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

func (c *Client) ListFiles(orgID, envID, path string) ([]FileEntry, error) {
	p := fmt.Sprintf("/api/v1/organizations/%s/environments/%s/files", orgID, envID)
	if path != "" {
		p += "?path=" + path
	}
	var entries []FileEntry
	if err := c.do("GET", p, nil, &entries); err != nil {
		return nil, err
	}
	return entries, nil
}

func (c *Client) UploadFile(orgID, envID, path string, data io.Reader) error {
	url := fmt.Sprintf("%s/api/v1/organizations/%s/environments/%s/files/upload?path=%s",
		c.ServerURL, orgID, envID, path)
	req, err := http.NewRequest(http.MethodPost, url, data)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/octet-stream")
	if c.SessionToken != "" {
		req.Header.Set("Authorization", "Bearer "+c.SessionToken)
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return fmt.Errorf("upload failed: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("upload failed (%d): %s", resp.StatusCode, string(body))
	}
	return nil
}

func (c *Client) LookupRepoConfig(orgID, repoURL string) (*RepoConfig, error) {
	var rc RepoConfig
	if err := c.do("GET", fmt.Sprintf("/api/v1/organizations/%s/repo-configs/lookup?repo_url=%s", orgID, repoURL), nil, &rc); err != nil {
		return nil, err
	}
	return &rc, nil
}

func (c *Client) SaveRepoConfig(orgID string, repoURL, presetID string, setupConfig map[string]any) error {
	body := map[string]any{
		"repo_url":     repoURL,
		"preset_id":    presetID,
		"setup_config": setupConfig,
	}
	return c.do("PUT", fmt.Sprintf("/api/v1/organizations/%s/repo-configs", orgID), body, nil)
}

func (c *Client) ProtectEnvironment(orgID, envID string) (*StatusResponse, error) {
	var resp StatusResponse
	if err := c.do("POST", fmt.Sprintf("/api/v1/organizations/%s/environments/%s/protect", orgID, envID), nil, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

func (c *Client) UnprotectEnvironment(orgID, envID string) (*StatusResponse, error) {
	var resp StatusResponse
	if err := c.do("POST", fmt.Sprintf("/api/v1/organizations/%s/environments/%s/unprotect", orgID, envID), nil, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

func (c *Client) CancelDeletion(orgID, envID string) (*StatusResponse, error) {
	var resp StatusResponse
	if err := c.do("POST", fmt.Sprintf("/api/v1/organizations/%s/environments/%s/cancel-deletion", orgID, envID), nil, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

func (c *Client) ExtendTTL(orgID, envID string, additionalSeconds int) (*StatusResponse, error) {
	var resp StatusResponse
	req := &ExtendTTLRequest{AdditionalSeconds: additionalSeconds}
	if err := c.do("POST", fmt.Sprintf("/api/v1/organizations/%s/environments/%s/extend-ttl", orgID, envID), req, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

func (c *Client) ListAccess(orgID, envID string) ([]AccessGrant, error) {
	var grants []AccessGrant
	if err := c.do("GET", fmt.Sprintf("/api/v1/organizations/%s/environments/%s/access", orgID, envID), nil, &grants); err != nil {
		return nil, err
	}
	return grants, nil
}

func (c *Client) GrantAccess(orgID, envID string, req *GrantAccessRequest) error {
	return c.do("POST", fmt.Sprintf("/api/v1/organizations/%s/environments/%s/access", orgID, envID), req, nil)
}

func (c *Client) RevokeAccess(orgID, envID, userID string) error {
	return c.do("DELETE", fmt.Sprintf("/api/v1/organizations/%s/environments/%s/access/%s", orgID, envID, userID), nil, nil)
}

func (c *Client) DownloadFile(orgID, envID, path string) (io.ReadCloser, error) {
	url := fmt.Sprintf("%s/api/v1/organizations/%s/environments/%s/files/download?path=%s",
		c.ServerURL, orgID, envID, path)
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	if c.SessionToken != "" {
		req.Header.Set("Authorization", "Bearer "+c.SessionToken)
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, fmt.Errorf("download failed: %w", err)
	}
	if resp.StatusCode >= 400 {
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		return nil, fmt.Errorf("download failed (%d): %s", resp.StatusCode, string(body))
	}
	return resp.Body, nil
}
