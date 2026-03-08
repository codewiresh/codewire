package platform

import "fmt"

// SecretMetadata represents a secret key with timestamps (no value exposed).
type SecretMetadata struct {
	Key       string `json:"key"`
	CreatedAt string `json:"created_at,omitempty"`
	UpdatedAt string `json:"updated_at,omitempty"`
}

type listSecretsResponse struct {
	Secrets []SecretMetadata `json:"secrets"`
}

type setSecretRequest struct {
	OrgID string `json:"org_id"`
	Key   string `json:"key"`
	Value string `json:"value"`
}

// ListSecrets returns secret metadata (names only, no values) for an org.
func (c *Client) ListSecrets(orgID string) ([]SecretMetadata, error) {
	var resp listSecretsResponse
	if err := c.do("GET", fmt.Sprintf("/api/v1/secrets?org_id=%s", orgID), nil, &resp); err != nil {
		return nil, err
	}
	return resp.Secrets, nil
}

// SetSecret creates or updates a secret for an org.
func (c *Client) SetSecret(orgID, key, value string) error {
	return c.do("PUT", "/api/v1/secrets", &setSecretRequest{
		OrgID: orgID,
		Key:   key,
		Value: value,
	}, nil)
}

// DeleteSecret removes a secret from an org.
func (c *Client) DeleteSecret(orgID, key string) error {
	return c.do("DELETE", fmt.Sprintf("/api/v1/secrets/%s?org_id=%s", key, orgID), nil, nil)
}

// ── Secret Project methods ───────────────────────────────────────────

type createSecretProjectRequest struct {
	Name string `json:"name"`
}

type setProjectSecretRequest struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

// CreateSecretProject creates a named secret project in an org.
func (c *Client) CreateSecretProject(orgID, name string) (*SecretProject, error) {
	var resp SecretProject
	if err := c.do("POST", fmt.Sprintf("/api/v1/organizations/%s/secret-projects", orgID),
		&createSecretProjectRequest{Name: name}, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// ListSecretProjects returns all secret projects for an org.
func (c *Client) ListSecretProjects(orgID string) ([]SecretProject, error) {
	var resp []SecretProject
	if err := c.do("GET", fmt.Sprintf("/api/v1/organizations/%s/secret-projects", orgID), nil, &resp); err != nil {
		return nil, err
	}
	return resp, nil
}

// DeleteSecretProject deletes a secret project and all its secrets.
func (c *Client) DeleteSecretProject(orgID, projectID string) error {
	return c.do("DELETE", fmt.Sprintf("/api/v1/organizations/%s/secret-projects/%s", orgID, projectID), nil, nil)
}

// ListProjectSecrets returns secret metadata for a project.
func (c *Client) ListProjectSecrets(orgID, projectID string) ([]SecretMetadata, error) {
	var resp listSecretsResponse
	if err := c.do("GET", fmt.Sprintf("/api/v1/organizations/%s/secret-projects/%s/secrets", orgID, projectID), nil, &resp); err != nil {
		return nil, err
	}
	return resp.Secrets, nil
}

// SetProjectSecret creates or updates a secret in a project.
func (c *Client) SetProjectSecret(orgID, projectID, key, value string) error {
	return c.do("PUT", fmt.Sprintf("/api/v1/organizations/%s/secret-projects/%s/secrets", orgID, projectID),
		&setProjectSecretRequest{Key: key, Value: value}, nil)
}

// DeleteProjectSecret removes a secret from a project.
func (c *Client) DeleteProjectSecret(orgID, projectID, key string) error {
	return c.do("DELETE", fmt.Sprintf("/api/v1/organizations/%s/secret-projects/%s/secrets/%s", orgID, projectID, key), nil, nil)
}
