package codewire

import (
	"context"

	"connectrpc.com/connect"
	codewirev1 "github.com/codewiresh/codewire/libs/gen-go/codewire/v1"
)

// SecretProjectService manages secret projects.
type SecretProjectService struct {
	client *Client
}

// Create creates a new secret project.
func (s *SecretProjectService) Create(ctx context.Context, body CreateSecretProjectInputBody) (*SecretProject, error) {
	orgID, err := s.client.resolveOrgID()
	if err != nil {
		return nil, err
	}
	response, err := s.client.secrets.CreateSecretProject(ctx, connect.NewRequest(&codewirev1.CreateSecretProjectRequest{OrgId: orgID, Name: body.Name}))
	if err != nil {
		return nil, connectSDKError(err)
	}
	p, err := fromProtoSecretProject(response.Msg.GetSecretProject())
	if err != nil {
		return nil, err
	}
	return &p, nil
}

// List returns all secret projects for the organization.
func (s *SecretProjectService) List(ctx context.Context) ([]SecretProject, error) {
	orgID, err := s.client.resolveOrgID()
	if err != nil {
		return nil, err
	}
	var projects []SecretProject
	for pageToken := ""; ; {
		response, err := s.client.secrets.ListSecretProjects(ctx, connect.NewRequest(&codewirev1.ListSecretProjectsRequest{OrgId: orgID, PageToken: pageToken}))
		if err != nil {
			return nil, connectSDKError(err)
		}
		for _, project := range response.Msg.GetSecretProjects() {
			converted, err := fromProtoSecretProject(project)
			if err != nil {
				return nil, err
			}
			projects = append(projects, converted)
		}
		pageToken = response.Msg.GetNextPageToken()
		if pageToken == "" {
			return projects, nil
		}
	}
}

// Delete removes a secret project by ID.
func (s *SecretProjectService) Delete(ctx context.Context, projectID string) error {
	orgID, err := s.client.resolveOrgID()
	if err != nil {
		return err
	}
	_, err = s.client.secrets.DeleteSecretProject(ctx, connect.NewRequest(&codewirev1.DeleteSecretProjectRequest{OrgId: orgID, SecretProjectId: projectID}))
	return connectSDKError(err)
}

// ListSecrets returns all secrets within a secret project.
func (s *SecretProjectService) ListSecrets(ctx context.Context, projectID string) ([]SecretMetadata, error) {
	orgID, err := s.client.resolveOrgID()
	if err != nil {
		return nil, err
	}
	var secrets []SecretMetadata
	for pageToken := ""; ; {
		response, err := s.client.secrets.ListProjectSecrets(ctx, connect.NewRequest(&codewirev1.ListProjectSecretsRequest{OrgId: orgID, SecretProjectId: projectID, PageToken: pageToken}))
		if err != nil {
			return nil, connectSDKError(err)
		}
		for _, secret := range response.Msg.GetSecrets() {
			converted, err := fromProtoSecretMetadata(secret)
			if err != nil {
				return nil, err
			}
			secrets = append(secrets, converted)
		}
		pageToken = response.Msg.GetNextPageToken()
		if pageToken == "" {
			return secrets, nil
		}
	}
}

// SetSecret creates or updates a secret within a secret project.
func (s *SecretProjectService) SetSecret(ctx context.Context, projectID, key, value string) error {
	orgID, err := s.client.resolveOrgID()
	if err != nil {
		return err
	}
	_, err = s.client.secrets.SetProjectSecret(ctx, connect.NewRequest(&codewirev1.SetProjectSecretRequest{OrgId: orgID, SecretProjectId: projectID, Key: key, Value: value}))
	return connectSDKError(err)
}

// DeleteSecret removes a secret from a secret project by key.
func (s *SecretProjectService) DeleteSecret(ctx context.Context, projectID, key string) error {
	orgID, err := s.client.resolveOrgID()
	if err != nil {
		return err
	}
	_, err = s.client.secrets.DeleteProjectSecret(ctx, connect.NewRequest(&codewirev1.DeleteProjectSecretRequest{OrgId: orgID, SecretProjectId: projectID, Key: key}))
	return connectSDKError(err)
}

// RenameProjectSecret changes a project-scoped secret key without exposing its value.
func (s *SecretProjectService) RenameProjectSecret(ctx context.Context, projectID, key, newKey string) error {
	orgID, err := s.client.resolveOrgID()
	if err != nil {
		return err
	}
	_, err = s.client.secrets.RenameProjectSecret(ctx, connect.NewRequest(&codewirev1.RenameProjectSecretRequest{OrgId: orgID, SecretProjectId: projectID, Key: key, NewKey: newKey}))
	return connectSDKError(err)
}
