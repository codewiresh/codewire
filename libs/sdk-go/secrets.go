package codewire

import (
	"context"
	"fmt"

	"connectrpc.com/connect"
	codewirev1 "github.com/codewiresh/codewire/libs/gen-go/codewire/v1"
)

// SecretService manages organization- and user-scoped secrets.
type SecretService struct {
	client *Client
}

// List returns all organization-scoped secrets.
func (s *SecretService) List(ctx context.Context) ([]SecretMetadata, error) {
	orgID, err := s.client.resolveOrgID()
	if err != nil {
		return nil, err
	}
	var secrets []SecretMetadata
	for pageToken := ""; ; {
		response, err := s.client.secrets.ListSecrets(ctx, connect.NewRequest(&codewirev1.ListSecretsRequest{OrgId: orgID, PageToken: pageToken}))
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

// Set creates or updates an organization-scoped secret.
func (s *SecretService) Set(ctx context.Context, key, value string) error {
	orgID, err := s.client.resolveOrgID()
	if err != nil {
		return err
	}
	_, err = s.client.secrets.SetSecret(ctx, connect.NewRequest(&codewirev1.SetSecretRequest{OrgId: orgID, Key: key, Value: value}))
	return connectSDKError(err)
}

// Delete removes an organization-scoped secret by key.
func (s *SecretService) Delete(ctx context.Context, key string) error {
	orgID, err := s.client.resolveOrgID()
	if err != nil {
		return err
	}
	_, err = s.client.secrets.DeleteSecret(ctx, connect.NewRequest(&codewirev1.DeleteSecretRequest{OrgId: orgID, Key: key}))
	return connectSDKError(err)
}

// ListUser returns all user-scoped secrets.
func (s *SecretService) ListUser(ctx context.Context) ([]SecretMetadata, error) {
	var secrets []SecretMetadata
	for pageToken := ""; ; {
		response, err := s.client.secrets.ListUserSecrets(ctx, connect.NewRequest(&codewirev1.ListUserSecretsRequest{PageToken: pageToken}))
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

// SetUser creates or updates a user-scoped secret.
func (s *SecretService) SetUser(ctx context.Context, key, value string) error {
	_, err := s.client.secrets.SetUserSecret(ctx, connect.NewRequest(&codewirev1.SetUserSecretRequest{Key: key, Value: value}))
	return connectSDKError(err)
}

// DeleteUser removes a user-scoped secret by key.
func (s *SecretService) DeleteUser(ctx context.Context, key string) error {
	_, err := s.client.secrets.DeleteUserSecret(ctx, connect.NewRequest(&codewirev1.DeleteUserSecretRequest{Key: key}))
	return connectSDKError(err)
}

// Preview resolves selected workload-secret key precedence without reading values.
func (s *SecretService) Preview(ctx context.Context, input WorkloadSecretPreviewInput) ([]ResolvedWorkloadSecretMetadata, error) {
	orgID, err := s.client.resolveOrgID()
	if err != nil {
		return nil, err
	}
	response, err := s.client.secrets.PreviewWorkloadSecretResolution(ctx, connect.NewRequest(&codewirev1.PreviewWorkloadSecretResolutionRequest{
		OrgId:                   orgID,
		Organization:            input.Organization,
		SecretProjectId:         input.SecretProjectID,
		User:                    input.User,
		ExplicitEnvironmentKeys: append([]string(nil), input.ExplicitEnvironmentKeys...),
	}))
	if err != nil {
		return nil, connectSDKError(err)
	}
	resolved := make([]ResolvedWorkloadSecretMetadata, 0, len(response.Msg.GetSecrets()))
	for _, secret := range response.Msg.GetSecrets() {
		source, err := workloadSecretSource(secret.GetSource())
		if err != nil {
			return nil, err
		}
		overridden := make([]WorkloadSecretSource, 0, len(secret.GetOverriddenSources()))
		for _, candidate := range secret.GetOverriddenSources() {
			converted, err := workloadSecretSource(candidate)
			if err != nil {
				return nil, err
			}
			overridden = append(overridden, converted)
		}
		resolved = append(resolved, ResolvedWorkloadSecretMetadata{
			Key:               secret.GetKey(),
			Source:            source,
			OverriddenSources: overridden,
		})
	}
	return resolved, nil
}

func workloadSecretSource(source codewirev1.WorkloadSecretSource) (WorkloadSecretSource, error) {
	switch source {
	case codewirev1.WorkloadSecretSource_WORKLOAD_SECRET_SOURCE_ORGANIZATION:
		return WorkloadSecretSourceOrganization, nil
	case codewirev1.WorkloadSecretSource_WORKLOAD_SECRET_SOURCE_PROJECT:
		return WorkloadSecretSourceProject, nil
	case codewirev1.WorkloadSecretSource_WORKLOAD_SECRET_SOURCE_USER:
		return WorkloadSecretSourceUser, nil
	case codewirev1.WorkloadSecretSource_WORKLOAD_SECRET_SOURCE_EXPLICIT_ENVIRONMENT:
		return WorkloadSecretSourceExplicitEnvironment, nil
	default:
		return "", fmt.Errorf("codewire: invalid workload-secret source %d", source)
	}
}

// RenameSecret changes an organization-scoped secret key without exposing its value.
func (s *SecretService) RenameSecret(ctx context.Context, key, newKey string) error {
	orgID, err := s.client.resolveOrgID()
	if err != nil {
		return err
	}
	_, err = s.client.secrets.RenameSecret(ctx, connect.NewRequest(&codewirev1.RenameSecretRequest{OrgId: orgID, Key: key, NewKey: newKey}))
	return connectSDKError(err)
}

// RenameUserSecret changes a user-scoped secret key without exposing its value.
func (s *SecretService) RenameUserSecret(ctx context.Context, key, newKey string) error {
	_, err := s.client.secrets.RenameUserSecret(ctx, connect.NewRequest(&codewirev1.RenameUserSecretRequest{Key: key, NewKey: newKey}))
	return connectSDKError(err)
}
