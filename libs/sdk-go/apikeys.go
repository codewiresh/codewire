package codewire

import (
	"context"
	"encoding/json"
	"fmt"
	"math"

	"connectrpc.com/connect"
	codewirev1 "github.com/codewiresh/codewire/libs/gen-go/codewire/v1"
)

// APIKeyService manages API keys for the configured organization.
type APIKeyService struct {
	client *Client
}

// Create issues a new API key and returns the full key value (only
// returned at creation time).
func (s *APIKeyService) Create(ctx context.Context, body CreateAPIKeyBody) (*CreateAPIKeyResponse, error) {
	orgID, err := s.client.resolveOrgID()
	if err != nil {
		return nil, err
	}
	req, err := createAPIKeyRequest(orgID, body)
	if err != nil {
		return nil, err
	}
	resp, err := s.client.apiKeys.CreateApiKey(ctx, connect.NewRequest(req))
	if err != nil {
		return nil, connectSDKError(err)
	}
	key, err := fromProtoCreateAPIKeyResponse(resp.Msg)
	if err != nil {
		return nil, err
	}
	return &key, nil
}

// List returns all API keys for the organization (key material redacted).
func (s *APIKeyService) List(ctx context.Context) ([]APIKey, error) {
	orgID, err := s.client.resolveOrgID()
	if err != nil {
		return nil, err
	}

	var keys []APIKey
	req := &codewirev1.ListApiKeysRequest{OrgId: orgID}
	for {
		resp, err := s.client.apiKeys.ListApiKeys(ctx, connect.NewRequest(req))
		if err != nil {
			return nil, connectSDKError(err)
		}
		for _, key := range resp.Msg.GetApiKeys() {
			converted, err := fromProtoAPIKey(key)
			if err != nil {
				return nil, err
			}
			keys = append(keys, converted)
		}
		if resp.Msg.GetNextPageToken() == "" {
			return keys, nil
		}
		req.PageToken = resp.Msg.GetNextPageToken()
	}
}

// Delete revokes an API key by ID.
func (s *APIKeyService) Delete(ctx context.Context, keyID string) error {
	orgID, err := s.client.resolveOrgID()
	if err != nil {
		return err
	}
	_, err = s.client.apiKeys.DeleteApiKey(ctx, connect.NewRequest(&codewirev1.DeleteApiKeyRequest{
		OrgId: orgID,
		KeyId: keyID,
	}))
	return connectSDKError(err)
}

// Update disables or re-enables an API key. body must contain a boolean
// disabled field; missing or non-boolean values are sent absent for the API to
// validate canonically.
func (s *APIKeyService) Update(ctx context.Context, keyID string, body any) (*APIKey, error) {
	orgID, err := s.client.resolveOrgID()
	if err != nil {
		return nil, err
	}
	resp, err := s.client.apiKeys.UpdateApiKey(ctx, connect.NewRequest(&codewirev1.UpdateApiKeyRequest{
		OrgId:    orgID,
		KeyId:    keyID,
		Disabled: updateAPIKeyDisabled(body),
	}))
	if err != nil {
		return nil, connectSDKError(err)
	}
	key, err := fromProtoAPIKey(resp.Msg.GetApiKey())
	if err != nil {
		return nil, err
	}
	return &key, nil
}

func createAPIKeyRequest(orgID string, body CreateAPIKeyBody) (*codewirev1.CreateApiKeyRequest, error) {
	req := &codewirev1.CreateApiKeyRequest{
		OrgId: orgID,
		Name:  body.Name,
	}
	if body.Scopes != nil {
		req.Scopes = append([]string(nil), (*body.Scopes)...)
	}
	if body.ExpiresInDays != nil {
		if *body.ExpiresInDays < math.MinInt32 || *body.ExpiresInDays > math.MaxInt32 {
			return nil, fmt.Errorf("codewire: expires_in_days is outside the API integer range")
		}
		expiresInDays := int32(*body.ExpiresInDays)
		req.ExpiresInDays = &expiresInDays
	}
	return req, nil
}

func updateAPIKeyDisabled(body any) *bool {
	encoded, err := json.Marshal(body)
	if err != nil {
		return nil
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(encoded, &fields) != nil {
		return nil
	}
	disabledJSON, ok := fields["disabled"]
	if !ok {
		return nil
	}
	var disabled bool
	if json.Unmarshal(disabledJSON, &disabled) != nil {
		return nil
	}
	return &disabled
}
