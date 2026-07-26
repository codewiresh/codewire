package codewire

import (
	"context"
	"fmt"

	"connectrpc.com/connect"
	codewirev1 "github.com/codewiresh/codewire/libs/gen-go/codewire/v1"
)

// TemplateService manages presets (environment templates).
type TemplateService struct {
	client *Client
}

// Create creates a new preset.
func (s *TemplateService) Create(ctx context.Context, body CreatePresetBody) (*Preset, error) {
	orgID, err := s.client.resolveOrgID()
	if err != nil {
		return nil, err
	}
	secretProjectID, err := s.resolveSecretProjectID(ctx, orgID, body.SecretProject, false)
	if err != nil {
		return nil, err
	}
	req, err := createPresetRequest(orgID, body, secretProjectID)
	if err != nil {
		return nil, err
	}
	response, err := s.client.presets.CreatePreset(ctx, connect.NewRequest(req))
	if err != nil {
		return nil, connectSDKError(err)
	}
	p, err := fromProtoPreset(response.Msg.GetPreset())
	if err != nil {
		return nil, err
	}
	return &p, nil
}

// List returns all presets for the organization.
func (s *TemplateService) List(ctx context.Context) ([]Preset, error) {
	orgID, err := s.client.resolveOrgID()
	if err != nil {
		return nil, err
	}
	var presets []Preset
	for pageToken := ""; ; {
		response, err := s.client.presets.ListPresets(ctx, connect.NewRequest(&codewirev1.ListPresetsRequest{
			OrgId: orgID, PageToken: pageToken,
		}))
		if err != nil {
			return nil, connectSDKError(err)
		}
		for _, preset := range response.Msg.GetPresets() {
			converted, err := fromProtoPreset(preset)
			if err != nil {
				return nil, err
			}
			presets = append(presets, converted)
		}
		pageToken = response.Msg.GetNextPageToken()
		if pageToken == "" {
			return presets, nil
		}
	}
}

// Get retrieves a preset by ID.
func (s *TemplateService) Get(ctx context.Context, presetID string) (*Preset, error) {
	orgID, err := s.client.resolveOrgID()
	if err != nil {
		return nil, err
	}
	response, err := s.client.presets.GetPreset(ctx, connect.NewRequest(&codewirev1.GetPresetRequest{
		OrgId: orgID, PresetId: presetID,
	}))
	if err != nil {
		return nil, connectSDKError(err)
	}
	p, err := fromProtoPreset(response.Msg.GetPreset())
	if err != nil {
		return nil, err
	}
	return &p, nil
}

// Update modifies an existing preset.
func (s *TemplateService) Update(ctx context.Context, presetID string, body UpdatePresetBody) (*Preset, error) {
	orgID, err := s.client.resolveOrgID()
	if err != nil {
		return nil, err
	}
	secretProjectID, err := s.resolveSecretProjectID(ctx, orgID, body.SecretProject, true)
	if err != nil {
		return nil, err
	}
	req, err := updatePresetRequest(orgID, presetID, body, secretProjectID)
	if err != nil {
		return nil, err
	}
	response, err := s.client.presets.UpdatePreset(ctx, connect.NewRequest(req))
	if err != nil {
		return nil, connectSDKError(err)
	}
	p, err := fromProtoPreset(response.Msg.GetPreset())
	if err != nil {
		return nil, err
	}
	return &p, nil
}

// Delete removes a preset by ID.
func (s *TemplateService) Delete(ctx context.Context, presetID string) error {
	orgID, err := s.client.resolveOrgID()
	if err != nil {
		return err
	}
	_, err = s.client.presets.DeletePreset(ctx, connect.NewRequest(&codewirev1.DeletePresetRequest{
		OrgId: orgID, PresetId: presetID,
	}))
	return connectSDKError(err)
}

func (s *TemplateService) resolveSecretProjectID(ctx context.Context, orgID string, selection *string, update bool) (*string, error) {
	if selection == nil {
		return nil, nil
	}
	if *selection == "" {
		if update {
			return selection, nil
		}
		return nil, nil
	}

	for pageToken := ""; ; {
		response, err := s.client.secrets.ListSecretProjects(ctx, connect.NewRequest(&codewirev1.ListSecretProjectsRequest{
			OrgId: orgID, PageToken: pageToken,
		}))
		if err != nil {
			return nil, connectSDKError(err)
		}
		for _, project := range response.Msg.GetSecretProjects() {
			if project.GetId() == *selection || project.GetName() == *selection {
				id := project.GetId()
				return &id, nil
			}
		}
		pageToken = response.Msg.GetNextPageToken()
		if pageToken == "" {
			return nil, fmt.Errorf("codewire: secret project not found: %s", *selection)
		}
	}
}
