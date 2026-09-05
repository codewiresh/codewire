package codewire

import (
	"context"

	"connectrpc.com/connect"
	codewirev1 "github.com/codewiresh/codewire/libs/gen-go/codewire/v1"
)

// PresetService manages reusable environment presets.
type PresetService struct {
	client *Client
}

// Create creates a new preset.
func (s *PresetService) Create(ctx context.Context, body CreatePresetBody) (*Preset, error) {
	orgID, err := s.client.resolveOrgID()
	if err != nil {
		return nil, err
	}
	req, err := createPresetRequest(orgID, body)
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
func (s *PresetService) List(ctx context.Context) ([]Preset, error) {
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
func (s *PresetService) Get(ctx context.Context, presetID string) (*Preset, error) {
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
func (s *PresetService) Update(ctx context.Context, presetID string, body UpdatePresetBody) (*Preset, error) {
	orgID, err := s.client.resolveOrgID()
	if err != nil {
		return nil, err
	}
	req, err := updatePresetRequest(orgID, presetID, body)
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
func (s *PresetService) Delete(ctx context.Context, presetID string) error {
	orgID, err := s.client.resolveOrgID()
	if err != nil {
		return err
	}
	_, err = s.client.presets.DeletePreset(ctx, connect.NewRequest(&codewirev1.DeletePresetRequest{
		OrgId: orgID, PresetId: presetID,
	}))
	return connectSDKError(err)
}
