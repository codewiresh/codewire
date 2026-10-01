package codewire

import (
	"context"
	"fmt"

	"connectrpc.com/connect"
	codewirev1 "github.com/codewiresh/codewire/libs/gen-go/codewire/v1"
)

// AccessProfileEntry is a metadata-only credential reference. Duplicate slots
// are invalid, never last-writer-wins.
type AccessProfileEntry struct {
	CapabilitySlot string `json:"capability_slot"`
	CredentialID   string `json:"credential_id"`
}

// AccessProfile is one immutable revision of a personal platform profile. Every
// profile includes the account's one GitHub connection; GitHub is never an entry.
type AccessProfile struct {
	ID       string               `json:"id"`
	Name     string               `json:"name"`
	Revision uint64               `json:"revision"`
	Entries  []AccessProfileEntry `json:"entries"`
}

// EnvironmentAccessProfileBinding is an exact selection, not an access grant
// or proof of runtime readiness. Revisions remain lossless uint64 values.
type EnvironmentAccessProfileBinding struct {
	EnvironmentID         string `json:"environment_id"`
	AccessProfileID       string `json:"access_profile_id"`
	AccessProfileRevision uint64 `json:"access_profile_revision"`
}

// EnvironmentAccessProfile reports an optional binding and stored consent.
type EnvironmentAccessProfile struct {
	Binding                      *EnvironmentAccessProfileBinding `json:"binding,omitempty"`
	PersonalCredentialsConfirmed bool                             `json:"personal_credentials_confirmed"`
}

// AccessProfileService manages the authenticated user's personal profiles.
// Organization API keys cannot manage this account resource; supply the existing
// user OAuth bearer to New. No method carries protected provider material,
// infers consent, or fetches and retries a stale compare-and-swap.
type AccessProfileService struct{ client *Client }

func accessProfileRevision(value uint64) error {
	if value == 0 {
		return fmt.Errorf("codewire: access profile revision must be a positive uint64")
	}
	return nil
}

func accessProfileEntries(entries []AccessProfileEntry) ([]*codewirev1.AccessProfileEntry, error) {
	result := make([]*codewirev1.AccessProfileEntry, 0, len(entries))
	slots := make(map[string]bool, len(entries))
	for _, entry := range entries {
		if entry.CapabilitySlot == "github" {
			return nil, fmt.Errorf("codewire: every profile includes the account's GitHub connection; it is never an entry")
		}
		if slots[entry.CapabilitySlot] {
			return nil, fmt.Errorf("codewire: duplicate access profile capability slot")
		}
		slots[entry.CapabilitySlot] = true
		result = append(result, &codewirev1.AccessProfileEntry{CapabilitySlot: entry.CapabilitySlot, CredentialId: entry.CredentialID})
	}
	return result, nil
}

func fromProtoAccessProfile(profile *codewirev1.AccessProfile) (*AccessProfile, error) {
	if profile == nil {
		return nil, fmt.Errorf("codewire: access profile response omitted access_profile")
	}
	if err := accessProfileRevision(profile.GetRevision()); err != nil {
		return nil, err
	}
	result := &AccessProfile{ID: profile.GetId(), Name: profile.GetName(), Revision: profile.GetRevision(), Entries: make([]AccessProfileEntry, 0, len(profile.GetEntries()))}
	for _, entry := range profile.GetEntries() {
		if entry == nil {
			return nil, fmt.Errorf("codewire: access profile response omitted entry")
		}
		result.Entries = append(result.Entries, AccessProfileEntry{CapabilitySlot: entry.GetCapabilitySlot(), CredentialID: entry.GetCredentialId()})
	}
	return result, nil
}

func fromProtoAccessProfileBinding(binding *codewirev1.EnvironmentAccessProfileBinding) (*EnvironmentAccessProfileBinding, error) {
	if binding == nil {
		return nil, fmt.Errorf("codewire: access profile response omitted binding")
	}
	if err := accessProfileRevision(binding.GetAccessProfileRevision()); err != nil {
		return nil, err
	}
	return &EnvironmentAccessProfileBinding{EnvironmentID: binding.GetEnvironmentId(), AccessProfileID: binding.GetAccessProfileId(), AccessProfileRevision: binding.GetAccessProfileRevision()}, nil
}

// List consumes all pages with the server's default page size.
func (s *AccessProfileService) List(ctx context.Context) ([]AccessProfile, error) {
	profiles := make([]AccessProfile, 0)
	for pageToken := ""; ; {
		response, err := s.client.accessProfiles.ListAccessProfiles(ctx, connect.NewRequest(&codewirev1.ListAccessProfilesRequest{PageToken: pageToken}))
		if err != nil {
			return nil, connectSDKError(err)
		}
		for _, profile := range response.Msg.GetAccessProfiles() {
			value, err := fromProtoAccessProfile(profile)
			if err != nil {
				return nil, err
			}
			profiles = append(profiles, *value)
		}
		pageToken = response.Msg.GetNextPageToken()
		if pageToken == "" {
			return profiles, nil
		}
	}
}

// Get selects an ID. A nil revision means current; a nonnil revision is exact.
func (s *AccessProfileService) Get(ctx context.Context, id string, revision *uint64) (*AccessProfile, error) {
	return s.get(ctx, &codewirev1.GetAccessProfileRequest{Selector: &codewirev1.GetAccessProfileRequest_AccessProfileId{AccessProfileId: id}}, revision)
}

// GetByName selects a personal name, without guessing whether a string is an ID.
func (s *AccessProfileService) GetByName(ctx context.Context, name string, revision *uint64) (*AccessProfile, error) {
	return s.get(ctx, &codewirev1.GetAccessProfileRequest{Selector: &codewirev1.GetAccessProfileRequest_Name{Name: name}}, revision)
}

func (s *AccessProfileService) get(ctx context.Context, request *codewirev1.GetAccessProfileRequest, revision *uint64) (*AccessProfile, error) {
	if revision != nil {
		if err := accessProfileRevision(*revision); err != nil {
			return nil, err
		}
		value := *revision
		request.Revision = &value
	}
	response, err := s.client.accessProfiles.GetAccessProfile(ctx, connect.NewRequest(request))
	if err != nil {
		return nil, connectSDKError(err)
	}
	return fromProtoAccessProfile(response.Msg.GetAccessProfile())
}

// Create publishes the supplied complete entry set as a new personal profile.
func (s *AccessProfileService) Create(ctx context.Context, name string, entries []AccessProfileEntry) (*AccessProfile, error) {
	values, err := accessProfileEntries(entries)
	if err != nil {
		return nil, err
	}
	response, err := s.client.accessProfiles.CreateAccessProfile(ctx, connect.NewRequest(&codewirev1.CreateAccessProfileRequest{Name: name, Entries: values}))
	if err != nil {
		return nil, connectSDKError(err)
	}
	return fromProtoAccessProfile(response.Msg.GetAccessProfile())
}

// Update replaces every entry at the exact expected revision. Empty entries
// explicitly remove every slot; existing environment bindings remain pinned.
func (s *AccessProfileService) Update(ctx context.Context, id string, expectedRevision uint64, entries []AccessProfileEntry) (*AccessProfile, error) {
	if err := accessProfileRevision(expectedRevision); err != nil {
		return nil, err
	}
	values, err := accessProfileEntries(entries)
	if err != nil {
		return nil, err
	}
	response, err := s.client.accessProfiles.UpdateAccessProfile(ctx, connect.NewRequest(&codewirev1.UpdateAccessProfileRequest{AccessProfileId: id, ExpectedRevision: expectedRevision, Entries: values}))
	if err != nil {
		return nil, connectSDKError(err)
	}
	return fromProtoAccessProfile(response.Msg.GetAccessProfile())
}

// Rename relabels a profile at the exact expected current revision. No revision
// is published, the entries are unchanged and environment bindings stay pinned.
func (s *AccessProfileService) Rename(ctx context.Context, id string, expectedRevision uint64, name string) (*AccessProfile, error) {
	if err := accessProfileRevision(expectedRevision); err != nil {
		return nil, err
	}
	response, err := s.client.accessProfiles.RenameAccessProfile(ctx, connect.NewRequest(&codewirev1.RenameAccessProfileRequest{AccessProfileId: id, ExpectedRevision: expectedRevision, Name: name}))
	if err != nil {
		return nil, connectSDKError(err)
	}
	return fromProtoAccessProfile(response.Msg.GetAccessProfile())
}

// Delete removes a profile only at the exact expected current revision.
func (s *AccessProfileService) Delete(ctx context.Context, id string, expectedRevision uint64) error {
	if err := accessProfileRevision(expectedRevision); err != nil {
		return err
	}
	_, err := s.client.accessProfiles.DeleteAccessProfile(ctx, connect.NewRequest(&codewirev1.DeleteAccessProfileRequest{AccessProfileId: id, ExpectedRevision: expectedRevision}))
	return connectSDKError(err)
}

// GetEnvironmentBinding returns an optional exact binding and stored consent.
func (s *AccessProfileService) GetEnvironmentBinding(ctx context.Context, environmentID string) (*EnvironmentAccessProfile, error) {
	response, err := s.client.accessProfiles.GetEnvironmentAccessProfile(ctx, connect.NewRequest(&codewirev1.GetEnvironmentAccessProfileRequest{EnvironmentId: environmentID}))
	if err != nil {
		return nil, connectSDKError(err)
	}
	result := &EnvironmentAccessProfile{PersonalCredentialsConfirmed: response.Msg.GetPersonalCredentialsConfirmed()}
	if response.Msg.GetBinding() != nil {
		result.Binding, err = fromProtoAccessProfileBinding(response.Msg.GetBinding())
		if err != nil {
			return nil, err
		}
	}
	return result, nil
}
