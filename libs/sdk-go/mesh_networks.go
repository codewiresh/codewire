package codewire

import (
	"context"
	"net/url"
)

// MeshNetworkService handles mesh network operations.
type MeshNetworkService struct {
	client *MeshClient
}

// Create creates a network owned by orgID.
func (s *MeshNetworkService) Create(ctx context.Context, orgID, networkID string) error {
	return s.client.doAuth(ctx, "POST", "/api/v1/networks", map[string]string{
		"org_id":     orgID,
		"network_id": networkID,
	}, nil)
}

// List returns networks owned by the exact orgID.
func (s *MeshNetworkService) List(ctx context.Context, orgID string) ([]MeshNetwork, error) {
	var networks []MeshNetwork
	err := s.client.doAuth(ctx, "GET", "/api/v1/networks?org_id="+url.QueryEscape(orgID), nil, &networks)
	return networks, err
}
