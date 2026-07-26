package codewire

import "context"

// MeshNetworkService handles mesh network operations.
type MeshNetworkService struct {
	client *MeshClient
}

// Create creates or claims a network.
func (s *MeshNetworkService) Create(ctx context.Context, networkID string) error {
	return s.client.doAuth(ctx, "POST", "/api/v1/networks", map[string]string{
		"network_id": networkID,
	}, nil)
}

// List returns all networks the authenticated user is a member of.
func (s *MeshNetworkService) List(ctx context.Context) ([]MeshNetwork, error) {
	var networks []MeshNetwork
	err := s.client.doAuth(ctx, "GET", "/api/v1/networks", nil, &networks)
	return networks, err
}
