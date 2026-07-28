package codewire

import (
	"context"

	"connectrpc.com/connect"
	codewirev1 "github.com/codewiresh/codewire/libs/gen-go/codewire/v1"
)

// MeshNetworkService handles mesh network operations.
type MeshNetworkService struct {
	client *MeshClient
}

// Create creates a network owned by orgID.
func (s *MeshNetworkService) Create(ctx context.Context, orgID, networkID string) (*MeshNetwork, error) {
	response, err := s.client.networkClient.CreateMeshNetwork(ctx, connect.NewRequest(&codewirev1.CreateMeshNetworkRequest{
		OrgId: orgID, NetworkId: networkID,
	}))
	if err != nil {
		return nil, connectSDKError(err)
	}
	network, err := fromProtoMeshNetwork(response.Msg.GetNetwork())
	if err != nil {
		return nil, err
	}
	return &network, nil
}

// List returns networks owned by the exact orgID.
func (s *MeshNetworkService) List(ctx context.Context, orgID string) ([]MeshNetwork, error) {
	var networks []MeshNetwork
	request := &codewirev1.ListMeshNetworksRequest{OrgId: orgID}
	for {
		response, err := s.client.networkClient.ListMeshNetworks(ctx, connect.NewRequest(request))
		if err != nil {
			return nil, connectSDKError(err)
		}
		for _, network := range response.Msg.GetNetworks() {
			converted, err := fromProtoMeshNetwork(network)
			if err != nil {
				return nil, err
			}
			networks = append(networks, converted)
		}
		request.PageToken = response.Msg.GetNextPageToken()
		if request.PageToken == "" {
			return networks, nil
		}
	}
}
