package codewire

import (
	"context"
	"time"

	"connectrpc.com/connect"
	codewirev1 "github.com/codewiresh/codewire/libs/gen-go/codewire/v1"
	"google.golang.org/protobuf/types/known/durationpb"
)

// MeshNodeService handles mesh node and enrollment operations.
type MeshNodeService struct {
	client *MeshClient
}

// List returns nodes in a network.
func (s *MeshNodeService) List(ctx context.Context, orgID, networkID string) ([]MeshNode, error) {
	var nodes []MeshNode
	request := &codewirev1.ListMeshNodesRequest{OrgId: orgID, NetworkId: networkID}
	for {
		response, err := s.client.nodeClient.ListMeshNodes(ctx, connect.NewRequest(request))
		if err != nil {
			return nil, connectSDKError(err)
		}
		for _, node := range response.Msg.GetNodes() {
			converted, err := fromProtoMeshNode(node)
			if err != nil {
				return nil, err
			}
			nodes = append(nodes, converted)
		}
		request.PageToken = response.Msg.GetNextPageToken()
		if request.PageToken == "" {
			return nodes, nil
		}
	}
}

// Revoke deletes a node from a network (owner required).
func (s *MeshNodeService) Revoke(ctx context.Context, orgID, networkID, nodeName string) error {
	_, err := s.client.nodeClient.RevokeMeshNode(ctx, connect.NewRequest(&codewirev1.RevokeMeshNodeRequest{
		OrgId: orgID, NetworkId: networkID, NodeName: nodeName,
	}))
	return connectSDKError(err)
}

// CreateEnrollment creates a one-use enrollment capability for registering a node.
// A zero ttl selects the server default.
func (s *MeshNodeService) CreateEnrollment(ctx context.Context, orgID, networkID, nodeName string, ttl time.Duration) (*MeshEnrollment, error) {
	request := &codewirev1.CreateMeshNodeEnrollmentRequest{
		OrgId: orgID, NetworkId: networkID, NodeName: nodeName,
	}
	if ttl != 0 {
		request.Ttl = durationpb.New(ttl)
	}
	response, err := s.client.nodeClient.CreateMeshNodeEnrollment(ctx, connect.NewRequest(request))
	if err != nil {
		return nil, connectSDKError(err)
	}
	enrollment, err := fromProtoMeshEnrollment(response.Msg.GetEnrollment())
	if err != nil {
		return nil, err
	}
	enrollment.EnrollmentCode = response.Msg.GetEnrollmentCode()
	return &enrollment, nil
}

// RedeemEnrollment consumes a one-use enrollment capability without sending a
// bearer. The generated response contains registration metadata only.
func (s *MeshNodeService) RedeemEnrollment(ctx context.Context, enrollmentCode, nodeName string) (*MeshNodeRegistration, error) {
	response, err := s.client.publicNodeClient.RedeemMeshNodeEnrollment(
		ctx,
		connect.NewRequest(&codewirev1.RedeemMeshNodeEnrollmentRequest{
			EnrollmentCode: enrollmentCode,
			NodeName:       nodeName,
		}),
	)
	if err != nil {
		return nil, connectSDKError(err)
	}
	node, err := fromProtoMeshNode(response.Msg.GetNode())
	if err != nil {
		return nil, err
	}
	enrollment, err := fromProtoMeshEnrollment(response.Msg.GetEnrollment())
	if err != nil {
		return nil, err
	}
	return &MeshNodeRegistration{Node: node, Enrollment: enrollment}, nil
}
