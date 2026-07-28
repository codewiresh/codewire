package codewire

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
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

// RedeemEnrollment redeems an enrollment token to register a node.
// This is a public endpoint -- no auth token required.
func (s *MeshNodeService) RedeemEnrollment(ctx context.Context, enrollmentToken, nodeName string) (*MeshNodeCredentials, error) {
	body, err := json.Marshal(map[string]string{
		"enrollment_token": enrollmentToken,
		"node_name":        nodeName,
	})
	if err != nil {
		return nil, fmt.Errorf("mesh: marshal enrollment redemption: %w", err)
	}
	req, err := http.NewRequestWithContext(
		ctx,
		http.MethodPost,
		s.client.baseURL+"/api/v1/node-enrollments/redeem",
		bytes.NewReader(body),
	)
	if err != nil {
		return nil, fmt.Errorf("mesh: create enrollment redemption request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	response, err := s.client.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("mesh: enrollment redemption request: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode >= 400 {
		detail, _ := io.ReadAll(io.LimitReader(response.Body, 1024))
		return nil, &Error{StatusCode: response.StatusCode, Detail: strings.TrimSpace(string(detail))}
	}
	var result MeshNodeCredentials
	if err := json.NewDecoder(response.Body).Decode(&result); err != nil {
		return nil, err
	}
	return &result, nil
}
