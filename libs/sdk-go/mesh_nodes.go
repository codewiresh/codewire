package codewire

import (
	"context"
	"fmt"
	"net/url"
)

// MeshNodeService handles mesh node and enrollment operations.
type MeshNodeService struct {
	client *MeshClient
}

// List returns nodes in a network.
func (s *MeshNodeService) List(ctx context.Context, networkID string) ([]MeshNode, error) {
	var nodes []MeshNode
	err := s.client.doAuth(ctx, "GET",
		fmt.Sprintf("/api/v1/nodes?network_id=%s", url.QueryEscape(networkID)),
		nil, &nodes)
	return nodes, err
}

// Revoke deletes a node from a network (owner required).
func (s *MeshNodeService) Revoke(ctx context.Context, networkID, nodeName string) error {
	return s.client.doAuth(ctx, "DELETE",
		fmt.Sprintf("/api/v1/nodes/%s?network_id=%s", url.PathEscape(nodeName), url.QueryEscape(networkID)),
		nil, nil)
}

// CreateEnrollment creates an enrollment token for registering nodes.
func (s *MeshNodeService) CreateEnrollment(ctx context.Context, networkID, nodeName string, uses int, ttl string) (*MeshEnrollment, error) {
	body := map[string]any{
		"network_id": networkID,
		"node_name":  nodeName,
		"uses":       uses,
	}
	if ttl != "" {
		body["ttl"] = ttl
	}
	var result MeshEnrollment
	err := s.client.doAuth(ctx, "POST", "/api/v1/node-enrollments", body, &result)
	if err != nil {
		return nil, err
	}
	return &result, nil
}

// RedeemEnrollment redeems an enrollment token to register a node.
// This is a public endpoint -- no auth token required.
func (s *MeshNodeService) RedeemEnrollment(ctx context.Context, enrollmentToken, nodeName string) (*MeshNodeCredentials, error) {
	var result MeshNodeCredentials
	err := s.client.doPublic(ctx, "POST", "/api/v1/node-enrollments/redeem", map[string]string{
		"enrollment_token": enrollmentToken,
		"node_name":        nodeName,
	}, &result)
	if err != nil {
		return nil, err
	}
	return &result, nil
}
