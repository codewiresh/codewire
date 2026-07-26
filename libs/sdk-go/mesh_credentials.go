package codewire

import (
	"context"
	"fmt"
	"net/url"
)

// MeshCredentialService handles mesh credential operations.
type MeshCredentialService struct {
	client *MeshClient
}

// IssueRuntimeCredential issues a short-lived runtime credential for a client.
func (s *MeshCredentialService) IssueRuntimeCredential(ctx context.Context, networkID string) (*MeshRuntimeCredential, error) {
	var cred MeshRuntimeCredential
	err := s.client.doAuth(ctx, "POST",
		fmt.Sprintf("/api/v1/network-auth/runtime/client?network_id=%s", url.QueryEscape(networkID)),
		nil, &cred)
	if err != nil {
		return nil, err
	}
	return &cred, nil
}

// FetchVerifierBundle returns the public keys for verifying credentials in a network.
func (s *MeshCredentialService) FetchVerifierBundle(ctx context.Context, networkID string) (*MeshVerifierBundle, error) {
	var bundle MeshVerifierBundle
	err := s.client.doAuth(ctx, "GET",
		fmt.Sprintf("/api/v1/network-auth/bundle?network_id=%s", url.QueryEscape(networkID)),
		nil, &bundle)
	if err != nil {
		return nil, err
	}
	return &bundle, nil
}

// IssueNodeRuntimeCredential issues a runtime credential using node auth.
// Uses the provided node token instead of the client's auth token.
func (s *MeshCredentialService) IssueNodeRuntimeCredential(ctx context.Context, nodeToken string) (*MeshRuntimeCredential, error) {
	var cred MeshRuntimeCredential
	err := s.client.doRequest(ctx, "POST", "/api/v1/network-auth/runtime/node", nodeToken, nil, &cred)
	if err != nil {
		return nil, err
	}
	return &cred, nil
}

// IssueSenderDelegation issues a sender delegation using node auth.
func (s *MeshCredentialService) IssueSenderDelegation(ctx context.Context, nodeToken string, sourceNode string, fromSessionID *uint32, fromSessionName string, verbs []string, audienceNode string) (*MeshSenderDelegation, error) {
	body := map[string]any{
		"source_node": sourceNode,
		"verbs":       verbs,
	}
	if fromSessionID != nil {
		body["from_session_id"] = *fromSessionID
	}
	if fromSessionName != "" {
		body["from_session_name"] = fromSessionName
	}
	if audienceNode != "" {
		body["audience_node"] = audienceNode
	}
	var deleg MeshSenderDelegation
	err := s.client.doRequest(ctx, "POST", "/api/v1/network-auth/delegation/node", nodeToken, body, &deleg)
	if err != nil {
		return nil, err
	}
	return &deleg, nil
}
