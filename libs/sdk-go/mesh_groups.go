package codewire

import (
	"context"
	"fmt"
	"net/url"
)

// MeshGroupService handles mesh group operations.
type MeshGroupService struct {
	client *MeshClient
}

// Create creates a group in a network (owner required).
func (s *MeshGroupService) Create(ctx context.Context, networkID, name string) (*MeshGroup, error) {
	var group MeshGroup
	err := s.client.doAuth(ctx, "POST", "/api/v1/groups", map[string]string{
		"network_id": networkID,
		"name":       name,
	}, &group)
	if err != nil {
		return nil, err
	}
	return &group, nil
}

// List returns all groups in a network (owner required).
func (s *MeshGroupService) List(ctx context.Context, networkID string) ([]MeshGroup, error) {
	var groups []MeshGroup
	err := s.client.doAuth(ctx, "GET",
		fmt.Sprintf("/api/v1/groups?network_id=%s", url.QueryEscape(networkID)),
		nil, &groups)
	return groups, err
}

// Get returns a group by name (owner required).
func (s *MeshGroupService) Get(ctx context.Context, networkID, name string) (*MeshGroup, error) {
	var group MeshGroup
	err := s.client.doAuth(ctx, "GET",
		fmt.Sprintf("/api/v1/groups/%s?network_id=%s", url.PathEscape(name), url.QueryEscape(networkID)),
		nil, &group)
	if err != nil {
		return nil, err
	}
	return &group, nil
}

// Delete removes a group (owner required).
func (s *MeshGroupService) Delete(ctx context.Context, networkID, name string) error {
	return s.client.doAuth(ctx, "DELETE",
		fmt.Sprintf("/api/v1/groups/%s?network_id=%s", url.PathEscape(name), url.QueryEscape(networkID)),
		nil, nil)
}

// AddMember adds a session to a group.
func (s *MeshGroupService) AddMember(ctx context.Context, networkID, groupName, nodeName, sessionName string) (*MeshGroupMember, error) {
	var member MeshGroupMember
	err := s.client.doAuth(ctx, "POST",
		fmt.Sprintf("/api/v1/groups/%s/members", url.PathEscape(groupName)),
		map[string]string{
			"network_id":   networkID,
			"node_name":    nodeName,
			"session_name": sessionName,
		}, &member)
	if err != nil {
		return nil, err
	}
	return &member, nil
}

// RemoveMember removes a session from a group.
func (s *MeshGroupService) RemoveMember(ctx context.Context, networkID, groupName, nodeName, sessionName string) error {
	return s.client.doAuth(ctx, "DELETE",
		fmt.Sprintf("/api/v1/groups/%s/members?network_id=%s&node_name=%s&session_name=%s",
			url.PathEscape(groupName), url.QueryEscape(networkID),
			url.QueryEscape(nodeName), url.QueryEscape(sessionName)),
		nil, nil)
}

// SetPolicy updates a group's messaging and debug policies (owner required).
func (s *MeshGroupService) SetPolicy(ctx context.Context, networkID, groupName, messagesPolicy, debugPolicy string) (*MeshGroupPolicy, error) {
	var policy MeshGroupPolicy
	err := s.client.doAuth(ctx, "PUT",
		fmt.Sprintf("/api/v1/groups/%s/policy", url.PathEscape(groupName)),
		map[string]string{
			"network_id":      networkID,
			"messages_policy": messagesPolicy,
			"debug_policy":    debugPolicy,
		}, &policy)
	if err != nil {
		return nil, err
	}
	return &policy, nil
}
