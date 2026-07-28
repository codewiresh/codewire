package codewire

import (
	"context"

	"connectrpc.com/connect"
	codewirev1 "github.com/codewiresh/codewire/libs/gen-go/codewire/v1"
)

// MeshGroupService handles mesh group operations.
type MeshGroupService struct {
	client *MeshClient
}

// Create creates a group in a network (owner required).
func (s *MeshGroupService) Create(ctx context.Context, orgID, networkID, name string) (*MeshGroup, error) {
	response, err := s.client.groupClient.CreateMeshGroup(ctx, connect.NewRequest(&codewirev1.CreateMeshGroupRequest{
		OrgId: orgID, NetworkId: networkID, Name: name,
	}))
	if err != nil {
		return nil, connectSDKError(err)
	}
	group, err := fromProtoMeshGroup(response.Msg.GetGroup())
	if err != nil {
		return nil, err
	}
	return &group, nil
}

// List returns all groups in a network (owner required).
func (s *MeshGroupService) List(ctx context.Context, orgID, networkID string) ([]MeshGroup, error) {
	var groups []MeshGroup
	request := &codewirev1.ListMeshGroupsRequest{OrgId: orgID, NetworkId: networkID}
	for {
		response, err := s.client.groupClient.ListMeshGroups(ctx, connect.NewRequest(request))
		if err != nil {
			return nil, connectSDKError(err)
		}
		for _, group := range response.Msg.GetGroups() {
			converted, err := fromProtoMeshGroup(group)
			if err != nil {
				return nil, err
			}
			groups = append(groups, converted)
		}
		request.PageToken = response.Msg.GetNextPageToken()
		if request.PageToken == "" {
			return groups, nil
		}
	}
}

// Get returns a group by name (owner required).
func (s *MeshGroupService) Get(ctx context.Context, orgID, networkID, name string) (*MeshGroup, error) {
	response, err := s.client.groupClient.GetMeshGroup(ctx, connect.NewRequest(&codewirev1.GetMeshGroupRequest{
		OrgId: orgID, NetworkId: networkID, GroupName: name,
	}))
	if err != nil {
		return nil, connectSDKError(err)
	}
	group, err := fromProtoMeshGroup(response.Msg.GetGroup())
	if err != nil {
		return nil, err
	}
	return &group, nil
}

// Delete removes a group (owner required).
func (s *MeshGroupService) Delete(ctx context.Context, orgID, networkID, name string) error {
	_, err := s.client.groupClient.DeleteMeshGroup(ctx, connect.NewRequest(&codewirev1.DeleteMeshGroupRequest{
		OrgId: orgID, NetworkId: networkID, GroupName: name,
	}))
	return connectSDKError(err)
}

// AddMember adds a session to a group.
func (s *MeshGroupService) AddMember(ctx context.Context, orgID, networkID, groupName, nodeName, sessionName string) (*MeshGroupMember, error) {
	response, err := s.client.groupClient.AddMeshGroupMember(ctx, connect.NewRequest(&codewirev1.AddMeshGroupMemberRequest{
		OrgId: orgID, NetworkId: networkID, GroupName: groupName, NodeName: nodeName, SessionName: sessionName,
	}))
	if err != nil {
		return nil, connectSDKError(err)
	}
	member, err := fromProtoMeshGroupMember(response.Msg.GetMember())
	if err != nil {
		return nil, err
	}
	return &member, nil
}

// RemoveMember removes a session from a group.
func (s *MeshGroupService) RemoveMember(ctx context.Context, orgID, networkID, groupName, nodeName, sessionName string) error {
	_, err := s.client.groupClient.RemoveMeshGroupMember(ctx, connect.NewRequest(&codewirev1.RemoveMeshGroupMemberRequest{
		OrgId: orgID, NetworkId: networkID, GroupName: groupName, NodeName: nodeName, SessionName: sessionName,
	}))
	return connectSDKError(err)
}

// SetPolicy updates a group's messaging and debug policies (owner required).
func (s *MeshGroupService) SetPolicy(ctx context.Context, orgID, networkID, groupName string, messagesPolicy MeshGroupMessagesPolicy, debugPolicy MeshGroupDebugPolicy) (*MeshGroupPolicy, error) {
	protoMessagesPolicy, err := toProtoMeshGroupMessagesPolicy(messagesPolicy)
	if err != nil {
		return nil, err
	}
	protoDebugPolicy, err := toProtoMeshGroupDebugPolicy(debugPolicy)
	if err != nil {
		return nil, err
	}
	response, err := s.client.groupClient.SetMeshGroupPolicy(ctx, connect.NewRequest(&codewirev1.SetMeshGroupPolicyRequest{
		OrgId: orgID, NetworkId: networkID, GroupName: groupName,
		MessagesPolicy: protoMessagesPolicy, DebugPolicy: protoDebugPolicy,
	}))
	if err != nil {
		return nil, connectSDKError(err)
	}
	policy, err := fromProtoMeshGroupPolicy(response.Msg.GetPolicy())
	if err != nil {
		return nil, err
	}
	return &policy, nil
}
