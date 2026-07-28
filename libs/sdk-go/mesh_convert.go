package codewire

import (
	"fmt"
	"sync"
	"time"

	codewirev1 "github.com/codewiresh/codewire/libs/gen-go/codewire/v1"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/types/known/timestamppb"
)

var (
	meshConverterCoverageOnce sync.Once
	meshConverterCoverageErr  error
)

func fromProtoMeshNetwork(network *codewirev1.MeshNetwork) (MeshNetwork, error) {
	if err := ensureMeshConverterCoverage(); err != nil {
		return MeshNetwork{}, err
	}
	if network == nil {
		return MeshNetwork{}, nil
	}
	createdAt, err := meshTimestamp("network created_at", network.GetCreatedAt())
	if err != nil {
		return MeshNetwork{}, err
	}
	return MeshNetwork{
		ID: network.GetId(), OrgID: network.GetOrgId(), CreatedAt: createdAt,
		NodeCount: network.GetNodeCount(), InviteCount: network.GetInviteCount(),
	}, nil
}

func fromProtoMeshNode(node *codewirev1.MeshNode) (MeshNode, error) {
	if err := ensureMeshConverterCoverage(); err != nil {
		return MeshNode{}, err
	}
	if node == nil {
		return MeshNode{}, nil
	}
	return MeshNode{
		OrgID: node.GetOrgId(), NetworkID: node.GetNetworkId(), Name: node.GetName(),
		PeerURL: node.GetPeerUrl(), Connected: node.GetConnected(),
	}, nil
}

func fromProtoMeshEnrollment(enrollment *codewirev1.MeshNodeEnrollment) (MeshEnrollment, error) {
	if err := ensureMeshConverterCoverage(); err != nil {
		return MeshEnrollment{}, err
	}
	if enrollment == nil {
		return MeshEnrollment{}, nil
	}
	expiresAt, err := meshTimestamp("enrollment expires_at", enrollment.GetExpiresAt())
	if err != nil {
		return MeshEnrollment{}, err
	}
	createdAt, err := meshTimestamp("enrollment created_at", enrollment.GetCreatedAt())
	if err != nil {
		return MeshEnrollment{}, err
	}
	redeemedAt, err := optionalMeshTimestamp("enrollment redeemed_at", enrollment.GetRedeemedAt())
	if err != nil {
		return MeshEnrollment{}, err
	}
	return MeshEnrollment{
		ID: enrollment.GetId(), OrgID: enrollment.GetOrgId(), NetworkID: enrollment.GetNetworkId(),
		NodeName: enrollment.GetNodeName(), OwnerUserID: enrollment.GetOwnerUserId(),
		IssuedByUserID: enrollment.GetIssuedByUserId(), ExpiresAt: expiresAt,
		CreatedAt: createdAt, RedeemedAt: redeemedAt,
	}, nil
}

func fromProtoMeshGroup(group *codewirev1.MeshGroup) (MeshGroup, error) {
	if err := ensureMeshConverterCoverage(); err != nil {
		return MeshGroup{}, err
	}
	if group == nil {
		return MeshGroup{}, nil
	}
	createdAt, err := meshTimestamp("group created_at", group.GetCreatedAt())
	if err != nil {
		return MeshGroup{}, err
	}
	members := make([]MeshGroupMember, 0, len(group.GetMembers()))
	for _, member := range group.GetMembers() {
		converted, err := fromProtoMeshGroupMember(member)
		if err != nil {
			return MeshGroup{}, err
		}
		members = append(members, converted)
	}
	var policy *MeshGroupPolicy
	if group.GetPolicy() != nil {
		converted, err := fromProtoMeshGroupPolicy(group.GetPolicy())
		if err != nil {
			return MeshGroup{}, err
		}
		policy = &converted
	}
	return MeshGroup{
		OrgID: group.GetOrgId(), NetworkID: group.GetNetworkId(), Name: group.GetName(),
		CreatedAt: createdAt, CreatedByUserID: group.GetCreatedByUserId(),
		Members: members, Policy: policy,
	}, nil
}

func fromProtoMeshGroupMember(member *codewirev1.MeshGroupMember) (MeshGroupMember, error) {
	if err := ensureMeshConverterCoverage(); err != nil {
		return MeshGroupMember{}, err
	}
	if member == nil {
		return MeshGroupMember{}, nil
	}
	createdAt, err := meshTimestamp("group member created_at", member.GetCreatedAt())
	if err != nil {
		return MeshGroupMember{}, err
	}
	return MeshGroupMember{
		OrgID: member.GetOrgId(), NetworkID: member.GetNetworkId(),
		GroupName: member.GetGroupName(), NodeName: member.GetNodeName(),
		SessionName: member.GetSessionName(), CreatedAt: createdAt,
	}, nil
}

func fromProtoMeshGroupPolicy(policy *codewirev1.MeshGroupPolicy) (MeshGroupPolicy, error) {
	if err := ensureMeshConverterCoverage(); err != nil {
		return MeshGroupPolicy{}, err
	}
	if policy == nil {
		return MeshGroupPolicy{}, nil
	}
	messagesPolicy, err := fromProtoMeshGroupMessagesPolicy(policy.GetMessagesPolicy())
	if err != nil {
		return MeshGroupPolicy{}, err
	}
	debugPolicy, err := fromProtoMeshGroupDebugPolicy(policy.GetDebugPolicy())
	if err != nil {
		return MeshGroupPolicy{}, err
	}
	updatedAt, err := meshTimestamp("group policy updated_at", policy.GetUpdatedAt())
	if err != nil {
		return MeshGroupPolicy{}, err
	}
	return MeshGroupPolicy{
		OrgID: policy.GetOrgId(), NetworkID: policy.GetNetworkId(), GroupName: policy.GetGroupName(),
		MessagesPolicy: messagesPolicy, DebugPolicy: debugPolicy, UpdatedAt: updatedAt,
	}, nil
}

func fromProtoMeshKeyValue(entry *codewirev1.MeshKeyValue) (MeshKVEntry, error) {
	if err := ensureMeshConverterCoverage(); err != nil {
		return MeshKVEntry{}, err
	}
	if entry == nil {
		return MeshKVEntry{}, nil
	}
	expiresAt, err := optionalMeshTimestamp("key value expires_at", entry.GetExpiresAt())
	if err != nil {
		return MeshKVEntry{}, err
	}
	return MeshKVEntry{
		OrgID: entry.GetOrgId(), NetworkID: entry.GetNetworkId(), Namespace: entry.GetNamespace(),
		Key: entry.GetKey(), Value: append([]byte(nil), entry.GetValue()...), ExpiresAt: expiresAt,
	}, nil
}

func fromProtoMeshGroupMessagesPolicy(value codewirev1.MeshGroupMessagesPolicy) (MeshGroupMessagesPolicy, error) {
	switch value {
	case codewirev1.MeshGroupMessagesPolicy_MESH_GROUP_MESSAGES_POLICY_UNSPECIFIED:
		return MeshGroupMessagesPolicyUnspecified, nil
	case codewirev1.MeshGroupMessagesPolicy_MESH_GROUP_MESSAGES_POLICY_INTERNAL_ONLY:
		return MeshGroupMessagesPolicyInternalOnly, nil
	case codewirev1.MeshGroupMessagesPolicy_MESH_GROUP_MESSAGES_POLICY_OPEN:
		return MeshGroupMessagesPolicyOpen, nil
	default:
		return "", fmt.Errorf("codewire: unknown Mesh group messages policy %d", value)
	}
}

func toProtoMeshGroupMessagesPolicy(value MeshGroupMessagesPolicy) (codewirev1.MeshGroupMessagesPolicy, error) {
	switch value {
	case MeshGroupMessagesPolicyUnspecified:
		return codewirev1.MeshGroupMessagesPolicy_MESH_GROUP_MESSAGES_POLICY_UNSPECIFIED, nil
	case MeshGroupMessagesPolicyInternalOnly:
		return codewirev1.MeshGroupMessagesPolicy_MESH_GROUP_MESSAGES_POLICY_INTERNAL_ONLY, nil
	case MeshGroupMessagesPolicyOpen:
		return codewirev1.MeshGroupMessagesPolicy_MESH_GROUP_MESSAGES_POLICY_OPEN, nil
	default:
		return 0, fmt.Errorf("codewire: unknown Mesh group messages policy %q", value)
	}
}

func fromProtoMeshGroupDebugPolicy(value codewirev1.MeshGroupDebugPolicy) (MeshGroupDebugPolicy, error) {
	switch value {
	case codewirev1.MeshGroupDebugPolicy_MESH_GROUP_DEBUG_POLICY_UNSPECIFIED:
		return MeshGroupDebugPolicyUnspecified, nil
	case codewirev1.MeshGroupDebugPolicy_MESH_GROUP_DEBUG_POLICY_NONE:
		return MeshGroupDebugPolicyNone, nil
	case codewirev1.MeshGroupDebugPolicy_MESH_GROUP_DEBUG_POLICY_OBSERVE_ONLY:
		return MeshGroupDebugPolicyObserveOnly, nil
	case codewirev1.MeshGroupDebugPolicy_MESH_GROUP_DEBUG_POLICY_FULL:
		return MeshGroupDebugPolicyFull, nil
	default:
		return "", fmt.Errorf("codewire: unknown Mesh group debug policy %d", value)
	}
}

func toProtoMeshGroupDebugPolicy(value MeshGroupDebugPolicy) (codewirev1.MeshGroupDebugPolicy, error) {
	switch value {
	case MeshGroupDebugPolicyUnspecified:
		return codewirev1.MeshGroupDebugPolicy_MESH_GROUP_DEBUG_POLICY_UNSPECIFIED, nil
	case MeshGroupDebugPolicyNone:
		return codewirev1.MeshGroupDebugPolicy_MESH_GROUP_DEBUG_POLICY_NONE, nil
	case MeshGroupDebugPolicyObserveOnly:
		return codewirev1.MeshGroupDebugPolicy_MESH_GROUP_DEBUG_POLICY_OBSERVE_ONLY, nil
	case MeshGroupDebugPolicyFull:
		return codewirev1.MeshGroupDebugPolicy_MESH_GROUP_DEBUG_POLICY_FULL, nil
	default:
		return 0, fmt.Errorf("codewire: unknown Mesh group debug policy %q", value)
	}
}

func meshTimestamp(name string, timestamp *timestamppb.Timestamp) (time.Time, error) {
	if timestamp == nil {
		return time.Time{}, nil
	}
	if err := timestamp.CheckValid(); err != nil {
		return time.Time{}, fmt.Errorf("codewire: Mesh %s: invalid timestamp: %w", name, err)
	}
	return timestamp.AsTime().UTC(), nil
}

func optionalMeshTimestamp(name string, timestamp *timestamppb.Timestamp) (*time.Time, error) {
	if timestamp == nil {
		return nil, nil
	}
	value, err := meshTimestamp(name, timestamp)
	if err != nil {
		return nil, err
	}
	return &value, nil
}

func ensureMeshConverterCoverage() error {
	meshConverterCoverageOnce.Do(func() {
		checks := []struct {
			descriptor protoreflect.MessageDescriptor
			fields     []protoreflect.Name
		}{
			{codewirev1.File_codewire_v1_mesh_network_proto.Messages().ByName("MeshNetwork"), []protoreflect.Name{"id", "org_id", "created_at", "node_count", "invite_count"}},
			{codewirev1.File_codewire_v1_mesh_node_proto.Messages().ByName("MeshNode"), []protoreflect.Name{"org_id", "network_id", "name", "peer_url", "connected"}},
			{codewirev1.File_codewire_v1_mesh_node_proto.Messages().ByName("MeshNodeEnrollment"), []protoreflect.Name{"id", "org_id", "network_id", "node_name", "owner_user_id", "issued_by_user_id", "expires_at", "created_at", "redeemed_at"}},
			{codewirev1.File_codewire_v1_mesh_group_proto.Messages().ByName("MeshGroup"), []protoreflect.Name{"org_id", "network_id", "name", "created_at", "created_by_user_id", "members", "policy"}},
			{codewirev1.File_codewire_v1_mesh_group_proto.Messages().ByName("MeshGroupMember"), []protoreflect.Name{"org_id", "network_id", "group_name", "node_name", "session_name", "created_at"}},
			{codewirev1.File_codewire_v1_mesh_group_proto.Messages().ByName("MeshGroupPolicy"), []protoreflect.Name{"org_id", "network_id", "group_name", "messages_policy", "debug_policy", "updated_at"}},
			{codewirev1.File_codewire_v1_mesh_kv_proto.Messages().ByName("MeshKeyValue"), []protoreflect.Name{"org_id", "network_id", "namespace", "key", "value", "expires_at"}},
		}
		for _, check := range checks {
			if err := checkMeshMessageFields(check.descriptor, check.fields); err != nil {
				meshConverterCoverageErr = err
				return
			}
		}
		if err := checkMeshEnumValues(
			codewirev1.File_codewire_v1_mesh_group_proto.Enums().ByName("MeshGroupMessagesPolicy"),
			[]protoreflect.Name{
				"MESH_GROUP_MESSAGES_POLICY_UNSPECIFIED",
				"MESH_GROUP_MESSAGES_POLICY_INTERNAL_ONLY",
				"MESH_GROUP_MESSAGES_POLICY_OPEN",
			},
		); err != nil {
			meshConverterCoverageErr = err
			return
		}
		meshConverterCoverageErr = checkMeshEnumValues(
			codewirev1.File_codewire_v1_mesh_group_proto.Enums().ByName("MeshGroupDebugPolicy"),
			[]protoreflect.Name{
				"MESH_GROUP_DEBUG_POLICY_UNSPECIFIED",
				"MESH_GROUP_DEBUG_POLICY_NONE",
				"MESH_GROUP_DEBUG_POLICY_OBSERVE_ONLY",
				"MESH_GROUP_DEBUG_POLICY_FULL",
			},
		)
	})
	return meshConverterCoverageErr
}

func checkMeshMessageFields(descriptor protoreflect.MessageDescriptor, expected []protoreflect.Name) error {
	if descriptor == nil {
		return fmt.Errorf("codewire: Mesh converter descriptor is missing")
	}
	fields := descriptor.Fields()
	if fields.Len() != len(expected) {
		return fmt.Errorf("codewire: Mesh %s converter covers %d descriptor fields, expected %d", descriptor.Name(), len(expected), fields.Len())
	}
	for index, name := range expected {
		field := fields.Get(index)
		if field.Number() != protoreflect.FieldNumber(index+1) || field.Name() != name {
			return fmt.Errorf("codewire: Mesh %s converter does not cover descriptor field %s", descriptor.Name(), field.FullName())
		}
	}
	return nil
}

func checkMeshEnumValues(descriptor protoreflect.EnumDescriptor, expected []protoreflect.Name) error {
	if descriptor == nil {
		return fmt.Errorf("codewire: Mesh enum descriptor is missing")
	}
	values := descriptor.Values()
	if values.Len() != len(expected) {
		return fmt.Errorf("codewire: Mesh %s converter covers %d enum values, expected %d", descriptor.Name(), len(expected), values.Len())
	}
	for index, name := range expected {
		value := values.Get(index)
		if value.Number() != protoreflect.EnumNumber(index) || value.Name() != name {
			return fmt.Errorf("codewire: Mesh %s converter does not cover enum value %s", descriptor.Name(), value.FullName())
		}
	}
	return nil
}
